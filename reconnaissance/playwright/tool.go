package main

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/playwright-community/playwright-go"
	"github.com/zero-day-ai/sdk/tool"
	"github.com/zero-day-ai/sdk/types"
)

const (
	ToolName        = "playwright"
	ToolVersion     = "1.0.0"
	ToolDescription = "Browser automation tool for web crawling, screenshots, PDF generation, and JavaScript execution"
)

type ToolImpl struct{}

func NewTool() tool.Tool {
	cfg := tool.NewConfig().
		SetName(ToolName).
		SetVersion(ToolVersion).
		SetDescription(ToolDescription).
		SetTags([]string{
			"reconnaissance",
			"browser",
			"automation",
			"T1592.002", // Gather Victim Host Information: Software
			"T1593",     // Search Open Websites/Domains
			"T1189",     // Drive-by Compromise
		}).
		SetInputSchema(InputSchema()).
		SetOutputSchema(OutputSchema()).
		SetExecuteFunc((&ToolImpl{}).Execute)

	t, _ := tool.New(cfg)
	return &toolWithHealth{Tool: t, impl: &ToolImpl{}}
}

type toolWithHealth struct {
	tool.Tool
	impl *ToolImpl
}

func (t *toolWithHealth) Health(ctx context.Context) types.HealthStatus {
	return t.impl.Health(ctx)
}

func (t *ToolImpl) Health(ctx context.Context) types.HealthStatus {
	// Check if playwright is installed by checking if browsers are installed
	cmd := exec.CommandContext(ctx, "npx", "playwright", "--version")
	if err := cmd.Run(); err != nil {
		return types.NewUnhealthyStatus("playwright not installed: run 'npx playwright install' to install browsers", nil)
	}

	// Additional check for chromium browser
	cmd = exec.CommandContext(ctx, "npx", "playwright", "install", "--dry-run", "chromium")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return types.NewUnhealthyStatus("playwright browsers not installed: run 'npx playwright install'", nil)
	}

	// If dry-run shows installation needed, browsers are missing
	if strings.Contains(string(output), "will be installed") {
		return types.NewUnhealthyStatus("playwright browsers not installed: run 'npx playwright install'", nil)
	}

	return types.NewHealthyStatus("playwright is ready")
}

func (t *ToolImpl) Execute(ctx context.Context, input map[string]any) (map[string]any, error) {
	startTime := time.Now()

	action := getString(input, "action", "navigate")
	targetURL := getString(input, "url", "")
	browserType := getString(input, "browser", "chromium")
	headless := getBool(input, "headless", true)

	// Validate URL for actions that require it
	if requiresURL(action) && targetURL == "" {
		return nil, fmt.Errorf("url is required for action: %s", action)
	}

	// Initialize playwright
	pw, err := playwright.Run()
	if err != nil {
		return nil, fmt.Errorf("failed to start playwright: %w", err)
	}
	defer pw.Stop()

	// Launch browser
	launchOpts := playwright.BrowserTypeLaunchOptions{
		Headless: playwright.Bool(headless),
	}

	// Add proxy configuration if provided
	if proxy, ok := input["proxy"].(map[string]any); ok {
		if server := getString(proxy, "server", ""); server != "" {
			launchOpts.Proxy = &playwright.Proxy{
				Server:   server,
				Username: playwright.String(getString(proxy, "username", "")),
				Password: playwright.String(getString(proxy, "password", "")),
			}
		}
	}

	var browser playwright.Browser
	switch browserType {
	case "firefox":
		browser, err = pw.Firefox.Launch(launchOpts)
	case "webkit":
		browser, err = pw.WebKit.Launch(launchOpts)
	default:
		browser, err = pw.Chromium.Launch(launchOpts)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to launch browser: %w", err)
	}
	defer browser.Close()

	// Create context options
	contextOpts := playwright.BrowserNewContextOptions{}

	// Set viewport
	if viewport, ok := input["viewport"].(map[string]any); ok {
		width := getInt(viewport, "width", 1920)
		height := getInt(viewport, "height", 1080)
		contextOpts.Viewport = &playwright.Size{
			Width:  width,
			Height: height,
		}
	} else {
		contextOpts.Viewport = &playwright.Size{
			Width:  1920,
			Height: 1080,
		}
	}

	// Set user agent
	if userAgent := getString(input, "user_agent", ""); userAgent != "" {
		contextOpts.UserAgent = playwright.String(userAgent)
	}

	// Set custom headers
	if headers, ok := input["headers"].(map[string]any); ok {
		extraHeaders := make(map[string]string)
		for k, v := range headers {
			if str, ok := v.(string); ok {
				extraHeaders[k] = str
			}
		}
		contextOpts.ExtraHttpHeaders = extraHeaders
	}

	// Create browser context
	context, err := browser.NewContext(contextOpts)
	if err != nil {
		return nil, fmt.Errorf("failed to create browser context: %w", err)
	}
	defer context.Close()

	// Add cookies if provided
	if cookies, ok := input["cookies"].([]any); ok {
		var cookiesToAdd []playwright.OptionalCookie
		for _, cookieData := range cookies {
			if cookie, ok := cookieData.(map[string]any); ok {
				cookiesToAdd = append(cookiesToAdd, playwright.OptionalCookie{
					Name:   getString(cookie, "name", ""),
					Value:  getString(cookie, "value", ""),
					Domain: playwright.String(getString(cookie, "domain", "")),
					Path:   playwright.String(getString(cookie, "path", "/")),
				})
			}
		}
		if len(cookiesToAdd) > 0 {
			if err := context.AddCookies(cookiesToAdd); err != nil {
				return nil, fmt.Errorf("failed to add cookies: %w", err)
			}
		}
	}

	// Create page
	page, err := context.NewPage()
	if err != nil {
		return nil, fmt.Errorf("failed to create page: %w", err)
	}
	defer page.Close()

	// Collectors for network requests and console logs
	var networkRequests []map[string]any
	var consoleLogs []string
	var errors []string

	// Setup network request interception
	page.On("request", func(req playwright.Request) {
		// Store basic request info
	})

	page.On("response", func(resp playwright.Response) {
		req := resp.Request()
		headers := make(map[string]any)
		for k, v := range resp.Headers() {
			headers[k] = v
		}

		networkRequests = append(networkRequests, map[string]any{
			"url":              req.URL(),
			"method":           req.Method(),
			"status":           resp.Status(),
			"resource_type":    req.ResourceType(),
			"response_headers": headers,
		})
	})

	// Capture console logs
	page.On("console", func(msg playwright.ConsoleMessage) {
		consoleLogs = append(consoleLogs, fmt.Sprintf("[%s] %s", msg.Type(), msg.Text()))
	})

	// Capture page errors
	page.On("pageerror", func(err error) {
		errors = append(errors, err.Error())
	})

	// Execute the requested action
	var result map[string]any
	switch action {
	case "navigate":
		result, err = t.navigate(ctx, page, targetURL, input)
	case "screenshot":
		result, err = t.screenshot(ctx, page, targetURL, input)
	case "pdf":
		result, err = t.pdf(ctx, page, targetURL, input)
	case "content":
		result, err = t.content(ctx, page, targetURL, input)
	case "evaluate":
		result, err = t.evaluate(ctx, page, targetURL, input)
	case "click":
		result, err = t.click(ctx, page, targetURL, input)
	case "fill":
		result, err = t.fill(ctx, page, targetURL, input)
	case "wait":
		result, err = t.wait(ctx, page, targetURL, input)
	case "crawl":
		result, err = t.crawl(ctx, browser, targetURL, input)
	default:
		return nil, fmt.Errorf("unknown action: %s", action)
	}

	if err != nil {
		return map[string]any{
			"success":           false,
			"action":            action,
			"url":               targetURL,
			"errors":            append(errors, err.Error()),
			"console_logs":      consoleLogs,
			"network_requests":  networkRequests,
			"execution_time_ms": time.Since(startTime).Milliseconds(),
		}, nil
	}

	// Add common fields to result
	result["success"] = true
	result["action"] = action
	result["url"] = targetURL
	result["console_logs"] = consoleLogs
	result["network_requests"] = networkRequests
	result["errors"] = errors
	result["execution_time_ms"] = time.Since(startTime).Milliseconds()

	// Get cookies
	cookies, _ := context.Cookies()
	cookieList := make([]map[string]any, 0, len(cookies))
	for _, c := range cookies {
		cookieList = append(cookieList, map[string]any{
			"name":     c.Name,
			"value":    c.Value,
			"domain":   c.Domain,
			"path":     c.Path,
			"expires":  c.Expires,
			"httpOnly": c.HttpOnly,
			"secure":   c.Secure,
		})
	}
	result["cookies"] = cookieList

	return result, nil
}

func (t *ToolImpl) navigate(ctx context.Context, page playwright.Page, url string, input map[string]any) (map[string]any, error) {
	navOpts := playwright.PageGotoOptions{}
	if timeout := getInt(input, "timeout", 0); timeout > 0 {
		navOpts.Timeout = playwright.Float(float64(timeout))
	}

	waitUntil := getString(input, "wait_until", "networkidle")
	switch waitUntil {
	case "load":
		navOpts.WaitUntil = playwright.WaitUntilStateLoad
	case "domcontentloaded":
		navOpts.WaitUntil = playwright.WaitUntilStateDomcontentloaded
	case "networkidle":
		navOpts.WaitUntil = playwright.WaitUntilStateNetworkidle
	}

	response, err := page.Goto(url, navOpts)
	if err != nil {
		return nil, fmt.Errorf("navigation failed: %w", err)
	}

	title, _ := page.Title()
	finalURL := page.URL()
	statusCode := 0
	if response != nil {
		statusCode = response.Status()
	}

	return map[string]any{
		"final_url":   finalURL,
		"status_code": statusCode,
		"title":       title,
	}, nil
}

func (t *ToolImpl) screenshot(ctx context.Context, page playwright.Page, url string, input map[string]any) (map[string]any, error) {
	// Navigate first
	navResult, err := t.navigate(ctx, page, url, input)
	if err != nil {
		return nil, err
	}

	// Generate screenshot
	screenshotOpts := playwright.PageScreenshotOptions{}

	ext := "png"
	if ssOpts, ok := input["screenshot_options"].(map[string]any); ok {
		screenshotOpts.FullPage = playwright.Bool(getBool(ssOpts, "full_page", false))

		ssType := getString(ssOpts, "type", "png")
		if ssType == "jpeg" {
			screenshotOpts.Type = playwright.ScreenshotTypeJpeg
			ext = "jpeg"
			if quality := getInt(ssOpts, "quality", 0); quality > 0 {
				screenshotOpts.Quality = playwright.Int(quality)
			}
		} else {
			screenshotOpts.Type = playwright.ScreenshotTypePng
		}
	}

	// Create temp file for screenshot
	tmpDir := os.TempDir()
	screenshotPath := filepath.Join(tmpDir, fmt.Sprintf("playwright-screenshot-%d.%s", time.Now().UnixNano(), ext))

	screenshotOpts.Path = playwright.String(screenshotPath)
	_, err = page.Screenshot(screenshotOpts)
	if err != nil {
		return nil, fmt.Errorf("screenshot failed: %w", err)
	}

	navResult["content"] = map[string]any{
		"screenshot_path": screenshotPath,
	}

	return navResult, nil
}

func (t *ToolImpl) pdf(ctx context.Context, page playwright.Page, url string, input map[string]any) (map[string]any, error) {
	// Navigate first
	navResult, err := t.navigate(ctx, page, url, input)
	if err != nil {
		return nil, err
	}

	// Generate PDF (only works with chromium)
	tmpDir := os.TempDir()
	pdfPath := filepath.Join(tmpDir, fmt.Sprintf("playwright-pdf-%d.pdf", time.Now().UnixNano()))

	_, err = page.PDF(playwright.PagePdfOptions{
		Path: playwright.String(pdfPath),
	})
	if err != nil {
		return nil, fmt.Errorf("PDF generation failed: %w", err)
	}

	navResult["content"] = map[string]any{
		"pdf_path": pdfPath,
	}

	return navResult, nil
}

func (t *ToolImpl) content(ctx context.Context, page playwright.Page, url string, input map[string]any) (map[string]any, error) {
	// Navigate first
	navResult, err := t.navigate(ctx, page, url, input)
	if err != nil {
		return nil, err
	}

	// Get HTML content
	html, err := page.Content()
	if err != nil {
		return nil, fmt.Errorf("failed to get HTML content: %w", err)
	}

	// Get text content
	text, err := page.InnerText("body")
	if err != nil {
		text = "" // Text extraction is optional
	}

	navResult["content"] = map[string]any{
		"html": html,
		"text": text,
	}

	return navResult, nil
}

func (t *ToolImpl) evaluate(ctx context.Context, page playwright.Page, url string, input map[string]any) (map[string]any, error) {
	// Navigate first if URL is provided
	var navResult map[string]any
	var err error
	if url != "" {
		navResult, err = t.navigate(ctx, page, url, input)
		if err != nil {
			return nil, err
		}
	} else {
		navResult = make(map[string]any)
	}

	// Get script to evaluate
	script := getString(input, "script", "")
	if script == "" {
		return nil, fmt.Errorf("script is required for evaluate action")
	}

	// Evaluate JavaScript
	result, err := page.Evaluate(script)
	if err != nil {
		return nil, fmt.Errorf("script evaluation failed: %w", err)
	}

	navResult["evaluate_result"] = result

	return navResult, nil
}

func (t *ToolImpl) click(ctx context.Context, page playwright.Page, url string, input map[string]any) (map[string]any, error) {
	// Navigate first if URL is provided
	if url != "" {
		_, err := t.navigate(ctx, page, url, input)
		if err != nil {
			return nil, err
		}
	}

	// Get selector
	selector := getString(input, "selector", "")
	if selector == "" {
		return nil, fmt.Errorf("selector is required for click action")
	}

	// Click element
	err := page.Click(selector)
	if err != nil {
		return nil, fmt.Errorf("click failed: %w", err)
	}

	title, _ := page.Title()
	finalURL := page.URL()

	return map[string]any{
		"final_url": finalURL,
		"title":     title,
	}, nil
}

func (t *ToolImpl) fill(ctx context.Context, page playwright.Page, url string, input map[string]any) (map[string]any, error) {
	// Navigate first if URL is provided
	if url != "" {
		_, err := t.navigate(ctx, page, url, input)
		if err != nil {
			return nil, err
		}
	}

	// Get selector and value
	selector := getString(input, "selector", "")
	if selector == "" {
		return nil, fmt.Errorf("selector is required for fill action")
	}

	value := getString(input, "value", "")

	// Fill input
	err := page.Fill(selector, value)
	if err != nil {
		return nil, fmt.Errorf("fill failed: %w", err)
	}

	title, _ := page.Title()
	finalURL := page.URL()

	return map[string]any{
		"final_url": finalURL,
		"title":     title,
	}, nil
}

func (t *ToolImpl) wait(ctx context.Context, page playwright.Page, url string, input map[string]any) (map[string]any, error) {
	// Navigate first if URL is provided
	if url != "" {
		_, err := t.navigate(ctx, page, url, input)
		if err != nil {
			return nil, err
		}
	}

	// Get selector
	selector := getString(input, "selector", "")
	if selector == "" {
		return nil, fmt.Errorf("selector is required for wait action")
	}

	// Wait for selector
	_, err := page.WaitForSelector(selector)
	if err != nil {
		return nil, fmt.Errorf("wait failed: %w", err)
	}

	title, _ := page.Title()
	finalURL := page.URL()

	return map[string]any{
		"final_url": finalURL,
		"title":     title,
	}, nil
}

func (t *ToolImpl) crawl(ctx context.Context, browser playwright.Browser, startURL string, input map[string]any) (map[string]any, error) {
	// Get crawl options
	crawlOpts := input["crawl_options"]
	maxDepth := 2
	maxPages := 100
	sameOrigin := true
	extractForms := true
	extractLinks := true
	extractScripts := true

	if opts, ok := crawlOpts.(map[string]any); ok {
		maxDepth = getInt(opts, "max_depth", 2)
		maxPages = getInt(opts, "max_pages", 100)
		sameOrigin = getBool(opts, "same_origin", true)
		extractForms = getBool(opts, "extract_forms", true)
		extractLinks = getBool(opts, "extract_links", true)
		extractScripts = getBool(opts, "extract_scripts", true)
	}

	// Parse start URL for origin checking
	startURLParsed, err := url.Parse(startURL)
	if err != nil {
		return nil, fmt.Errorf("invalid start URL: %w", err)
	}
	startOrigin := startURLParsed.Scheme + "://" + startURLParsed.Host

	// Crawl state
	visited := make(map[string]bool)
	queue := []struct {
		url   string
		depth int
	}{{url: startURL, depth: 0}}

	var allLinks []map[string]any
	var allForms []map[string]any
	var allScripts []map[string]any
	technologies := make(map[string]bool)

	// Create a new context for crawling
	context, err := browser.NewContext()
	if err != nil {
		return nil, fmt.Errorf("failed to create context: %w", err)
	}
	defer context.Close()

	pagesVisited := 0

	for len(queue) > 0 && pagesVisited < maxPages {
		current := queue[0]
		queue = queue[1:]

		if visited[current.url] {
			continue
		}

		if current.depth > maxDepth {
			continue
		}

		// Check same origin
		if sameOrigin {
			currentParsed, err := url.Parse(current.url)
			if err != nil {
				continue
			}
			currentOrigin := currentParsed.Scheme + "://" + currentParsed.Host
			if currentOrigin != startOrigin {
				continue
			}
		}

		visited[current.url] = true
		pagesVisited++

		// Create page for this URL
		page, err := context.NewPage()
		if err != nil {
			continue
		}

		// Navigate
		_, err = page.Goto(current.url, playwright.PageGotoOptions{
			WaitUntil: playwright.WaitUntilStateNetworkidle,
			Timeout:   playwright.Float(30000),
		})
		if err != nil {
			page.Close()
			continue
		}

		// Extract links
		if extractLinks {
			links, err := page.Locator("a[href]").All()
			if err == nil {
				for _, link := range links {
					href, _ := link.GetAttribute("href")
					text, _ := link.InnerText()
					if href != "" {
						absURL := resolveURL(current.url, href)
						if absURL != "" {
							allLinks = append(allLinks, map[string]any{
								"url":         absURL,
								"text":        strings.TrimSpace(text),
								"source_page": current.url,
							})
							// Add to queue for further crawling
							if !visited[absURL] {
								queue = append(queue, struct {
									url   string
									depth int
								}{url: absURL, depth: current.depth + 1})
							}
						}
					}
				}
			}
		}

		// Extract forms
		if extractForms {
			forms, err := page.Locator("form").All()
			if err == nil {
				for _, form := range forms {
					action, _ := form.GetAttribute("action")
					method, _ := form.GetAttribute("method")
					if method == "" {
						method = "GET"
					}

					inputs, _ := form.Locator("input, select, textarea").All()
					var inputList []map[string]any
					for _, input := range inputs {
						name, _ := input.GetAttribute("name")
						inputType, _ := input.GetAttribute("type")
						id, _ := input.GetAttribute("id")
						inputList = append(inputList, map[string]any{
							"name": name,
							"type": inputType,
							"id":   id,
						})
					}

					allForms = append(allForms, map[string]any{
						"action":      action,
						"method":      method,
						"inputs":      inputList,
						"source_page": current.url,
					})
				}
			}
		}

		// Extract scripts
		if extractScripts {
			scripts, err := page.Locator("script").All()
			if err == nil {
				for _, script := range scripts {
					src, _ := script.GetAttribute("src")
					if src != "" {
						allScripts = append(allScripts, map[string]any{
							"src":         resolveURL(current.url, src),
							"inline":      false,
							"source_page": current.url,
						})
					} else {
						allScripts = append(allScripts, map[string]any{
							"src":         "",
							"inline":      true,
							"source_page": current.url,
						})
					}
				}
			}
		}

		// Detect technologies (basic)
		html, _ := page.Content()
		detectTechnologies(html, technologies)

		page.Close()
	}

	// Convert technologies map to slice
	var techList []string
	for tech := range technologies {
		techList = append(techList, tech)
	}

	return map[string]any{
		"final_url": startURL,
		"crawl_results": map[string]any{
			"pages_visited":         pagesVisited,
			"links":                 allLinks,
			"forms":                 allForms,
			"scripts":               allScripts,
			"technologies_detected": techList,
		},
	}, nil
}

// Helper functions

func getString(m map[string]any, key string, defaultVal string) string {
	if v, ok := m[key].(string); ok {
		return v
	}
	return defaultVal
}

func getInt(m map[string]any, key string, defaultVal int) int {
	if v, ok := m[key].(int); ok {
		return v
	}
	if v, ok := m[key].(float64); ok {
		return int(v)
	}
	return defaultVal
}

func getBool(m map[string]any, key string, defaultVal bool) bool {
	if v, ok := m[key].(bool); ok {
		return v
	}
	return defaultVal
}

func requiresURL(action string) bool {
	switch action {
	case "navigate", "screenshot", "pdf", "content", "crawl":
		return true
	default:
		return false
	}
}

func resolveURL(base, href string) string {
	baseURL, err := url.Parse(base)
	if err != nil {
		return ""
	}
	refURL, err := url.Parse(href)
	if err != nil {
		return ""
	}
	return baseURL.ResolveReference(refURL).String()
}

func detectTechnologies(html string, technologies map[string]bool) {
	// Basic technology detection based on common patterns
	htmlLower := strings.ToLower(html)

	checks := map[string][]string{
		"React":      {"react", "react-dom"},
		"Vue.js":     {"vue.js", "vue.min.js"},
		"Angular":    {"angular.js", "angular.min.js", "ng-app"},
		"jQuery":     {"jquery.js", "jquery.min.js"},
		"Bootstrap":  {"bootstrap.css", "bootstrap.min.css"},
		"WordPress":  {"wp-content", "wp-includes"},
		"Drupal":     {"drupal.js", "sites/all"},
		"Joomla":     {"joomla", "components/com_"},
		"Google Analytics": {"google-analytics.com", "ga.js"},
		"Font Awesome":     {"font-awesome", "fontawesome"},
	}

	for tech, patterns := range checks {
		for _, pattern := range patterns {
			if strings.Contains(htmlLower, pattern) {
				technologies[tech] = true
				break
			}
		}
	}
}
