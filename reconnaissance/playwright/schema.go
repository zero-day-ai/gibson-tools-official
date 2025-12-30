package main

import "github.com/zero-day-ai/sdk/schema"

func InputSchema() schema.JSON {
	return schema.Object(map[string]schema.JSON{
		"action": schema.JSON{
			Type:        "string",
			Description: "Action to perform: navigate, screenshot, pdf, content, evaluate, click, fill, wait, or crawl",
			Enum:        []any{"navigate", "screenshot", "pdf", "content", "evaluate", "click", "fill", "wait", "crawl"},
		},
		"url": schema.StringWithDesc("Target URL (required for navigate, screenshot, pdf, content, crawl)"),
		"browser": schema.JSON{
			Type:        "string",
			Description: "Browser type to use",
			Enum:        []any{"chromium", "firefox", "webkit"},
			Default:     "chromium",
		},
		"headless": schema.JSON{
			Type:        "boolean",
			Description: "Run browser in headless mode",
			Default:     true,
		},
		"viewport": schema.Object(map[string]schema.JSON{
			"width": schema.JSON{
				Type:        "integer",
				Description: "Viewport width in pixels",
				Default:     1920,
			},
			"height": schema.JSON{
				Type:        "integer",
				Description: "Viewport height in pixels",
				Default:     1080,
			},
		}),
		"timeout": schema.JSON{
			Type:        "integer",
			Description: "Navigation timeout in milliseconds",
		},
		"wait_until": schema.JSON{
			Type:        "string",
			Description: "When to consider navigation complete",
			Enum:        []any{"load", "domcontentloaded", "networkidle"},
			Default:     "networkidle",
		},
		"user_agent": schema.StringWithDesc("Custom user agent string"),
		"proxy": schema.Object(map[string]schema.JSON{
			"server":   schema.StringWithDesc("Proxy server URL"),
			"username": schema.StringWithDesc("Proxy username"),
			"password": schema.StringWithDesc("Proxy password"),
		}),
		"cookies": schema.Array(schema.Object(map[string]schema.JSON{
			"name":   schema.StringWithDesc("Cookie name"),
			"value":  schema.StringWithDesc("Cookie value"),
			"domain": schema.StringWithDesc("Cookie domain"),
			"path":   schema.StringWithDesc("Cookie path"),
		})),
		"headers": schema.JSON{
			Type:        "object",
			Description: "Custom HTTP headers",
		},
		"screenshot_options": schema.Object(map[string]schema.JSON{
			"full_page": schema.JSON{
				Type:        "boolean",
				Description: "Capture full scrollable page",
				Default:     false,
			},
			"type": schema.JSON{
				Type:        "string",
				Description: "Screenshot image format",
				Enum:        []any{"png", "jpeg"},
				Default:     "png",
			},
			"quality": schema.JSON{
				Type:        "integer",
				Description: "Image quality for JPEG (0-100)",
			},
		}),
		"selector": schema.StringWithDesc("CSS selector for click/fill/wait actions"),
		"value":    schema.StringWithDesc("Value for fill action"),
		"script":   schema.StringWithDesc("JavaScript code for evaluate action"),
		"crawl_options": schema.Object(map[string]schema.JSON{
			"max_depth": schema.JSON{
				Type:        "integer",
				Description: "Maximum crawl depth",
				Default:     2,
			},
			"max_pages": schema.JSON{
				Type:        "integer",
				Description: "Maximum pages to crawl",
				Default:     100,
			},
			"same_origin": schema.JSON{
				Type:        "boolean",
				Description: "Only crawl same-origin URLs",
				Default:     true,
			},
			"extract_forms": schema.JSON{
				Type:        "boolean",
				Description: "Extract form information",
				Default:     true,
			},
			"extract_links": schema.JSON{
				Type:        "boolean",
				Description: "Extract links",
				Default:     true,
			},
			"extract_scripts": schema.JSON{
				Type:        "boolean",
				Description: "Extract script information",
				Default:     true,
			},
		}),
	}, "action", "url")
}

func OutputSchema() schema.JSON {
	return schema.Object(map[string]schema.JSON{
		"success": schema.JSON{
			Type:        "boolean",
			Description: "Whether the action completed successfully",
		},
		"action": schema.StringWithDesc("Action that was performed"),
		"url":    schema.StringWithDesc("Original URL"),
		"final_url": schema.JSON{
			Type:        "string",
			Description: "Final URL after redirects",
		},
		"status_code": schema.JSON{
			Type:        "integer",
			Description: "HTTP status code",
		},
		"title": schema.StringWithDesc("Page title"),
		"content": schema.Object(map[string]schema.JSON{
			"html":            schema.StringWithDesc("Page HTML content"),
			"text":            schema.StringWithDesc("Page text content"),
			"screenshot_path": schema.StringWithDesc("Path to screenshot file"),
			"pdf_path":        schema.StringWithDesc("Path to PDF file"),
		}),
		"evaluate_result": schema.JSON{
			Type:        "object",
			Description: "Result of JavaScript evaluation",
		},
		"cookies": schema.Array(schema.Object(map[string]schema.JSON{
			"name":     schema.StringWithDesc("Cookie name"),
			"value":    schema.StringWithDesc("Cookie value"),
			"domain":   schema.StringWithDesc("Cookie domain"),
			"path":     schema.StringWithDesc("Cookie path"),
			"expires":  schema.Number(),
			"httpOnly": schema.Bool(),
			"secure":   schema.Bool(),
		})),
		"console_logs": schema.Array(schema.String()),
		"network_requests": schema.Array(schema.Object(map[string]schema.JSON{
			"url":    schema.StringWithDesc("Request URL"),
			"method": schema.StringWithDesc("HTTP method"),
			"status": schema.JSON{
				Type:        "integer",
				Description: "Response status code",
			},
			"resource_type": schema.StringWithDesc("Resource type (document, script, etc)"),
			"response_headers": schema.JSON{
				Type:        "object",
				Description: "Response headers",
			},
		})),
		"crawl_results": schema.Object(map[string]schema.JSON{
			"pages_visited": schema.JSON{
				Type:        "integer",
				Description: "Number of pages crawled",
			},
			"links": schema.Array(schema.Object(map[string]schema.JSON{
				"url":         schema.StringWithDesc("Link URL"),
				"text":        schema.StringWithDesc("Link text"),
				"source_page": schema.StringWithDesc("Page where link was found"),
			})),
			"forms": schema.Array(schema.Object(map[string]schema.JSON{
				"action": schema.StringWithDesc("Form action URL"),
				"method": schema.StringWithDesc("Form method (GET/POST)"),
				"inputs": schema.Array(schema.Object(map[string]schema.JSON{
					"name": schema.StringWithDesc("Input name"),
					"type": schema.StringWithDesc("Input type"),
					"id":   schema.StringWithDesc("Input ID"),
				})),
				"source_page": schema.StringWithDesc("Page where form was found"),
			})),
			"scripts": schema.Array(schema.Object(map[string]schema.JSON{
				"src":         schema.StringWithDesc("Script source URL"),
				"inline":      schema.Bool(),
				"source_page": schema.StringWithDesc("Page where script was found"),
			})),
			"technologies_detected": schema.Array(schema.String()),
		}),
		"timing": schema.Object(map[string]schema.JSON{
			"navigation_ms":          schema.Int(),
			"dom_content_loaded_ms":  schema.Int(),
			"load_ms":                schema.Int(),
		}),
		"errors":            schema.Array(schema.String()),
		"execution_time_ms": schema.Int(),
	})
}
