package main

import (
	"log"

	"github.com/zero-day-ai/sdk/serve"
	"github.com/zero-day-ai/tools/discovery/nmap"
)

func main() {
	tool := nmap.NewTool()
	if err := serve.Tool(tool, serve.WithRegistryFromEnv()); err != nil {
		log.Fatal(err)
	}
}
