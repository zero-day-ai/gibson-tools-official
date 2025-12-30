package main

import "github.com/zero-day-ai/sdk/schema"

// InputSchema defines the input schema for the spiderfoot tool
func InputSchema() schema.JSON {
	target := schema.String()
	target.Description = "Target domain, IP, email, or other entity to investigate"

	scanType := schema.Enum("all", "passive", "active")
	scanType.Description = "Type of scan to perform (all, passive, or active)"

	modules := schema.Array(schema.String())
	modules.Description = "Specific SpiderFoot modules to run (optional)"

	maxThreads := schema.Int()
	maxThreads.Description = "Maximum number of threads to use (optional)"

	return schema.Object(map[string]schema.JSON{
		"target":      target,
		"scan_type":   scanType,
		"modules":     modules,
		"max_threads": maxThreads,
	}, "target") // target is required
}

// OutputSchema defines the output schema for the spiderfoot tool
func OutputSchema() schema.JSON {
	targetDesc := schema.String()
	targetDesc.Description = "The target that was scanned"

	entityType := schema.String()
	entityType.Description = "Type of entity discovered"

	entityValue := schema.String()
	entityValue.Description = "The entity value"

	sourceModule := schema.String()
	sourceModule.Description = "SpiderFoot module that discovered this entity"

	confidence := schema.Number()
	confidence.Description = "Confidence score for this entity"

	relationFrom := schema.String()
	relationFrom.Description = "Source entity"

	relationTo := schema.String()
	relationTo.Description = "Destination entity"

	relationType := schema.String()
	relationType.Description = "Relationship type"

	entities := schema.Array(
		schema.Object(map[string]schema.JSON{
			"type":          entityType,
			"value":         entityValue,
			"source_module": sourceModule,
			"confidence":    confidence,
		}),
	)
	entities.Description = "Entities discovered during the scan"

	relationships := schema.Array(
		schema.Object(map[string]schema.JSON{
			"from": relationFrom,
			"to":   relationTo,
			"type": relationType,
		}),
	)
	relationships.Description = "Relationships between discovered entities"

	scanTime := schema.Int()
	scanTime.Description = "Scan duration in milliseconds"

	return schema.Object(map[string]schema.JSON{
		"target":        targetDesc,
		"entities":      entities,
		"relationships": relationships,
		"scan_time_ms":  scanTime,
	})
}
