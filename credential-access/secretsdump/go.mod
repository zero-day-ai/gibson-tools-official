module github.com/zero-day-ai/gibson-tools-official/credential-access/secretsdump

go 1.24.4

require (
	github.com/zero-day-ai/sdk v0.0.0
	github.com/zero-day-ai/gibson-tools-official/pkg v0.0.0
)

replace (
	github.com/zero-day-ai/sdk => ../../../sdk
	github.com/zero-day-ai/gibson-tools-official/pkg => ../../pkg
)
