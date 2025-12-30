# SecretsDump Tool

Gibson SDK tool wrapper for Impacket's `secretsdump.py` - dumps credentials from Windows systems (SAM, LSA, NTDS).

## Overview

This tool provides a programmatic interface to Impacket's secretsdump.py for extracting Windows credentials. It supports dumping from:
- SAM (Security Account Manager) database
- LSA (Local Security Authority) secrets
- NTDS.dit (Active Directory database)

## MITRE ATT&CK Mapping

- **T1003.002**: OS Credential Dumping: Security Account Manager
- **T1003.003**: OS Credential Dumping: NTDS

## Prerequisites

- Python 3
- Impacket library installed (`pip install impacket`)
- Valid credentials or NTLM hash for target system
- Network access to target system

## Input Schema

```json
{
  "target": "string (required) - Target host (IP, hostname, or domain)",
  "domain": "string (optional) - Domain name",
  "username": "string (required) - Username for authentication",
  "password": "string (optional) - Password for authentication",
  "hash": "string (optional) - NTLM hash for pass-the-hash authentication",
  "method": "string (optional) - Extraction method: sam, lsa, or ntds"
}
```

## Output Schema

```json
{
  "domain_users": [
    {
      "username": "string",
      "rid": "integer",
      "lm_hash": "string",
      "nt_hash": "string"
    }
  ],
  "machine_accounts": [
    {
      "username": "string",
      "lm_hash": "string",
      "nt_hash": "string"
    }
  ],
  "cached_credentials": [
    {
      "username": "string",
      "hash": "string"
    }
  ],
  "dpapi_keys": [
    {
      "username": "string",
      "key": "string"
    }
  ]
}
```

## Usage Examples

### Password Authentication

```json
{
  "target": "192.168.1.100",
  "domain": "CORP",
  "username": "admin",
  "password": "P@ssw0rd",
  "method": "ntds"
}
```

### Pass-the-Hash Authentication

```json
{
  "target": "dc01.corp.local",
  "domain": "CORP",
  "username": "administrator",
  "hash": "aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c"
}
```

### SAM Database Dump

```json
{
  "target": "workstation01",
  "username": "localadmin",
  "password": "password123",
  "method": "sam"
}
```

## Implementation Details

### Authentication String Format

The tool constructs authentication strings in the format:
- Password: `domain/username:password@target`
- Pass-the-hash: `domain/username@NTLM_HASH@target`

### Output Parsing

The tool parses secretsdump.py output using regex patterns to extract:

1. **Domain Users**: Standard hash format `username:RID:LMhash:NThash:::`
2. **Machine Accounts**: Identified by `$` suffix in username
3. **Cached Credentials**: Tagged with `[CACHED]` prefix
4. **DPAPI Keys**: Tagged with `[DPAPI]` prefix

### Error Handling

- Returns structured `ToolError` with execution details on failure
- Includes exit code and stderr output in error details
- Validates input parameters via JSON schema
- Handles timeout with configurable duration (default: 5 minutes)

## Health Check

The health check verifies:
1. Python 3 is installed and available
2. Impacket module can be imported (checks for `impacket.examples.secretsdump`)

## Building

```bash
go build -o secretsdump .
```

## Running as gRPC Service

```bash
./secretsdump
```

The tool serves on the default gRPC port and can be accessed via the Gibson SDK.

## Security Considerations

- This tool executes external Python scripts - ensure Impacket is from a trusted source
- Credentials are passed as command-line arguments - use pass-the-hash when possible
- Output contains sensitive hash data - handle securely
- Requires elevated privileges on target system
- Network traffic may be detected by EDR/IDS systems

## Dependencies

- **github.com/zero-day-ai/sdk**: Gibson SDK for tool interface
- **github.com/zero-day-ai/gibson-tools-official/pkg/executor**: Process execution utilities
- **github.com/zero-day-ai/gibson-tools-official/pkg/health**: Health check utilities
- **github.com/zero-day-ai/gibson-tools-official/pkg/common**: Common helpers and error handling

## Related Tools

- **responder**: LLMNR/NBT-NS poisoning for hash capture
- **hashcat**: GPU-based hash cracking
- **john**: CPU-based hash cracking
- **crackmapexec**: Active Directory enumeration and credential spraying
