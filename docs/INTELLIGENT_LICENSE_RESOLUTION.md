# Intelligent License Resolution

## Overview

The SBOM Auditor Action includes **intelligent license resolution** that automatically maps non-standard or descriptive license names to their correct SPDX identifiers.

## Problem

Maven Central and other package registries often use descriptive license names instead of standardized SPDX identifiers:

- `"Eclipse Public License v2.0"` → should be `"EPL-2.0"`
- `"The Apache Software License, Version 2.0"` → should be `"Apache-2.0"`
- `"BSD 3-Clause License"` → should be `"BSD-3-Clause"`

This previously caused these licenses to be flagged as `needs-review` even though they are well-known and permitted licenses.

## Solution

### Hybrid Resolution System

1. **SPDX Pattern Matching** (primary)
   - Loads the official SPDX License List from GitHub
   - Normalizes license names (removes "The", "License", etc.)
   - Uses predefined regex patterns for common cases
   - Fuzzy string matching with configurable threshold

2. **AI-powered Fallback** (optional)
   - Uses GitHub Models, OpenAI, Azure, or AWS Bedrock for difficult cases
   - Only triggered when SPDX matching fails

### Implementation

License resolution is integrated directly into the main scripts:

- **`helpers/license_resolver.py`**: Core `LicenseResolver` class
- **`helpers/enrich_sbom.py`**: Uses `LicenseResolver` during SBOM enrichment
- **`helpers/audit_licenses.py`**: Uses `LicenseResolver` as a defense-in-depth fallback before marking packages as `NO-LICENSE-FOUND`

## Usage

### Standalone License Resolution

```python
from license_resolver import LicenseResolver

resolver = LicenseResolver()
result = resolver.resolve_license("Eclipse Public License v2.0")

print(result)
# {
#   'original': 'Eclipse Public License v2.0',
#   'resolved': 'EPL-2.0',
#   'method': 'spdx_fuzzy',
#   'confidence': 0.9
# }
```

### SBOM Enrichment (integrated)

```bash
python helpers/enrich_sbom.py input.json output.json
```

### License Audit (integrated)

```bash
python helpers/audit_licenses.py sbom_enriched.json policy.json --markdown
```

## Configuration

### Environment Variables

- **`GITHUB_TOKEN`**: Used for AI-powered fallback when `ai_provider` is `github` (optional)

### Parameters

| Parameter | Description |
|-----------|-------------|
| `--debug` | Enable detailed logging |

## Resolution Methods

| Method | Description | Example |
|--------|-------------|---------|
| `spdx_fuzzy` | SPDX pattern / fuzzy matching | `"MIT License"` → `"MIT"` |
| `ai_assisted` | AI-powered recognition | Complex or unusual names |
| `maven_pom_fallback` | Direct Maven Central POM lookup | Maven packages with empty registry data |
| `unresolved` | No resolution possible | Stays `needs-review` |

## Enrichment Metadata

Resolution adds additional metadata to SBOM packages:

```json
{
  "name": "example-package",
  "licenseConcluded": "EPL-2.0",
  "enrichment": {
    "licenseResolution": {
      "original": "Eclipse Public License v2.0",
      "resolved": "EPL-2.0",
      "method": "spdx_fuzzy",
      "confidence": 0.9
    }
  }
}
```

## Pattern Recognition

### Common Patterns

- Apache: `apache.*license.*v?\.?2\.?0?` → `Apache-2.0`
- Eclipse: `eclipse.*public.*license.*v?\.?2\.?0?` → `EPL-2.0`
- MIT: `mit.*license` → `MIT`
- BSD: `bsd.*3.*clause` → `BSD-3-Clause`
- GPL: `gnu.*general.*public.*license.*v?\.?3` → `GPL-3.0-only`

### Normalization Steps

1. Lowercase conversion
2. Removal of "The", commas, brackets
3. Unification of "License"/"Licence"
4. Version pattern normalization (`v2.0`, `version 2.0` → `v2.0`)

## Performance

- **SPDX data**: ~703 licenses, loaded and cached once per run
- **Pattern matching**: ~1ms per license
- **AI fallback**: ~500ms per call (only when needed)
- **LRU cache**: Repeated lookups are instant

## Testing

```bash
python3 -m unittest helpers/test_license_resolution.py
```
