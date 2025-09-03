# Release v0.4.1: Organization-Agnostic Action

## 🌍 Major Improvement: Organization-Neutral Design

### Removed Otto-Specific Defaults
- **BREAKING**: Removed hardcoded `de.otto.*` as default internal dependency pattern
- **NEW**: Users must now explicitly configure their internal dependency patterns
- **BENEFIT**: Action is now truly organization-neutral and reusable

## 🐛 Critical Fixes

### Missing Input Definitions
- **FIXED**: Added missing `enable_cache`, `cache_ttl_hours`, and `debug` input definitions
- **FIXED**: Resolved `--cache-ttl-hours: expected one argument` error
- **FIXED**: Action now works properly in all workflows

### Multiline Pattern Handling
- **FIXED**: Multiline YAML internal dependency patterns now work correctly
- **FIXED**: Resolved `unrecognized arguments: com\.otto\..* pkg:maven/de\.otto\..*` error  
- **SOLUTION**: Uses environment variable for proper multiline pattern handling
- **TESTED**: All pattern configurations validated in GitHub Actions

### Regex Pattern Corrections
- **FIXED**: Corrected regex patterns in documentation (proper escaping)
- **EXAMPLE**: `de\.otto\..*` instead of incorrect `de.otto.*`
- **TESTED**: All patterns validated and working correctly

## 🔧 Key Changes

### Action Configuration
- `internal_dependency_pattern` now defaults to empty string instead of `de.otto.*`
- No fallback internal patterns in audit code
- Explicit configuration required for internal dependency skipping

### Documentation Updates
- Updated README examples with generic organization patterns
- Better examples showing multiple pattern types (Maven, npm, etc.)
- Clear guidance for any organization setup

## ⚠️ Breaking Change Notice

**For existing Otto users:** You must now explicitly add this to your workflow:

```yaml
- uses: otto-de/sbom_auditor_action@v0.4.1
  with:
    internal_dependency_pattern: |
      de\.otto\..*
      com\.otto\..*
      pkg:maven/de\.otto\..*
      pkg:maven/com\.otto\..*
```

**For other organizations:** Configure your own patterns:

```yaml
- uses: otto-de/sbom_auditor_action@v0.4.1
  with:
    internal_dependency_pattern: |
      com\.my-company\..*
      org\.my-company\..*
      pkg:maven/com\.my-company\..*
```

## 📦 Artifact Improvements (from v0.4.0)

- Fixed ZIP-in-ZIP artifact issues
- Separate uploads: `sbom-enriched` and `license-artifacts`
- Better compression and retention policies

## 📊 License Resolution Statistics (from v0.4.0)

- Comprehensive resolver statistics in audit summaries
- Track deps.dev, SPDX fuzzy, AI, POM, and cache resolution counts
- Enhanced pipeline transparency

## 🔄 Migration Guide

### For Otto Users
Add explicit internal dependency patterns to your workflows (see example above).

### For Other Organizations
This release makes the action much easier to adopt - just configure your own patterns!

### For Generic Usage
Leave `internal_dependency_pattern` empty if you want all packages audited.

---

**Full Changelog**: https://github.com/otto-de/sbom_auditor_action/compare/v0.4.0...v0.4.1
