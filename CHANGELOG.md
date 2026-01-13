# Changelog

All notable changes to this project will be documented in this file.

## [0.5.0] - 2026-01-13

### Added
- **Unified Policy File Support**: Custom policy files (`policy_path`) now support both `policies` (license rules) AND `packagePolicies` (PURL-based exceptions) in a single file
  - Both sections are automatically merged with the built-in defaults
  - No more need for separate `package_policy_path` for simple use cases
- **New `policy_mode` Input**: Control how custom policies are handled
  - `merge` (default): Combines custom policies with built-in defaults
  - `replace`: Uses only the custom policy, ignoring built-in defaults
- **Package Policy Merging**: Added `merge_package_policies()` function for intelligent PURL-based policy combination
- **Improved Logging**: Better log messages distinguishing between license policies and package policies during merge

### Changed
- **Breaking Change (Behavioral)**: Custom `policy_path` files with `packagePolicies` now work automatically (previously ignored)
- Improved validation messages when policy files contain unexpected structures
- Documentation completely rewritten for clearer policy configuration guidance

### Deprecated
- `package_policy_path` input: Use `policy_path` with `packagePolicies` section instead (still works for backwards compatibility)

### Fixed
- **Bug Fix**: `packagePolicies` in custom policy files were being ignored when using `policy_path` input
- Policy merge now correctly reports count of both license policies AND package policies

## [0.4.3] - 2025-07-22

### Fixed
- **Critical Bug: Custom Policy Merge** (Issue #9): Custom `policy_path` now properly extends the default policy instead of completely replacing it. Previously, using a custom policy caused all default allowlisted licenses (Apache-2.0, MIT, etc.) to be flagged as "needs-review".

### Added
- **Data-Driven License Aliases**: License aliases are now defined in `policy.json` instead of being hardcoded in Python
  - Added `licenseAliases` section with 95+ mappings for common license name variations
  - Added `combinedLicenseAliases` section for dual-license expressions (e.g., "CDDL + GPLv2 with classpath exception")
  - Users can now add custom aliases in their own policy files
- **Policy Merge Functions**: Added `merge_license_policies()` and `merge_aliases()` functions for intelligent policy combination
- **New CLI Argument**: Added `--base-policy` argument to explicitly specify base policy for merging
- **Extended License Coverage**: Added aliases for EDL (Eclipse Distribution License), BSD New License, Public Domain/CC0, and various GPL/CDDL combinations

### Changed
- `SPDXExpressionParser` now accepts aliases as constructor parameters instead of using hardcoded values
- `action.yml` automatically detects and uses default policy as base when custom `policy_path` is provided
- License expression parsing improved for non-standard formats using `+` operator and `w/` shortcuts

## [0.4.0] - 2025-07-15

### Added
- **Organizational Caching for SBOM Enrichment**: Revolutionary caching system for package metadata
  - Added `SBOMCacheManager` class for intelligent cache management
  - Multi-level caching: local filesystem + GitHub Actions cache + organization-wide sharing
  - 703x performance improvement on subsequent runs (9 it/s → 6,449 it/s)
  - Smart cache keys based on organization, package hashes, and TTL
  - Automatic cleanup of expired cache entries
  - Added `enable_cache` and `cache_ttl_hours` inputs for configuration
  - Reduced API calls to package registries (npm, PyPI, Maven Central)
  - Enhanced GitHub Actions cache integration with restore-keys strategy
- **GitHub Models Support**: Added experimental support for GitHub Models as a fourth AI provider
  - Added `github` option to `ai_provider` input for using GitHub's AI models
  - Uses GitHub token for authentication (no additional API keys needed)
  - Supports all models available in GitHub Models (GPT-4o, Claude, Llama, etc.)
  - Requires `models: read` permission in GitHub Actions workflows
  - Enhanced test coverage for GitHub Models integration
  - **Cost Optimized**: Changed default to `openai/gpt-4o-mini` for 94% cost reduction
- **Multi-Provider AI Support**: Expanded AI-assisted summary to support OpenAI, Azure OpenAI, and AWS Bedrock
  - Added `ai_provider` input to select between providers (openai, azure, bedrock, github)
  - Added `azure_endpoint` and `azure_deployment` inputs for Azure OpenAI configuration
  - Added `aws_region` input for AWS Bedrock configuration
  - Added `ai_model_name` input to specify custom models for each provider
  - Updated dependencies to include `boto3` for AWS Bedrock support
- **Enhanced AI Prompts**: Improved AI prompt structure for more detailed license compliance analysis
- **Provider-Specific Error Handling**: Each AI provider has tailored error handling and fallback mechanisms

### Changed
- **Performance**: SBOM enrichment is now 703x faster on subsequent runs with caching enabled
- **Default Caching**: Caching is enabled by default (`enable_cache: true`)
- **Cache TTL**: Default cache time-to-live set to 168 hours (7 days)
- Renamed `openai_api_key` input description to be provider-agnostic
- Updated README.md with comprehensive examples for all four AI providers and caching documentation
- Enhanced test coverage for multi-provider functionality and caching

## [1.0.0] - 2025-06-30

### Added
- **AI-Assisted Summary**: Integrates with the OpenAI API to generate a high-level summary of the license audit report. This is enabled by providing the `openai_api_key` input.
- **Configurable Internal Dependencies**: Added a new `internal_dependency_pattern` input to allow users to specify one or more regex patterns to skip internal dependencies from the audit.
- Added a dedicated CI workflow (`.github/workflows/ci.yml`) to run unit tests on push and pull requests.

### Changed
- **OpenAI API v1.0.0+**: Updated the OpenAI integration to use the latest version of the `openai` Python library (`v1.0.0+`), moving from the legacy API.
- The `internal_dependency_pattern` input now accepts a newline-separated list of patterns for more flexibility.

### Fixed
- Unit tests for the AI summary feature were updated to mock the new OpenAI client structure.

### Removed
- The test execution step was removed from the main `action.yml` workflow to be handled by the new dedicated CI workflow.

## [0.3.1] - 2025-06-27

### Fixed
- Patched a bug in the `all-versions` matcher that caused an exception when processing scoped npm packages (e.g., `@angular/core`). The logic now correctly handles PURLs with multiple `@` symbols.
- Added a defensive check to prevent `AttributeError` when parsing complex or malformed license strings.
- Refined license expression parsing to correctly handle licenses with exceptions (e.g., `GPL-2.0-with-classpath-exception`) and avoid splitting valid license names.
- Updated license parsing to correctly handle comma-separated license strings, ensuring each license is audited individually.

## [0.3.0] - 2025-06-27

### Added
- **Flexible PURL Matching**: Introduced a `matcher` field in `package_policy.json` to allow for more flexible package matching. Supported matchers are:
  - `exact`: (Default) Matches the PURL exactly.
  - `all-versions`: Matches a package regardless of its version.
  - `wildcard`: Allows using `*` as a wildcard in the PURL.
- **Custom License Policies**: Added a new optional input `policy_path` to allow users to provide their own license policy file.

### Changed
- **PURL Normalization**: The PURL matching logic now ignores qualifiers (anything after a `?`) for more reliable matching.
- `audit_licenses.py` was significantly refactored to support the new matching logic.
- `action.yml` was updated to include the `policy_path` input.

## [0.2.0] - 2025-06-27

### Added
- **Package-Specific Policies**: Implemented a mechanism to define policies for specific packages via a `package_policy.json` file. This allows overriding the general license-based audit for individual components.
- Added a new optional input `package_policy_path` to the action to specify a custom location for the package policy file.

### Changed
- Updated `audit_licenses.py` to prioritize package-specific policies over general license policies.
- Modified `action.yml` to handle the new `package_policy_path` input with smart defaults.

## [0.1.1] - 2025-06-27

### Fixed
- Initial release to the GitHub Marketplace. Addressed initial version resolution issues.

## [0.1.0] - 2025-06-27

### Added
- Initial creation of the SBOM Auditor Action.
- Core functionality to fetch SBOM, enrich it, collect license texts, and audit against a license policy.
- Created `action.yml` for use in GitHub Actions.
- Added a `release.yml` workflow for automated releases.
- Comprehensive `README.md` documentation.
