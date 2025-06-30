# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]

### Added
- **Multi-Provider AI Support**: Expanded AI-assisted summary to support OpenAI, Azure OpenAI, and AWS Bedrock
  - Added `ai_provider` input to select between providers (openai, azure, bedrock)
  - Added `azure_endpoint` and `azure_deployment` inputs for Azure OpenAI configuration
  - Added `aws_region` input for AWS Bedrock configuration
  - Added `ai_model_name` input to specify custom models for each provider
  - Updated dependencies to include `boto3` for AWS Bedrock support
- **Enhanced AI Prompts**: Improved AI prompt structure for more detailed license compliance analysis
- **Provider-Specific Error Handling**: Each AI provider has tailored error handling and fallback mechanisms

### Changed
- Renamed `openai_api_key` input description to be provider-agnostic
- Updated README.md with comprehensive examples for all three AI providers
- Enhanced test coverage for multi-provider functionality

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
