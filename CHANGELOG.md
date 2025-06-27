# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]

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
