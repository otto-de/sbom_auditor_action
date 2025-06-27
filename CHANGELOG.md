# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]

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
