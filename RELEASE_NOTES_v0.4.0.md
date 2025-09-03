# Release v0.4.0: Enhanced License Resolution Statistics & Improved Artifacts

## 🚀 Major Features

### 📊 License Resolver Statistics
- **NEW**: Comprehensive license resolution statistics in audit summaries
- Track resolution method effectiveness (deps.dev, SPDX fuzzy matching, AI, POM parsing, cache hits)
- Enhanced transparency into the license resolution pipeline
- Detailed counts and descriptions for each resolution method

### 📦 Improved Artifact Management  
- **FIXED**: ZIP-in-ZIP artifact issues resolved
- Separate artifact uploads for better organization:
  - `sbom-enriched`: Contains the enriched SBOM file
  - `license-artifacts`: Contains license texts and audit reports
- Added compression-level control and retention policies
- Cleaner artifact structure for downstream consumption

## 🔧 Technical Improvements

### Enhanced Audit Pipeline
- Added resolver statistics collection during enrichment phase
- Improved summary generation with detailed resolution method tracking  
- Better integration between enrichment and audit phases
- Configurable debug logging for production environments

### Workflow Optimizations
- Optimized artifact upload configuration
- Better error handling and logging
- Improved caching strategies
- Enhanced GitHub Actions integration

## 🐛 Bug Fixes

- Fixed artifact compression issues causing nested ZIP files
- Resolved summary generation duplications
- Improved error handling in license resolution pipeline
- Better handling of missing license information

## 📈 Performance Improvements

- More efficient artifact handling
- Reduced redundant processing
- Optimized summary generation
- Better memory usage for large SBOMs

## 🔄 Breaking Changes

None - this release is fully backward compatible.

## 📋 Migration Guide

No migration required - existing workflows will continue to work without changes. The new resolver statistics will automatically appear in your audit summaries.

## 🧪 Testing

- Validated with real-world SBOM files
- Comprehensive testing of all license resolution methods
- Artifact upload/download verification
- Debug flag functionality confirmed

---

**Full Changelog**: https://github.com/otto-de/sbom_auditor_action/compare/v0.3.3...v0.4.0
