# Release v0.4.2: Critical Exit Code Fix

## 🐛 **Critical Bug Fix**

### Restored Exit Status Logic
- **FIXED**: Action now properly fails when disallowed licenses are found
- **FIXED**: Restored missing exit status logic that was accidentally removed in v0.4.x
- **FIXED**: `fail_hard: true` now works correctly in GitHub Actions workflows

## 🔧 **What was broken**

In versions v0.4.0 and v0.4.1, the action would complete successfully even when license violations were detected, despite having `fail_hard: true` configured. This was a regression from v0.3.3 where the functionality worked correctly.

### Root Cause
During the v0.4.x enhancements, the exit status logic was inadvertently removed from the main function:

```python
# This critical logic was missing:
if denied or needs_review:
    logging.info("Found packages that are denied or need review. Exiting with status 1.")
    sys.exit(1)
else:
    logging.info("All packages conform to the license policy.")
    sys.exit(0)
```

## ✅ **What's Fixed**

### Exit Codes Now Work Correctly
- **Exit code 1**: When denied or needs-review packages are found
- **Exit code 0**: When all packages conform to the license policy
- **Compatible**: With GitHub Actions `fail_hard` functionality

### Behavior Restored
- Workflows will now fail properly when license violations are detected
- Same behavior as v0.3.3 but with all v0.4.x enhancements
- No changes to SBOM processing or license resolution logic

## 🧪 **Validation**

### Test Results Confirmed
```bash
# Test with violations → Exit code 1 ✅
python audit_licenses.py problem_sbom.json policy.json --markdown
# → Exits with code 1

# Test with compliant SBOM → Exit code 0 ✅  
python audit_licenses.py clean_sbom.json policy.json --markdown
# → Exits with code 0
```

### GitHub Actions Workflow
```yaml
- uses: otto-de/sbom_auditor_action@v0.4.2
  with:
    fail_hard: true  # Now works correctly! 🎉
```

## 📦 **No Breaking Changes**

This is a **patch release** that only fixes the exit code behavior. All other functionality remains unchanged:

- ✅ License resolver statistics (from v0.4.0)
- ✅ Organization-neutral design (from v0.4.1) 
- ✅ Enhanced artifact management (from v0.4.0)
- ✅ All input parameters and outputs unchanged
- ✅ Backward compatible with existing workflows

## 🙏 **Acknowledgments**

Huge thanks to **@emmersonbonnat-tw** for:
- Detailed bug report with excellent analysis
- Comparing v0.3.3 behavior with current versions
- Providing specific code references that made debugging fast
- Testing across multiple versions to identify the regression

This is exactly the kind of thorough issue reporting that makes open source better! 🌟

## 🔗 **Links**

- **Issue**: #6 - Action passes even when disallowed licenses are found  
- **Fix Commit**: https://github.com/otto-de/sbom_auditor_action/commit/1e06d07
- **Full Changelog**: https://github.com/otto-de/sbom_auditor_action/compare/v0.4.1...v0.4.2

---

**⚠️ Users of v0.4.0 and v0.4.1**: Please upgrade to v0.4.2 immediately if you rely on `fail_hard` functionality for compliance enforcement.