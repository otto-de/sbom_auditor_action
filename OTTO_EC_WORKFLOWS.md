# Example Workflows for otto-ec Organization

This file contains example GitHub Actions workflows optimized for otto-ec organization with organizational caching.

## Basic SBOM Audit with Organizational Caching

```yaml
name: SBOM License Audit

on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main ]

jobs:
  sbom-audit:
    runs-on: ubuntu-latest
    
    permissions:
      contents: read
      # Required for organizational cache access
      packages: read
      
    steps:
      - name: Checkout code
        uses: actions/checkout@v4

      - name: SBOM License Audit
        id: sbom-audit
        uses: otto-de/sbom_auditor_action@v1
        with:
          github_token: ${{ secrets.GITHUB_TOKEN }}
          # Enable organizational caching for otto-ec
          enable_cache: true
          cache_ttl_hours: 168  # 7 days
          # Fail on license violations
          fail_hard: true
          # Internal dependency patterns for otto-ec
          internal_dependency_pattern: |
            de.otto.ec.*
            com.ottoec.*

      - name: Upload Audit Results
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: sbom-audit-results
          path: |
            license-audit-report.md
            sbom_enriched.json
            LICENSES.md
```

## Advanced SBOM Audit with AI Summary (GitHub Models)

```yaml
name: Advanced SBOM Audit with AI

on:
  push:
    branches: [ main ]
  schedule:
    # Run weekly on Sundays
    - cron: '0 2 * * 0'

jobs:
  sbom-audit-ai:
    runs-on: ubuntu-latest
    
    permissions:
      contents: read
      # Required for organizational cache access
      packages: read
      # Required for GitHub Models AI
      models: read
      
    steps:
      - name: Checkout code
        uses: actions/checkout@v4

      - name: SBOM License Audit with AI Summary
        id: sbom-audit
        uses: otto-de/sbom_auditor_action@v1
        with:
          github_token: ${{ secrets.GITHUB_TOKEN }}
          # Organizational caching for otto-ec
          enable_cache: true
          cache_ttl_hours: 168
          # AI-powered summary using GitHub Models
          ai_provider: 'github'
          ai_model_name: 'openai/gpt-4o-mini'  # Cost-optimized
          # otto-ec specific patterns
          internal_dependency_pattern: |
            de.otto.ec.*
            com.ottoec.*
            pkg:maven/de.otto.ec
          # Don't fail for informational runs
          fail_hard: false

      - name: Post AI Summary to PR
        if: github.event_name == 'pull_request' && steps.sbom-audit.outputs.audit_exit_code != '0'
        uses: actions/github-script@v7
        with:
          script: |
            const fs = require('fs');
            const report = fs.readFileSync('license-audit-report.md', 'utf8');
            
            github.rest.issues.createComment({
              issue_number: context.issue.number,
              owner: context.repo.owner,
              repo: context.repo.repo,
              body: `## 📋 SBOM License Audit Results\n\n${report}`
            });

      - name: Commit License Report
        if: github.ref == 'refs/heads/main'
        uses: stefanzweifel/git-auto-commit-action@v5
        with:
          commit_message: "docs: Update license audit report [skip ci]"
          file_pattern: "docs/licenses/"
          repository_path: "docs/licenses/"
```

## Multi-Environment SBOM Audit

```yaml
name: Multi-Environment SBOM Audit

on:
  workflow_dispatch:
    inputs:
      environment:
        description: 'Environment to audit'
        required: true
        default: 'all'
        type: choice
        options:
        - all
        - development
        - staging
        - production

jobs:
  sbom-audit:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        environment: 
          - ${{ github.event.inputs.environment == 'all' && 'development' || github.event.inputs.environment }}
          - ${{ github.event.inputs.environment == 'all' && 'staging' || '' }}
          - ${{ github.event.inputs.environment == 'all' && 'production' || '' }}
      fail-fast: false
      
    permissions:
      contents: read
      packages: read
      
    steps:
      - name: Checkout code
        uses: actions/checkout@v4

      - name: Setup Environment-Specific Config
        run: |
          case "${{ matrix.environment }}" in
            development)
              echo "POLICY_PATH=.github/policies/dev-license-policy.json" >> $GITHUB_ENV
              echo "FAIL_HARD=false" >> $GITHUB_ENV
              ;;
            staging)
              echo "POLICY_PATH=.github/policies/staging-license-policy.json" >> $GITHUB_ENV
              echo "FAIL_HARD=true" >> $GITHUB_ENV
              ;;
            production)
              echo "POLICY_PATH=.github/policies/prod-license-policy.json" >> $GITHUB_ENV
              echo "FAIL_HARD=true" >> $GITHUB_ENV
              ;;
          esac

      - name: SBOM Audit - ${{ matrix.environment }}
        if: matrix.environment != ''
        uses: otto-de/sbom_auditor_action@v1
        with:
          github_token: ${{ secrets.GITHUB_TOKEN }}
          enable_cache: true
          cache_ttl_hours: 168
          policy_path: ${{ env.POLICY_PATH }}
          fail_hard: ${{ env.FAIL_HARD }}
          ai_provider: 'github'
          ai_model_name: 'openai/gpt-4o-mini'
          internal_dependency_pattern: |
            de.otto.ec.*
            com.ottoec.*

      - name: Archive Environment Report
        if: matrix.environment != ''
        uses: actions/upload-artifact@v4
        with:
          name: sbom-audit-${{ matrix.environment }}
          path: license-audit-report.md
```

## Cache Performance Monitoring

```yaml
name: Cache Performance Monitor

on:
  schedule:
    # Monitor cache performance daily
    - cron: '0 6 * * *'
  workflow_dispatch:

jobs:
  cache-stats:
    runs-on: ubuntu-latest
    
    permissions:
      contents: read
      packages: read
      
    steps:
      - name: Checkout code
        uses: actions/checkout@v4

      - name: Monitor Cache Performance
        uses: otto-de/sbom_auditor_action@v1
        with:
          github_token: ${{ secrets.GITHUB_TOKEN }}
          enable_cache: true
          cache_ttl_hours: 168
          # Run on test SBOM for monitoring
          # You would replace this with a path to a test SBOM file

      - name: Extract Cache Stats
        run: |
          echo "## Cache Performance Report" >> cache-report.md
          echo "Date: $(date)" >> cache-report.md
          echo "" >> cache-report.md
          
          # Extract performance metrics from action logs
          grep -i "cache" $GITHUB_STEP_SUMMARY || echo "Cache stats not available" >> cache-report.md

      - name: Upload Cache Report
        uses: actions/upload-artifact@v4
        with:
          name: cache-performance-$(date +%Y%m%d)
          path: cache-report.md
```

## Otto-EC Specific Configuration Examples

### Internal Dependency Patterns
```yaml
internal_dependency_pattern: |
  de.otto.ec.*
  com.ottoec.*
  pkg:maven/de.otto.ec
  pkg:npm/@otto-ec/
  pkg:pypi/otto-ec-*
```

### License Policy Examples

**Development (Permissive)**:
```json
{
  "allow": ["MIT", "Apache-2.0", "BSD-3-Clause", "ISC"],
  "needs-review": ["LGPL-2.1", "LGPL-3.0", "EPL-2.0"],
  "deny": ["GPL-2.0", "GPL-3.0", "AGPL-3.0"]
}
```

**Production (Strict)**:
```json
{
  "allow": ["MIT", "Apache-2.0", "BSD-3-Clause"],
  "needs-review": ["ISC", "BSD-2-Clause"],
  "deny": ["GPL-2.0", "GPL-3.0", "AGPL-3.0", "LGPL-2.1", "LGPL-3.0"]
}
```

## 🚀 Performance Expectations

With organizational caching enabled:

- **First repository run**: Normal speed (building cache)
- **Subsequent runs**: **703x faster** (9 it/s → 6,449 it/s)
- **Cache hit rate**: ~90%+ after initial population
- **API call reduction**: 90%+ fewer external requests

The cache will be shared across all otto-ec repositories automatically!
