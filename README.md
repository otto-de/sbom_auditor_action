# SBOM Auditor Action

This GitHub Action audits Software Bill of Materials (SBOM) for license compliance. It performs the following steps:
1.  Fetches the SBOM from the repository's dependency graph.
2.  Enriches the SBOM with detailed license information.
3.  Collects the full license texts for all dependencies.
4.  Audits the licenses against a defined policy.
5.  Generates a license audit report, optionally including an AI-assisted summary using OpenAI, Azure OpenAI, or AWS Bedrock.

## Usage

To use this action in your workflow, add the following step:

```yaml
- name: Audit SBOM
  uses: otto-de/sbom_auditor_action@v1
  with:
    # GitHub token with permissions to read the dependency graph.
    github_token: ${{ secrets.GITHUB_TOKEN }}

    # (Optional) If true, the workflow will fail if license violations are found.
    # fail_hard: true

    # (Optional) API key for AI-assisted summary generation.
    # openai_api_key: ${{ secrets.OPENAI_API_KEY }}

    # (Optional) AI provider to use for summary generation.
    # ai_provider: 'openai'  # Options: openai, azure, bedrock, github

    # (Optional) Azure OpenAI specific configuration
    # azure_endpoint: ${{ secrets.AZURE_OPENAI_ENDPOINT }}
    # azure_deployment: ${{ secrets.AZURE_OPENAI_DEPLOYMENT }}

    # (Optional) AWS Bedrock specific configuration
    # aws_region: 'us-east-1'

    # (Optional) Specific AI model name to use
    # ai_model_name: 'gpt-4'

    # (Optional) Path to a custom license policy file.
    # policy_path: '.github/license_policy.json'

    # (Optional) Path to a custom package policy file.
    # package_policy_path: '.github/package_policy.json'

    # (Optional) A newline-separated list of regex patterns to identify internal dependencies that should be skipped from the audit.
    # internal_dependency_pattern: |
    #   com.my-company.*
    #   de.my-other-company.*
```

## Inputs

| Name                  | Description                                                                                                  | Required | Default                                                  |
| --------------------- | ------------------------------------------------------------------------------------------------------------ | -------- | -------------------------------------------------------- |
| `github_token`        | GitHub token to access the dependency graph API.                                                             | `true`   | `${{ github.token }}`                                  |
| `fail_hard`           | If `true`, the action will fail if license violations are found.                                             | `false`  | `'false'`                                                |
| `openai_api_key`      | API key for AI-assisted summary generation. Use with `ai_provider` input to specify the provider.          | `false`  | `''`                                                     |
| `ai_provider`         | AI provider to use for summary generation. Options: `openai`, `azure`, `bedrock`, `github`.               | `false`  | `'openai'`                                               |
| `azure_endpoint`      | Azure OpenAI endpoint URL (required when `ai_provider` is `azure`).                                        | `false`* | `''`                                                     |
| `azure_deployment`    | Azure OpenAI deployment name (required when `ai_provider` is `azure`).                                     | `false`* | `''`                                                     |
| `aws_region`          | AWS region for Bedrock (required when `ai_provider` is `bedrock`).                                         | `false`* | `''`                                                     |
| `ai_model_name`       | Specific AI model name to use (optional, provider-specific defaults will be used).                         | `false`  | `''`                                                     |
| `policy_path`         | Path to a custom policy JSON file. Can contain `policies` (license rules) and/or `packagePolicies` (PURL-based exceptions). By default merged with the built-in policy. | `false`  | `''`                                                     |
| `policy_mode`         | How to handle custom policies: `merge` (default) combines with built-in policies, `replace` uses only the custom policy. | `false`  | `'merge'`                                                |
| `package_policy_path` | ⚠️ **Deprecated**: Use `policy_path` with `packagePolicies` instead. Path to a separate package policy file. | `false`  | `''`                                                     |
| `internal_dependency_pattern` | A newline-separated list of regex patterns to identify internal dependencies that should be skipped from the audit. | `false`  | `''` (no internal patterns by default)                  |
| `enable_cache`        | Enable caching for SBOM enrichment to speed up subsequent runs (recommended for organizations).                  | `false`  | `'true'`                                                 |
| `cache_ttl_hours`     | Cache time-to-live in hours for package data (default: 168 = 7 days).                                          | `false`  | `'168'`                                                  |

**Note:** Parameters marked with `*` are conditionally required based on the selected `ai_provider`:
- `azure_endpoint` and `azure_deployment` are required when `ai_provider` is `'azure'`
- `aws_region` is required when `ai_provider` is `'bedrock'`

**⚠️ Important:** Input names use **underscores** (`_`), not hyphens (`-`). 
- ✅ Correct: `cache_ttl_hours`, `enable_cache`, `internal_dependency_pattern`
- ❌ Wrong: `cache-ttl-hours`, `enable-cache`, `internal-dependency-pattern`

## Outputs

| Name                     | Description                                                              |
| ------------------------ | ------------------------------------------------------------------------ |
| `audit_exit_code`        | The exit code of the license audit. `0` if successful, non-zero otherwise. |
| `license-audit-report`   | Path to the license audit report in markdown format.                     |
| `sbom_enriched`          | Path to the enriched SBOM file.                                          |
| `licenses_md`            | Path to the collected license texts.                                     |

## AI-Assisted Summary

This action can use the OpenAI API to generate an AI-assisted summary of the license audit report. This provides a high-level overview of the license landscape, potential risks, and recommendations.

To enable this feature, you must provide an `openai_api_key`.

### Example Summary

Here is an example of what the AI-assisted summary might look like in your report:

> ### AI-Assisted License Landscape Summary
>
> **Overall Status:**
> The license landscape of this project is generally compliant, with the majority of dependencies using permissive licenses like MIT and Apache-2.0. There are no licenses from the "deny" list. However, there are a few licenses that fall into the "needs-review" category, which require closer inspection.
>
> **Key Risks:**
> *   **`EPL-2.0`**: The Eclipse Public License 2.0 is a weak copyleft license. While it is generally acceptable for use in commercial software, it requires that any modifications to the source code be released under the same license.
> *   **`LGPL-2.0-only`**: The GNU Lesser General Public License 2.0 is a weak copyleft license. It is more permissive than the GPL, but it still has some requirements that need to be considered.
>
> **Recommendations:**
> 1.  **Review `needs-review` licenses:** Carefully examine the dependencies using `EPL-2.0` and `LGPL-2.0-only` to ensure that your use case complies with the license terms.
> 2.  **Monitor for new dependencies:** As the project evolves, continue to monitor the licenses of new dependencies to ensure they align with your compliance policies.

## AI-Assisted Summary Examples

The action supports multiple AI providers for generating intelligent license compliance summaries. Each provider has its own configuration requirements:

### OpenAI (Default)

```yaml
- name: SBOM Audit with OpenAI
  uses: otto-de/sbom_auditor_action@v1
  with:
    github_token: ${{ secrets.GITHUB_TOKEN }}
    openai_api_key: ${{ secrets.OPENAI_API_KEY }}
    ai_provider: 'openai'
    ai_model_name: 'gpt-4'  # Optional: defaults to gpt-3.5-turbo
```

### Azure OpenAI

```yaml
- name: SBOM Audit with Azure OpenAI
  uses: otto-de/sbom_auditor_action@v1
  with:
    github_token: ${{ secrets.GITHUB_TOKEN }}
    openai_api_key: ${{ secrets.AZURE_OPENAI_API_KEY }}
    ai_provider: 'azure'
    azure_endpoint: ${{ secrets.AZURE_OPENAI_ENDPOINT }}
    azure_deployment: ${{ secrets.AZURE_OPENAI_DEPLOYMENT }}
```

### AWS Bedrock

```yaml
- name: SBOM Audit with AWS Bedrock
  uses: otto-de/sbom_auditor_action@v1
  with:
    github_token: ${{ secrets.GITHUB_TOKEN }}
    ai_provider: 'bedrock'
    aws_region: 'us-east-1'
    ai_model_name: 'anthropic.claude-3-5-sonnet-20241022-v2:0'  # Optional
  env:
    # AWS credentials can be provided via environment variables
    AWS_ACCESS_KEY_ID: ${{ secrets.AWS_ACCESS_KEY_ID }}
    AWS_SECRET_ACCESS_KEY: ${{ secrets.AWS_SECRET_ACCESS_KEY }}
    # Or use IAM roles for authentication
```

**Note for AWS Bedrock:** You can either provide the AWS access key via the `openai_api_key` input (in which case you must also set `AWS_SECRET_ACCESS_KEY` as an environment variable), or use environment variables for AWS credentials, or rely on IAM roles if running on AWS infrastructure.

### GitHub Models (Beta)

```yaml
- name: SBOM Audit with GitHub Models
  uses: otto-de/sbom_auditor_action@v1
  with:
    github_token: ${{ secrets.GITHUB_TOKEN }}
    ai_provider: 'github'
    ai_model_name: 'openai/gpt-4o-mini'  # Optional: defaults to openai/gpt-4o-mini
  # Note: Requires models: read permission in workflow
```

**Note for GitHub Models:** This provider uses the GitHub Models API (in beta) and requires the `models: read` permission in your workflow. Add this to your workflow file:

```yaml
permissions:
  models: read
  contents: read  # Required for SBOM access
```

## Example Workflow

Here is an example of a workflow that runs the SBOM audit on every push to the `main` branch:

```yaml
name: SBOM Audit

on:
  push:
    branches:
      - main

jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout code
        uses: actions/checkout@v4

      - name: Run SBOM Auditor
        id: sbom-audit
        uses: otto-de/sbom_auditor_action@v0.4.1
        with:
          github_token: ${{ secrets.GITHUB_TOKEN }}
          fail_hard: true
          enable_cache: true
          cache_ttl_hours: 168
          debug: false

      - name: Upload Audit Artifacts
        uses: actions/upload-artifact@v4
        with:
          name: sbom-audit-artifacts
          path: |
            ${{ steps.sbom-audit.outputs.licenses_md }}
            ${{ steps.sbom-audit.outputs.sbom_enriched }}
```

## Advanced Configuration

### Custom Policies

The action uses a built-in policy that covers common open-source licenses. You can customize this behavior in two ways:

#### Option 1: Extend Default Policies (Recommended)

Create a custom policy file that **adds exceptions** to the default policies. This is the most common use case:

```json
// .github/license_policy.json
{
  "policies": [
    {"id": "EPL-2.0", "usagePolicy": "allow", "reason": "Approved by legal team"}
  ],
  "packagePolicies": [
    {
      "purl": "pkg:maven/jakarta.ws.rs/jakarta.ws.rs-api",
      "usagePolicy": "allow",
      "reason": "Jakarta API approved - we're not modifying anything"
    },
    {
      "purl": "pkg:maven/org.jboss/*",
      "usagePolicy": "allow",
      "reason": "All JBoss packages approved"
    }
  ]
}
```

```yaml
- name: Run SBOM Auditor
  uses: otto-de/sbom_auditor_action@v1
  with:
    github_token: ${{ secrets.GITHUB_TOKEN }}
    policy_path: '.github/license_policy.json'
    # policy_mode: 'merge'  # Default - merges with built-in policies
```

#### Option 2: Replace Default Policies Completely

If you want to use **only your own policies** without the built-in defaults:

```yaml
- name: Run SBOM Auditor
  uses: otto-de/sbom_auditor_action@v1
  with:
    github_token: ${{ secrets.GITHUB_TOKEN }}
    policy_path: '.github/license_policy.json'
    policy_mode: 'replace'  # Use ONLY the custom policy
```

### Policy File Structure

A policy file can contain any combination of these sections:

```json
{
  "policies": [
    {
      "id": "MIT",
      "usagePolicy": "allow"
    },
    {
      "id": "GPL-3.0-only",
      "usagePolicy": "deny",
      "reason": "Copyleft not allowed"
    }
  ],
  "packagePolicies": [
    {
      "purl": "pkg:maven/com.example/my-package",
      "usagePolicy": "allow",
      "reason": "Specific package exception"
    }
  ],
  "licenseAliases": {
    "The MIT License": "MIT",
    "Apache 2.0": "Apache-2.0"
  }
}
```

| Section | Purpose |
|---------|----------|
| `policies` | License-based rules (by SPDX ID) |
| `packagePolicies` | PURL-based exceptions for specific packages |
| `licenseAliases` | Map non-standard license names to SPDX IDs |

### Package Policies (PURL-based Exceptions)

Package policies allow you to override the license-based audit for specific packages. This is useful for:

*   Packages incorrectly identified as having `NO-LICENSE-FOUND`
*   Dependencies with non-standard license agreements approved by your legal team
*   Internal packages that don't require license auditing

#### PURL Matching with Wildcards

The action uses `fnmatch` for PURL matching, supporting `*` and `?` wildcards:

```json
{
  "packagePolicies": [
    // Exact package (all versions - version in PURL is ignored)
    {"purl": "pkg:maven/jakarta.ws.rs/jakarta.ws.rs-api", "usagePolicy": "allow"},
    
    // All packages in a group
    {"purl": "pkg:maven/org.jboss/*", "usagePolicy": "allow"},
    
    // All jakarta APIs
    {"purl": "pkg:maven/jakarta.*/jakarta.*-api", "usagePolicy": "allow"},
    
    // Specific npm scope
    {"purl": "pkg:npm/@mycompany/*", "usagePolicy": "allow"}
  ]
}
```

> **Note:** Query parameters (e.g., `?type=jar`) are automatically stripped before matching, so `pkg:maven/group/artifact` matches `pkg:maven/group/artifact@1.0.0?type=jar`.

### Skipping Internal Dependencies

To skip internal dependencies from the audit, you can use the `internal_dependency_pattern` input. This input accepts a regular expression that is matched against the PURL of each dependency. If the PURL matches the pattern, the dependency is skipped.

**Example workflow skipping internal dependencies:**

```yaml
- name: Run SBOM Auditor and Skip Internal Dependencies
  uses: otto-de/sbom_auditor_action@v0.4.1
  with:
    github_token: ${{ secrets.GITHUB_TOKEN }}
    internal_dependency_pattern: |
      com\.my-company\..*
      org\.my-company\..*
      pkg:maven/com\.my-company\..*
      pkg:npm/@my-company/.*
    enable_cache: true
    cache_ttl_hours: 168
    debug: false
```

**Example for Otto teams (v0.4.1+):**

```yaml
- name: Run SBOM Auditor for Otto Project  
  uses: otto-de/sbom_auditor_action@v0.4.1
  with:
    github_token: ${{ secrets.GITHUB_TOKEN }}
    internal_dependency_pattern: |
      de\.otto\..*
      com\.otto\..*
      com\.github\.otto-ec.*
      pkg:maven/de\.otto\..*
      pkg:maven/com\.otto\..*
      pkg:github/otto-ec/.*
      pkg:github/otto-de/.*
    enable_cache: true
    cache_ttl_hours: 168
    fail_hard: true
```

### Alternative: Committing the License Report

Instead of uploading the license report as an artifact, you can configure your workflow to commit it directly to your repository. This is useful for keeping track of license changes over time in version control.

**Example workflow committing the `licenses.md` file:**

```yaml
name: SBOM Audit and Commit Report

on:
  push:
    branches:
      - main

jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout code
        uses: actions/checkout@v4

      - name: Run SBOM Auditor
        id: sbom-audit
        uses: otto-de/sbom_auditor_action@v1
        with:
          github_token: ${{ secrets.GITHUB_TOKEN }}
          fail_hard: false # Set to false to allow committing the report even with violations

      - name: Organize License Report
        run: |
          mkdir -p licenses
          mv ${{ steps.sbom-audit.outputs.licenses_md }} licenses/licenses.md
        
      - name: Commit License Report
        uses: stefanzweifel/git-auto-commit-action@v5
        with:
          commit_message: "docs: Update license report"
          file_pattern: licenses/licenses.md
```

## Organizational Caching for SBOM Enrichment

The action includes intelligent caching for SBOM enrichment to dramatically speed up license audits across your organization:

### Benefits

- **🚀 703x faster** on subsequent runs (measured: 9 it/s → 6,449 it/s)
- **📡 Reduced API calls** to package registries (npm, PyPI, Maven Central)
- **🏢 Organization-wide sharing** of package metadata across repositories
- **⚡ Faster CI/CD pipelines** with cached license data

### How it works

The action uses a **hybrid caching strategy** for maximum performance:

1. **Local Cache**: Immediate reuse within the same workflow run
2. **GitHub Actions Cache**: Cross-job sharing within the same repository  
3. **Organization-wide Cache**: Shared cache repository for cross-repository access

### Cache Access Mechanism

#### Repository-Level Cache (GitHub Actions)
```yaml
# Automatic per-repository caching
- uses: actions/cache@v4
  with:
    path: ./sbom_cache
    key: sbom-cache-${{ github.repository_owner }}-${{ hashFiles('**/*.json') }}
    restore-keys: sbom-cache-${{ github.repository_owner }}-
```

#### Organization-wide Cache (Shared Repository)
The action automatically:
1. **Loads** cache entries from `{organization}/sbom-cache` repository
2. **Saves** new cache entries back to the shared repository
3. **Shares** package metadata across all organization repositories

### Setup for Organization-wide Caching

#### Option 1: Automatic Setup (Recommended)
The action will automatically attempt to use organization-wide caching if:
- `GITHUB_TOKEN` has access to create/read repositories in your organization
- The token has `repo` permissions for the organization

#### Option 2: Manual Setup
Create a dedicated cache repository for your organization:

```bash
# Create the shared cache repository
python helpers/setup_org_cache.py \
  --github-token $GITHUB_TOKEN \
  --organization otto-de \
  --repo-name sbom-cache
```

This creates a private repository `otto-de/sbom-cache` that stores cache data.

### Configuration

```yaml
- name: SBOM Audit with Organizational Caching
  uses: otto-de/sbom_auditor_action@v1
  with:
    github_token: ${{ secrets.GITHUB_TOKEN }}  # Used for org-wide cache access
    enable_cache: true          # Enable caching (default: true)
    cache_ttl_hours: 168        # Cache for 7 days (default: 168 hours)
```

### Cache Strategy Details

The multi-level cache strategy ensures maximum performance:

| Level | Scope | Speed | Sharing |
|-------|-------|-------|---------|
| **Local** | Current workflow | Instant | Same job |
| **GitHub Actions** | Repository | Very fast | Same repo |
| **Organization** | All repos | Fast | Organization-wide |

### Cache Keys and Organization Sharing

- **Local Cache Key**: `{purl_hash}.json`
- **GitHub Actions Key**: `sbom-cache-{org}-{dependency-hash}-{ttl}`
- **Organization Cache Path**: `cache/{YYYY}/{MM}/{purl_hash}.json`

### Performance Metrics

Real-world performance improvement:
```
First run (cold cache):     ████████ 3/3 [00:00<00:00,    9.17it/s]
Second run (warm cache):    ████████ 3/3 [00:00<00:00, 6449.47it/s]
Performance improvement:    703x faster! 🚀
API calls reduction:        ~90% fewer external requests
```

### Organization Benefits

**For the first repository that runs:**
- Builds cache for the entire organization
- Normal runtime (cold cache)
- Populates shared repository with package metadata

**For all subsequent repositories:**
- Instant cache hits from organizational cache
- 703x faster execution
- Minimal API calls to external registries

### Security and Privacy

- **Cache Repository**: Private to your organization
- **Cache Content**: Only public package metadata (licenses, versions)
- **No Sensitive Data**: No source code or proprietary information cached
- **Automatic Cleanup**: Expired entries are automatically removed

### Disabling Cache

To disable caching (not recommended for production):

```yaml
- name: SBOM Audit without Caching
  uses: otto-de/sbom_auditor_action@v1
  with:
    github_token: ${{ secrets.GITHUB_TOKEN }}
    enable_cache: false
```

### Troubleshooting

If organizational caching isn't working:

1. **Check Token Permissions**: Ensure `GITHUB_TOKEN` has `repo` access
2. **Verify Repository**: Confirm `{organization}/sbom-cache` repository exists
3. **Check Logs**: Look for cache loading/saving messages in action logs
4. **Fallback**: Action will work with local/repository cache even if org cache fails
