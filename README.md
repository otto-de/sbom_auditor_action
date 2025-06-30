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
    # ai_provider: 'openai'  # Options: openai, azure, bedrock

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
| `ai_provider`         | AI provider to use for summary generation. Options: `openai`, `azure`, `bedrock`.                          | `false`  | `'openai'`                                               |
| `azure_endpoint`      | Azure OpenAI endpoint URL (required when `ai_provider` is `azure`).                                        | `false`  | `''`                                                     |
| `azure_deployment`    | Azure OpenAI deployment name (required when `ai_provider` is `azure`).                                     | `false`  | `''`                                                     |
| `aws_region`          | AWS region for Bedrock (required when `ai_provider` is `bedrock`).                                         | `false`  | `''`                                                     |
| `ai_model_name`       | Specific AI model name to use (optional, provider-specific defaults will be used).                         | `false`  | `''`                                                     |
| `package_policy_path` | Path to an optional package policy JSON file. If not provided, the action looks for a file named `package_policy.json` in the `helpers` directory of the action itself. | `false`  | `''`                                                     |
| `policy_path`         | Path to an optional license policy JSON file. If not provided, the action uses the `policy.json` file included with the action. | `false`  | `''`                                                     |
| `internal_dependency_pattern` | A newline-separated list of regex patterns to identify internal dependencies that should be skipped from the audit. | `false`  | `'de.otto.*'`                                            |

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
        uses: otto-de/sbom_auditor_action@v1
        with:
          github_token: ${{ secrets.GITHUB_TOKEN }}
          fail_hard: true

      - name: Upload Audit Artifacts
        uses: actions/upload-artifact@v4
        with:
          name: sbom-audit-artifacts
          path: |
            ${{ steps.sbom-audit.outputs.licenses_md }}
            ${{ steps.sbom-audit.outputs.sbom_enriched }}
```

## Advanced Configuration

### Package-Specific Policies

For cases where the general license-based audit is not sufficient, you can define specific policies for individual packages. This is useful for:

*   Packages that are incorrectly identified as having `NO-LICENSE-FOUND`.
*   Dependencies with non-standard license agreements.
*   Internal packages that do not require a license audit.

You can create a `package_policy.json` file in your repository and provide the path to it using the `package_policy_path` input. The policy for a package is determined by its Package URL (PURL).

### Skipping Internal Dependencies

To skip internal dependencies from the audit, you can use the `internal_dependency_pattern` input. This input accepts a regular expression that is matched against the PURL of each dependency. If the PURL matches the pattern, the dependency is skipped.

**Example workflow skipping internal dependencies:**

```yaml
- name: Run SBOM Auditor and Skip Internal Dependencies
  uses: otto-de/sbom_auditor_action@v1
  with:
    github_token: ${{ secrets.GITHUB_TOKEN }}
    internal_dependency_pattern: |
      com.my-company.*
      de.my-other-company.*
```


#### PURL Matching

To provide maximum flexibility, the action supports different matching strategies for PURLs. The matching logic automatically **normalizes** PURLs by removing any qualifiers (e.g., `?type=jar`, `?os=windows`) before comparison, which significantly improves reliability.

You can specify the matching strategy using the `matcher` field in your policy rule. If omitted, it defaults to `exact`.

| Matcher          | Description                                                                                                |
| ---------------- | ---------------------------------------------------------------------------------------------------------- |
| `exact`          | (Default) The PURL from the SBOM must exactly match the PURL in the policy (after normalization).          |
| `all-versions`   | Matches the package regardless of its version. The version part of the PURL is ignored during comparison.    |
| `wildcard`       | Allows the use of `*` as a wildcard in the policy PURL. Useful for matching groups of related packages. |

**Example `package_policy.json` with Matchers:**

```json
{
  "packagePolicies": [
    {
      "purl": "pkg:npm/react",
      "matcher": "all-versions",
      "usagePolicy": "allow",
      "reason": "All versions of React are approved."
    },
    {
      "purl": "pkg:maven/org.apache.logging.log4j/*",
      "matcher": "wildcard",
      "usagePolicy": "deny",
      "reason": "All log4j packages are denied due to security vulnerabilities."
    },
    {
      "purl": "pkg:pypi/requests@2.28.1",
      "matcher": "exact",
      "usagePolicy": "allow",
      "reason": "This specific version of requests is allowed."
    }
  ]
}
```

**Example workflow using `package_policy_path`:**

```yaml
- name: Run SBOM Auditor with Package Policies
  uses: otto-de/sbom_auditor_action@v1
  with:
    github_token: ${{ secrets.GITHUB_TOKEN }}
    package_policy_path: '.github/config/package_policy.json'
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
