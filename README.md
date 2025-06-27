# SBOM Auditor Action

This GitHub Action audits Software Bill of Materials (SBOM) for license compliance. It performs the following steps:
1.  Fetches the SBOM from the repository's dependency graph.
2.  Enriches the SBOM with detailed license information (optionally using the OpenAI API).
3.  Collects the full license texts for all dependencies.
4.  Audits the licenses against a defined policy.
5.  Generates a license audit report.

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

    # (Optional and not implemented yet) OpenAI API key for enriching the SBOM with more accurate license data.
    # openai_api_key: ${{ secrets.OPENAI_API_KEY }}

    # (Optional) Path to a custom license policy file.
    # policy_path: '.github/license_policy.json'

    # (Optional) Path to a custom package policy file.
    # package_policy_path: '.github/package_policy.json'
```

## Inputs

| Name                  | Description                                                                                                  | Required | Default                                                  |
| --------------------- | ------------------------------------------------------------------------------------------------------------ | -------- | -------------------------------------------------------- |
| `github_token`        | GitHub token to access the dependency graph API.                                                             | `true`   | `${{ github.token }}`                                  |
| `fail_hard`           | If `true`, the action will fail if license violations are found.                                             | `false`  | `'false'`                                                |
| `openai_api_key`      | OpenAI API key for enriching the SBOM.                                                                       | `false`  | `''`                                                     |
| `package_policy_path` | Path to an optional package policy JSON file. If not provided, the action looks for a file named `package_policy.json` in the `helpers` directory of the action itself. | `false`  | `''`                                                     |
| `policy_path`         | Path to an optional license policy JSON file. If not provided, the action uses the `policy.json` file included with the action. | `false`  | `''`                                                     |

## Outputs

| Name                     | Description                                                              |
| ------------------------ | ------------------------------------------------------------------------ |
| `audit_exit_code`        | The exit code of the license audit. `0` if successful, non-zero otherwise. |
| `license-audit-report`   | Path to the license audit report in markdown format.                     |
| `sbom_enriched`          | Path to the enriched SBOM file.                                          |
| `licenses_md`            | Path to the collected license texts.                                     |

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
