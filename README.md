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
        uses: otto-de/sbom_auditor_action@v1
        with:
          github_token: ${{ secrets.GITHUB_TOKEN }}
          fail_hard: true
```

## Advanced Configuration

### Package-Specific Policies

For cases where the general license-based audit is not sufficient, you can define specific policies for individual packages. This is useful for:

*   Packages that are incorrectly identified as having `NO-LICENSE-FOUND`.
*   Dependencies with non-standard license agreements.
*   Internal packages that do not require a license audit.

You can create a `package_policy.json` file in your repository and provide the path to it using the `package_policy_path` input. The policy for a package is determined by its Package URL (PURL).

**Example `package_policy.json`:**

```json
{
  "packagePolicies": [
    {
      "purl": "pkg:npm/left-pad@1.3.0",
      "usagePolicy": "allow",
      "reason": "Special agreement for this package, despite its non-standard license."
    },
    {
      "purl": "pkg:pypi/internal-tool@2.5",
      "usagePolicy": "allow",
      "reason": "This is an internal tool, license audit is not required."
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
