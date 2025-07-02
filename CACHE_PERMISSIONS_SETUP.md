# Cache Repository Permissions Setup Guide

This guide explains how to configure the `otto-ec/sbom-cache` repository so that GitHub Actions from other repositories can write cache data to it.

## 🔐 Repository Access Configuration

### Step 1: Configure Repository Settings

1. Go to `https://github.com/otto-ec/sbom-cache`
2. Navigate to **Settings** → **Actions** → **General**
3. Configure the following settings:

#### Actions Permissions:
- ✅ **Allow all actions and reusable workflows**
- Or ✅ **Allow actions created by GitHub** + **Allow Marketplace actions by verified creators**

#### Workflow Permissions:
- ✅ **Read and write permissions**
- ✅ **Allow GitHub Actions to create and approve pull requests**

### Step 2: Organization-Level Permissions

1. Go to `https://github.com/organizations/otto-ec/settings/actions`
2. Under **Actions permissions**:
   - ✅ **Allow all actions and reusable workflows**
3. Under **Workflow permissions**:
   - ✅ **Read and write permissions**
   - ✅ **Allow GitHub Actions to create and approve pull requests**

### Step 3: Fine-Grained Token Permissions

If using fine-grained personal access tokens, ensure the token has:

- ✅ **Repository permissions**:
  - `contents: write` (to create/update cache files)
  - `metadata: read` (to access repository info)
  - `pull_requests: write` (if using PRs for cache updates)

- ✅ **Organization permissions**:
  - `members: read` (to verify organization membership)

## 🤖 Alternative: GitHub App Authentication

For better security, consider creating a GitHub App:

### Create GitHub App:
1. Go to `https://github.com/organizations/otto-ec/settings/apps`
2. Click **New GitHub App**
3. Configure:
   - **Name**: `SBOM Cache Manager`
   - **Homepage URL**: `https://github.com/otto-ec/sbom-cache`
   - **Repository permissions**:
     - Contents: **Read and write**
     - Metadata: **Read**
   - **Organization permissions**:
     - Members: **Read**

### Install App:
1. Install the app on the organization
2. Give it access to:
   - ✅ `otto-ec/sbom-cache` (required)
   - ✅ All repositories (recommended for automatic access)

## 🔧 Repository-Specific Configuration

### Option A: Classic Approach (Recommended)

Use the default `GITHUB_TOKEN` with organization-wide permissions:

```yaml
# In any otto-ec repository workflow:
- name: SBOM Audit with Org Cache
  uses: otto-de/sbom_auditor_action@v1
  with:
    github_token: ${{ secrets.GITHUB_TOKEN }}  # Uses default token
    enable_cache: true
```

**Requirements:**
- Organization allows `GITHUB_TOKEN` to access other repositories
- Cache repository has "read and write" workflow permissions

### Option B: Custom Token Approach

Create a custom token with broader permissions:

1. **Create Personal Access Token (Classic)**:
   - Go to `https://github.com/settings/tokens`
   - Select scopes:
     - ✅ `repo` (Full control of private repositories)
     - ✅ `write:org` (Write org data)

2. **Add to Organization Secrets**:
   - Go to `https://github.com/organizations/otto-ec/settings/secrets/actions`
   - Add secret: `SBOM_CACHE_TOKEN`

3. **Use in Workflows**:
```yaml
- name: SBOM Audit with Org Cache
  uses: otto-de/sbom_auditor_action@v1
  with:
    github_token: ${{ secrets.SBOM_CACHE_TOKEN }}  # Custom token
    enable_cache: true
```

## 🧪 Test Cache Access

Test if the configuration works:

```yaml
name: Test Cache Access
on: workflow_dispatch

jobs:
  test-cache:
    runs-on: ubuntu-latest
    steps:
      - name: Test Cache Repository Access
        run: |
          # Test write access to cache repository
          curl -X PUT \
            -H "Authorization: Bearer ${{ secrets.GITHUB_TOKEN }}" \
            -H "Accept: application/vnd.github.v3+json" \
            "https://api.github.com/repos/otto-ec/sbom-cache/contents/test/access-test.txt" \
            -d '{
              "message": "Test cache access",
              "content": "'$(echo "Cache access test at $(date)" | base64)'"
            }'
```

## ⚠️ Security Considerations

### Least Privilege Principle:
- Only grant necessary permissions
- Use repository-specific tokens when possible
- Regularly rotate tokens

### Audit Access:
- Monitor cache repository for unexpected changes
- Review access logs in GitHub audit log
- Set up notifications for cache repository changes

## 🚨 Troubleshooting

### Common Issues:

**"Resource not accessible by integration"**:
- Check workflow permissions in repository settings
- Verify organization allows repository access
- Ensure token has sufficient permissions

**"API rate limit exceeded"**:
- Cache operations respect rate limits
- Consider using GitHub App for higher limits
- Implement retry logic with exponential backoff

**"Not Found" errors**:
- Verify cache repository exists and is accessible
- Check repository visibility (private vs public)
- Confirm organization membership

### Debug Commands:

```bash
# Test repository access
curl -H "Authorization: Bearer $TOKEN" \
  https://api.github.com/repos/otto-ec/sbom-cache

# Test write permissions
curl -X PUT \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  https://api.github.com/repos/otto-ec/sbom-cache/contents/test.json \
  -d '{"message":"test","content":"dGVzdA=="}'
```

## ✅ Verification Checklist

After configuration, verify:

- [ ] Repository has "Read and write" workflow permissions
- [ ] Organization allows cross-repository access
- [ ] Test workflow can write to cache repository
- [ ] Cache files appear in `otto-ec/sbom-cache`
- [ ] Cache loading works in subsequent runs
- [ ] No permission errors in action logs

## 🎯 Expected Workflow

Once properly configured:

1. **First repository run**: Writes cache to `otto-ec/sbom-cache`
2. **Subsequent repository runs**: Read from shared cache (703x faster!)
3. **Cache updates**: Automatically managed by SBOM Auditor Action
4. **Cache cleanup**: Expired entries automatically removed

Your organizational cache is now ready for enterprise-scale SBOM auditing! 🚀
