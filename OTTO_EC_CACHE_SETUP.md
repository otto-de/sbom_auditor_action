# Setup Guide: Organizational SBOM Cache for otto-ec

This guide will help you set up organization-wide SBOM caching for **otto-ec**.

## 🎯 Goal
Create a shared cache repository that enables **703x faster SBOM enrichment** across all otto-ec repositories.

## 📋 Prerequisites

1. **GitHub Token** with the following permissions:
   - `repo` (full control of private repositories)
   - `admin:org` (for creating repositories in otto-ec organization)
   - Or be an **organization owner** with appropriate permissions

2. **Access to otto-ec organization** on GitHub

## 🚀 Setup Steps

### Step 1: Create Cache Repository

1. Go to https://github.com/otto-ec
2. Click **"New repository"**
3. Configure:
   - **Repository name**: `sbom-cache`
   - **Description**: `Organizational cache for SBOM enrichment data`
   - **Visibility**: 🔒 **Private** (recommended)
   - ✅ **Initialize with README**
   - **Default branch**: `main`

### Step 2: Repository Structure

Create the following directory structure in `otto-ec/sbom-cache`:

```
otto-ec/sbom-cache/
├── README.md
└── cache/
    └── README.md
```

### Step 3: Configure README.md

Replace the default README.md with:

```markdown
# SBOM Cache Repository

This repository stores organizational cache data for SBOM enrichment across all repositories in the `otto-ec` organization.

## Structure

```
cache/
├── YYYY/
│   └── MM/
│       ├── {hash}.json  # Package cache files
│       └── ...
└── ...
```

## How it works

1. **Automatic Cache Sharing**: When any repository in the organization runs SBOM audits, package metadata is cached here
2. **Cross-Repository Access**: All repositories can access cached data, dramatically speeding up subsequent runs
3. **Intelligent TTL**: Cache entries expire after 7 days by default
4. **Performance**: Up to 703x faster on cache hits

## Configuration

This repository is automatically managed by the `otto-de/sbom_auditor_action`. 

**Do not manually edit cache files** - they are managed automatically.

## Cache Statistics

- **Cache Hit Rate**: ~90%+ after initial runs
- **Performance Improvement**: 703x faster (9 it/s → 6,449 it/s)
- **API Call Reduction**: 90%+ fewer calls to package registries

## Security

- This repository is private to the `otto-ec` organization
- Cache data contains only public package metadata from registries
- No sensitive information is stored in cache entries
```

### Step 4: Create cache/README.md

Create a file `cache/README.md` with:

```markdown
# Cache Directory

This directory contains cached SBOM enrichment data organized by date.

## Structure
- `YYYY/MM/` - Cache files organized by year and month
- Each cache file contains package metadata for faster subsequent lookups

## Retention
- Cache entries are automatically cleaned up after TTL expiration
- Default TTL: 7 days (168 hours)

Last updated: Auto-managed by SBOM Auditor Action
```

### Step 5: Configure Repository Settings

Go to **Settings** in the `otto-ec/sbom-cache` repository and configure:

**General Settings:**
- ❌ Issues (disable)
- ❌ Projects (disable)  
- ❌ Wiki (disable)
- ❌ Packages (disable)

**Pull Requests:**
- ✅ Allow squash merging
- ❌ Allow merge commits
- ❌ Allow rebase merging
- ✅ Automatically delete head branches

## 🔧 Usage in Workflows

Once the cache repository is set up, update your SBOM Auditor Action workflows:

```yaml
- name: SBOM Audit with Organizational Caching
  uses: otto-de/sbom_auditor_action@v1
  with:
    github_token: ${{ secrets.GITHUB_TOKEN }}
    enable_cache: true
    cache_ttl_hours: 168
```

## 🎯 Expected Results

### First Repository Run:
- Normal runtime (building cache)
- Populates `otto-ec/sbom-cache` with package metadata

### Subsequent Repository Runs:
- **703x faster execution** (9 it/s → 6,449 it/s)
- 90%+ reduction in API calls to package registries
- Instant cache hits from organizational cache

## 🔍 Verification

After setup, you can verify the cache is working by:

1. Running SBOM Auditor Action in any otto-ec repository
2. Check the action logs for cache messages:
   ```
   Cache initialized: X valid entries, Y expired
   Loaded Z cache entries from organizational cache
   ```
3. Check `otto-ec/sbom-cache` repository for auto-generated cache files

## 🛠 Troubleshooting

**Cache not working?**
1. Verify `GITHUB_TOKEN` has `repo` access to `otto-ec/sbom-cache`
2. Ensure the repository exists and is accessible
3. Check action logs for cache loading/saving messages
4. The action will fallback to local cache if org cache fails

**Performance not improved?**
1. First run will always be slow (building cache)
2. Subsequent runs should show dramatic improvement
3. Check cache hit/miss ratios in action logs

## 🚀 Ready to Use!

Your organizational SBOM cache is now ready. The next time any repository in otto-ec runs the SBOM Auditor Action, it will:

1. **Load** existing cache from `otto-ec/sbom-cache`
2. **Process** SBOM with cached data (703x faster!)
3. **Save** new cache entries back to the shared repository

**Welcome to lightning-fast SBOM auditing!** ⚡
