#!/bin/bash
# Debug script for GitHub Models AI Summary issue in SBOM Auditor Action
# This script helps diagnose why AI Summary is not appearing with GitHub Models

echo "🔍 SBOM Auditor Action - GitHub Models AI Summary Debug"
echo "====================================================="

# Check GitHub token
echo ""
echo "1. 🔐 Checking GitHub Token..."
if [ -z "$GITHUB_TOKEN" ]; then
    echo "❌ GITHUB_TOKEN environment variable is not set"
    echo "   Solution: Ensure GITHUB_TOKEN is available in your GitHub Actions workflow"
else
    echo "✅ GITHUB_TOKEN is set (length: ${#GITHUB_TOKEN})"
fi

# Check GitHub Models API access
echo ""
echo "2. 🚀 Testing GitHub Models API access..."
if [ -n "$GITHUB_TOKEN" ]; then
    response=$(curl -s -w "HTTP_STATUS:%{http_code}" \
        -H "Authorization: Bearer $GITHUB_TOKEN" \
        -H "Content-Type: application/json" \
        -d '{
            "messages": [{"role": "user", "content": "test"}],
            "model": "openai/gpt-4o-mini",
            "max_tokens": 1
        }' \
        "https://models.github.ai/inference/chat/completions")
    
    http_status=$(echo "$response" | grep -o "HTTP_STATUS:[0-9]*" | cut -d: -f2)
    response_body=$(echo "$response" | sed 's/HTTP_STATUS:[0-9]*$//')
    
    case $http_status in
        200)
            echo "✅ GitHub Models API access successful"
            ;;
        401)
            echo "❌ GitHub Models API authentication failed (401)"
            echo "   Solution: Check that GITHUB_TOKEN is valid"
            ;;
        403)
            echo "❌ GitHub Models API access forbidden (403)"
            echo "   Solution: Ensure 'models: read' permission is granted"
            echo "   Check organization settings for GitHub Models access"
            ;;
        404)
            echo "❌ GitHub Models API endpoint not found (404)"
            echo "   Solution: Verify GitHub Models is available for your organization"
            ;;
        *)
            echo "⚠️  GitHub Models API returned status: $http_status"
            echo "   Response: $response_body"
            ;;
    esac
else
    echo "⏭️  Skipping API test (no token available)"
fi

# Check workflow permissions
echo ""
echo "3. 📋 Workflow Permissions Check..."
echo "   Required permissions for GitHub Models:"
echo "   ✅ contents: read"
echo "   ✅ models: read  ← CRITICAL for GitHub Models"
echo ""
echo "   Add this to your workflow:"
echo "   permissions:"
echo "     contents: read"
echo "     models: read"

# Check action inputs
echo ""
echo "4. ⚙️  Action Input Check..."
echo "   Verify these inputs in your workflow:"
echo "   ✅ ai_provider: 'github'"
echo "   ✅ github_token: \${{ secrets.GITHUB_TOKEN }}"
echo "   ⚠️  For GitHub Models, use 'github_token' NOT 'openai_api_key'"

# Test AI Summary generation locally
echo ""
echo "5. 🧪 Local AI Summary Test..."
if [ -n "$GITHUB_TOKEN" ]; then
    echo "   Testing AI summary generation..."
    python3 -c "
import sys
import os
sys.path.append('$GITHUB_ACTION_PATH/helpers' if 'GITHUB_ACTION_PATH' in os.environ else './helpers')

try:
    from ai_summary import generate_summary
    
    # Test data
    denied = [{'package': 'test-pkg', 'license': 'GPL-3.0', 'policy': 'deny', 'purl': 'pkg:npm/test@1.0.0'}]
    needs_review = []
    
    print('   Generating AI summary...')
    summary = generate_summary(
        api_key='$GITHUB_TOKEN',
        denied_list=denied,
        needs_review_list=needs_review,
        provider='github',
        model_name='openai/gpt-4o-mini'
    )
    
    if summary and summary.strip():
        print('   ✅ AI Summary generated successfully!')
        print(f'   Summary length: {len(summary)} characters')
    else:
        print('   ❌ AI Summary generation failed - empty result')
        
except ImportError as e:
    print(f'   ⚠️  Cannot import ai_summary module: {e}')
except Exception as e:
    print(f'   ❌ AI Summary test failed: {e}')
    import traceback
    traceback.print_exc()
"
else
    echo "   ⏭️  Skipping local test (no token available)"
fi

echo ""
echo "📋 TROUBLESHOOTING CHECKLIST:"
echo "========================================="
echo "□ GITHUB_TOKEN is available in workflow environment"
echo "□ Workflow has 'models: read' permission"
echo "□ GitHub Models is enabled for otto-ec organization"
echo "□ Using ai_provider: 'github' in action inputs"
echo "□ Using github_token: \${{ secrets.GITHUB_TOKEN }}"
echo "□ NOT using openai_api_key for GitHub Models"
echo ""
echo "💡 COMMON FIXES:"
echo "1. Add 'models: read' to workflow permissions"
echo "2. Contact GitHub admin to enable Models for otto-ec"
echo "3. Verify action is using latest version (@v1 or @main)"
echo ""
echo "🔗 USEFUL LINKS:"
echo "- GitHub Models Documentation: https://docs.github.com/en/github-models"
echo "- Otto-EC Organization Settings: https://github.com/organizations/otto-ec/settings/actions"
