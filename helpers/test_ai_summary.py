#!/usr/bin/env python3
# Copyright (c) 2025 Otto GmbH & Co KG
# SPDX-License-Identifier: Apache-2.0

import unittest
import os
import sys
import logging
from unittest.mock import patch, MagicMock
from ai_summary import generate_summary

# Configure logging for debugging
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

class TestAISummary(unittest.TestCase):

    def test_generate_summary_no_api_key(self):
        summary = generate_summary(None, [], [])
        self.assertEqual(summary, "")

    @patch('ai_summary.OpenAI')
    def test_generate_summary_openai_success(self, mock_openai):
        mock_client = MagicMock()
        mock_choice = MagicMock()
        mock_choice.message.content = "Test summary"
        mock_response = MagicMock()
        mock_response.choices = [mock_choice]
        mock_client.chat.completions.create.return_value = mock_response
        mock_openai.return_value = mock_client

        denied_list = [{'package': 'test-denied', 'license': 'GPL-2.0', 'policy': 'deny'}]
        needs_review_list = [{'package': 'test-review', 'license': 'LGPL-2.1', 'policy': 'needs-review'}]
        
        summary = generate_summary('fake_api_key', denied_list, needs_review_list, provider='openai')
        self.assertEqual(summary, '\n### AI-Assisted Summary\n\nTest summary\n')
        mock_openai.assert_called_once_with(api_key='fake_api_key')
        mock_client.chat.completions.create.assert_called_once()

    @patch('ai_summary.requests.post')
    def test_generate_summary_github_success(self, mock_post):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            'choices': [{'message': {'content': 'Test GitHub Models summary'}}]
        }
        mock_post.return_value = mock_response

        denied_list = [{'package': 'test-denied', 'license': 'GPL-2.0', 'policy': 'deny'}]
        needs_review_list = []
        
        summary = generate_summary('fake_github_token', denied_list, needs_review_list, 
                                 provider='github')
        self.assertEqual(summary, '\n### AI-Assisted Summary (GitHub Models)\n\nTest GitHub Models summary\n')
        mock_post.assert_called_once()

    @patch('ai_summary.requests.post')
    def test_generate_summary_github_401_error(self, mock_post):
        mock_response = MagicMock()
        mock_response.status_code = 401
        mock_response.text = "Unauthorized"
        mock_post.return_value = mock_response

        denied_list = [{'package': 'test-denied', 'license': 'GPL-2.0', 'policy': 'deny'}]
        needs_review_list = []
        
        summary = generate_summary('invalid_github_token', denied_list, needs_review_list, 
                                 provider='github')
        self.assertIn("Error: Could not generate the AI summary using github", summary)

    def test_generate_summary_github_no_token(self):
        """Test that github provider fails gracefully when no token is provided"""
        denied_list = []
        needs_review_list = [{'package': 'test-review', 'license': 'LGPL-2.1', 'policy': 'needs-review'}]
        
        summary = generate_summary(None, denied_list, needs_review_list, provider='github')
        self.assertEqual(summary, "")

    def test_generate_summary_unsupported_provider(self):
        summary = generate_summary('fake_api_key', [], [], provider='unsupported')
        self.assertIn("Error: Unsupported AI provider 'unsupported'", summary)

def test_github_models_integration():
    """Interactive test for GitHub Models integration."""
    print("\n🧪 Testing GitHub Models AI Summary Integration")
    print("=" * 50)
    
    # Get GitHub token
    github_token = os.getenv('GITHUB_TOKEN')
    if not github_token:
        print("❌ GITHUB_TOKEN environment variable not set")
        print("   Please set your GitHub token with 'models: read' permission")
        return False
    
    print(f"✅ GitHub token found (length: {len(github_token)})")
    
    # Test data
    denied_list = [
        {
            'package': 'test-denied-package',
            'license': 'GPL-3.0',
            'policy': 'deny',
            'purl': 'pkg:npm/test-denied@1.0.0'
        }
    ]
    
    needs_review_list = [
        {
            'package': 'test-review-package',
            'license': 'LGPL-2.1',
            'policy': 'needs-review',
            'purl': 'pkg:npm/test-review@2.0.0'
        }
    ]
    
    print("\n🎯 Test Data:")
    print(f"   Denied packages: {len(denied_list)}")
    print(f"   Review packages: {len(needs_review_list)}")
    
    # Test GitHub Models
    print("\n🚀 Testing GitHub Models...")
    try:
        summary = generate_summary(
            api_key=github_token,
            denied_list=denied_list,
            needs_review_list=needs_review_list,
            provider="github",
            model_name="openai/gpt-4o-mini"
        )
        
        if summary and summary.strip():
            print("✅ GitHub Models AI Summary generated successfully!")
            print("\n📄 Generated Summary:")
            print("-" * 40)
            print(summary)
            print("-" * 40)
            return True
        else:
            print("❌ GitHub Models returned empty summary")
            return False
            
    except Exception as e:
        print(f"❌ GitHub Models AI Summary failed: {e}")
        logging.exception("Full error details:")
        return False

if __name__ == '__main__':
    if len(sys.argv) > 1 and sys.argv[1] == 'integration':
        # Run integration test
        print("🧪 GitHub Models AI Summary Integration Test")
        success = test_github_models_integration()
        sys.exit(0 if success else 1)
    else:
        # Run unit tests
        unittest.main()
