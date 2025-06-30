#!/usr/bin/env python3
# Copyright (c) 2025 Otto GmbH & Co KG
# SPDX-License-Identifier: Apache-2.0

import unittest
from unittest.mock import patch, MagicMock
from helpers.ai_summary import generate_summary

class TestAISummary(unittest.TestCase):

    def test_generate_summary_no_api_key(self):
        summary = generate_summary(None, [], [])
        self.assertEqual(summary, "")

    @patch('helpers.ai_summary.OpenAI')
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

    @patch('helpers.ai_summary.OpenAI')
    def test_generate_summary_azure_success(self, mock_openai):
        mock_client = MagicMock()
        mock_choice = MagicMock()
        mock_choice.message.content = "Test Azure summary"
        mock_response = MagicMock()
        mock_response.choices = [mock_choice]
        mock_client.chat.completions.create.return_value = mock_response
        mock_openai.return_value = mock_client

        denied_list = [{'package': 'test-denied', 'license': 'GPL-2.0', 'policy': 'deny'}]
        needs_review_list = []
        
        summary = generate_summary('fake_api_key', denied_list, needs_review_list, 
                                 provider='azure', 
                                 azure_endpoint='https://test.openai.azure.com/',
                                 azure_deployment='test-deployment')
        self.assertEqual(summary, '\n### AI-Assisted Summary (Azure OpenAI)\n\nTest Azure summary\n')
        mock_openai.assert_called_once_with(
            api_key='fake_api_key',
            api_version='2024-02-01',
            azure_endpoint='https://test.openai.azure.com/'
        )

    def test_generate_summary_bedrock_missing_boto3(self):
        """Test that bedrock provider fails gracefully when boto3 is not available"""
        denied_list = []
        needs_review_list = [{'package': 'test-review', 'license': 'LGPL-2.1', 'policy': 'needs-review'}]
        
        # Test without mocking - this will trigger the ImportError for boto3
        summary = generate_summary('fake_access_key', denied_list, needs_review_list,
                                 provider='bedrock',
                                 aws_region='us-east-1')
        self.assertIn("Error: Could not generate the AI summary using bedrock", summary)

    def test_generate_summary_unsupported_provider(self):
        summary = generate_summary('fake_api_key', [], [], provider='unsupported')
        self.assertIn("Error: Unsupported AI provider 'unsupported'", summary)

if __name__ == '__main__':
    unittest.main()
