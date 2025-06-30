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
    def test_generate_summary_success(self, mock_openai):
        mock_client = MagicMock()
        mock_choice = MagicMock()
        mock_choice.message.content = "Test summary"
        mock_response = MagicMock()
        mock_response.choices = [mock_choice]
        mock_client.chat.completions.create.return_value = mock_response
        mock_openai.return_value = mock_client

        denied_list = [{'package': 'test-denied', 'license': 'GPL-2.0', 'policy': 'deny'}]
        needs_review_list = [{'package': 'test-review', 'license': 'LGPL-2.1', 'policy': 'needs-review'}]
        
        summary = generate_summary('fake_api_key', denied_list, needs_review_list)
        self.assertEqual(summary, '\n### AI-Assisted Summary\n\nTest summary\n')
        mock_openai.assert_called_once_with(api_key='fake_api_key')
        mock_client.chat.completions.create.assert_called_once()

if __name__ == '__main__':
    unittest.main()
