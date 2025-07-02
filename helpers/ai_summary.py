#!/usr/bin/env python3
# Copyright (c) 2025 Otto GmbH & Co KG
# SPDX-License-Identifier: Apache-2.0

from openai import OpenAI
import logging
import json
import os
import requests

def generate_summary(api_key, denied_list, needs_review_list, provider="openai", azure_endpoint=None, azure_deployment=None, aws_region=None, model_name=None):
    """
    Generates an AI-powered summary of the license audit report using various AI providers.
    
    Args:
        api_key: API key for the selected provider (for GitHub Models, use GitHub token)
        denied_list: List of denied packages
        needs_review_list: List of packages needing review
        provider: AI provider to use ("openai", "azure", "bedrock", "github")
        azure_endpoint: Azure OpenAI endpoint URL (required for azure provider)
        azure_deployment: Azure OpenAI deployment name (required for azure provider)
        aws_region: AWS region for Bedrock (required for bedrock provider)
        model_name: Specific model name to use (optional, provider-specific defaults will be used)
    """
    if not api_key:
        return ""

    # Construct the prompt
    prompt = _build_prompt(denied_list, needs_review_list)
    
    logging.info(f"Generating AI summary using {provider} provider...")
    
    try:
        if provider.lower() == "openai":
            return _generate_openai_summary(api_key, prompt, model_name)
        elif provider.lower() == "azure":
            return _generate_azure_summary(api_key, azure_endpoint, azure_deployment, prompt, model_name)
        elif provider.lower() == "bedrock":
            return _generate_bedrock_summary(api_key, aws_region, prompt, model_name)
        elif provider.lower() == "github":
            return _generate_github_summary(api_key, prompt, model_name)
        else:
            logging.error(f"Unsupported AI provider: {provider}")
            return f"\n### AI-Assisted Summary\n\nError: Unsupported AI provider '{provider}'.\n"
    except Exception as e:
        logging.error(f"Failed to generate AI summary with {provider}: {e}")
        return f"\n### AI-Assisted Summary\n\nError: Could not generate the AI summary using {provider}.\n"


def _build_prompt(denied_list, needs_review_list):
    """Builds the prompt for the AI model."""
    prompt = """You are an expert in software license compliance, tasked with providing a high-level summary of a license audit report for a software project.
Your audience includes developers, project managers, and legal counsel. The summary should be clear, concise, and actionable.

Please structure your summary in Markdown format with the following sections:

### Overall Status
Provide a brief, one-sentence overview of the license compliance status.

### Key Risks
- List the top 3-5 most significant license risks identified in the audit.
- For each risk, analyze the specific license terms and how they might conflict with commercial use, distribution, or proprietary code. Mention specific clauses (e.g., copyleft, patent grants, attribution requirements) and their impact.
- Focus on denied packages and those with ambiguous or restrictive licenses that require review.

### Recommendations
- Provide clear, actionable recommendations for each identified risk.
- For packages that should be replaced, suggest 1-2 specific, license-compliant alternatives. Explain why the alternatives are suitable (e.g., similar functionality, permissive license).
- For packages that need review, specify what needs to be reviewed and why.
- Suggestions may include replacing a package, seeking legal advice, or updating the license policy.

Maintain a professional and neutral tone.

Here is the raw data from the audit:
"""

    if denied_list:
        prompt += "\n**Denied Packages:**\n"
        for item in denied_list:
            prompt += f"- `{item['package']}` (License: `{item['license']}`, Policy: `{item['policy']}`)\n"

    if needs_review_list:
        prompt += "\n**Packages Needing Review:**\n"
        for item in needs_review_list:
            prompt += f"- `{item['package']}` (License: `{item['license']}`, Policy: `{item['policy']}`)\n"

    if not denied_list and not needs_review_list:
        prompt += "\n**Status:** All packages conform to the license policy. No immediate risks identified.\n"

    return prompt


def _generate_openai_summary(api_key, prompt, model_name=None):
    """Generate summary using OpenAI API."""
    client = OpenAI(api_key=api_key)
    model = model_name or "gpt-3.5-turbo"
    
    response = client.chat.completions.create(
        model=model,
        messages=[
            {"role": "system", "content": "You are a license compliance expert."},
            {"role": "user", "content": prompt}
        ]
    )
    summary = response.choices[0].message.content
    return f"\n### AI-Assisted Summary\n\n{summary}\n"


def _generate_azure_summary(api_key, azure_endpoint, azure_deployment, prompt, model_name=None):
    """Generate summary using Azure OpenAI API."""
    if not azure_endpoint or not azure_deployment:
        raise ValueError("Azure OpenAI requires both endpoint and deployment parameters")
    
    try:
        # Try the newer Azure OpenAI client initialization
        from openai import AzureOpenAI
        client = AzureOpenAI(
            api_key=api_key,
            api_version="2024-12-01-preview",  # Updated for o4-mini support
            azure_endpoint=azure_endpoint
        )
    except ImportError:
        # Fallback to older method if AzureOpenAI is not available
        client = OpenAI(
            api_key=api_key,
            base_url=f"{azure_endpoint.rstrip('/')}/openai/deployments/{azure_deployment}",
            default_headers={"api-key": api_key}
        )
    
    response = client.chat.completions.create(
        model=azure_deployment,  # In Azure, this is the deployment name
        messages=[
            {"role": "system", "content": "You are a license compliance expert."},
            {"role": "user", "content": prompt}
        ]
    )
    summary = response.choices[0].message.content
    return f"\n### AI-Assisted Summary (Azure OpenAI)\n\n{summary}\n"


def _generate_bedrock_summary(api_key, aws_region, prompt, model_name=None):
    """Generate summary using AWS Bedrock API."""
    try:
        import boto3
    except ImportError:
        raise ImportError("boto3 is required for AWS Bedrock support. Install with: pip install boto3")
    
    if not aws_region:
        raise ValueError("AWS Bedrock requires region parameter")
    
    # Use the api_key as AWS access key, or use environment variables/IAM roles
    if api_key and api_key != "default":
        # If api_key is provided and not "default", use it as access key
        # Note: This requires the secret key to be provided via environment variable AWS_SECRET_ACCESS_KEY
        session = boto3.Session(
            aws_access_key_id=api_key,
            region_name=aws_region
        )
    else:
        # Use default credentials (environment variables, IAM roles, etc.)
        session = boto3.Session(region_name=aws_region)
    
    bedrock = session.client('bedrock-runtime')
    
    # Default to Claude 3.5 Sonnet if no model specified
    model_id = model_name or "anthropic.claude-3-5-sonnet-20241022-v2:0"
    
    # Prepare the request body based on the model type
    if "anthropic.claude" in model_id:
        body = {
            "anthropic_version": "bedrock-2023-05-31",
            "max_tokens": 2000,
            "messages": [
                {
                    "role": "user",
                    "content": f"You are a license compliance expert.\n\n{prompt}"
                }
            ]
        }
    elif "amazon.titan" in model_id:
        body = {
            "inputText": f"You are a license compliance expert.\n\n{prompt}",
            "textGenerationConfig": {
                "maxTokenCount": 2000,
                "temperature": 0.7
            }
        }
    else:
        # Generic format that might work for other models
        body = {
            "prompt": f"You are a license compliance expert.\n\n{prompt}",
            "max_tokens": 2000,
            "temperature": 0.7
        }
    
    response = bedrock.invoke_model(
        modelId=model_id,
        body=json.dumps(body),
        contentType="application/json"
    )
    
    response_body = json.loads(response['body'].read().decode('utf-8'))
    
    # Extract the generated text based on model type
    if "anthropic.claude" in model_id:
        summary = response_body['content'][0]['text']
    elif "amazon.titan" in model_id:
        summary = response_body['results'][0]['outputText']
    else:
        # Try to find text in common response fields
        summary = response_body.get('text', response_body.get('generated_text', str(response_body)))
    
    return f"\n### AI-Assisted Summary (AWS Bedrock)\n\n{summary}\n"


def _generate_github_summary(github_token, prompt, model_name=None):
    """Generate summary using GitHub Models API."""
    if not github_token:
        raise ValueError("GitHub Models requires a GitHub token")
    
    # Default to GPT-4o mini if no model specified (best price/performance)
    model = model_name or "openai/gpt-4o-mini"
    
    url = "https://models.github.ai/inference/chat/completions"
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {github_token}"
    }
    
    data = {
        "messages": [
            {"role": "system", "content": "You are a license compliance expert."},
            {"role": "user", "content": prompt}
        ],
        "model": model
    }
    
    response = requests.post(url, headers=headers, json=data, timeout=60)
    response.raise_for_status()
    
    response_data = response.json()
    summary = response_data['choices'][0]['message']['content']
    return f"\n### AI-Assisted Summary (GitHub Models)\n\n{summary}\n"
