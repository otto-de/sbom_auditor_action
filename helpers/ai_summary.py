import openai
import logging

def generate_summary(api_key, denied_list, needs_review_list):
    """
    Generates an AI-powered summary of the license audit report.
    """
    if not api_key:
        return ""

    openai.api_key = api_key

    # Construct the prompt
    prompt = """
You are an expert in software license compliance, tasked with providing a high-level summary of a license audit report for a software project.
Your audience includes developers, project managers, and legal counsel. The summary should be clear, concise, and actionable.

Please structure your summary in Markdown format with the following sections:

### Overall Status
Provide a brief, one-sentence overview of the license compliance status.

### Key Risks
- List the top 3-5 most significant license risks identified in the audit.
- For each risk, briefly explain the potential implications (e.g., legal, reputational).
- Focus on denied packages and those with ambiguous or restrictive licenses that require review.

### Recommendations
- Provide clear, actionable recommendations for each identified risk.
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

    logging.info("Generating AI summary...")
    try:
        response = openai.ChatCompletion.create(
            model="gpt-3.5-turbo",
            messages=[
                {"role": "system", "content": "You are a license compliance expert."},
                {"role": "user", "content": prompt}
            ]
        )
        summary = response.choices[0].message.content
        return f"\n### AI-Assisted Summary\n\n{summary}\n"
    except Exception as e:
        logging.error(f"Failed to generate AI summary: {e}")
        return "\n### AI-Assisted Summary\n\nError: Could not generate the AI summary.\n"
