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
    prompt = "You are a helpful assistant specializing in software license compliance.\n"
    prompt += "Based on the following license audit results, provide a concise executive summary.\n"
    prompt += "Highlight the most critical issues, identify potential risks, and suggest actionable next steps.\n\n"
    prompt += "--- Audit Results ---\n"

    if denied_list:
        prompt += "Denied Packages:\n"
        for item in denied_list:
            prompt += f"- {item['package']} (License: {item['license']}, Reason: {item['policy']})\n"
    
    if needs_review_list:
        prompt += "\nPackages Needing Review:\n"
        for item in needs_review_list:
            prompt += f"- {item['package']} (License: {item['license']}, Reason: {item['policy']})\n"

    if not denied_list and not needs_review_list:
        prompt += "All packages conform to the license policy. No issues found.\n"

    prompt += "\n--- End of Audit Results ---\n\n"
    prompt += "Please provide the summary in Markdown format."

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
