import json
import re
import shutil
from openai import OpenAI
import textwrap
from utils.common import print_status, CUSTOM_SETTINGS
import os


def sanitize_plugin_input(port_data):
    """Strip down to safe, non-sensitive data."""
    return {
        "port": port_data.get("port"),
        "service": port_data.get("service", "").replace("-", "_"),
        "version": port_data.get("version", ""),
        "banner": port_data.get("banner", "")
    }

def format_ai_summary(summary, port_info=None, format_type="markdown"):
    import textwrap
    import re

    if not summary or not isinstance(summary, str):
        return "⚠️ No AI summary available."

    port_label = f"{port_info.get('port')}/tcp ({port_info.get('service')})" if port_info else ""

    summary = summary.strip().replace("\r", "")

    # Strip markdown elements
    summary = re.sub(r"\[([^\]]+)\]\(([^)]+)\)", r"\1 (\2)", summary)
    summary = summary.replace("**", "").replace("`", "")
    summary = re.sub(r"^```[a-z]*", "", summary, flags=re.MULTILINE)
    summary = re.sub(r"^</?details.*?>", "", summary, flags=re.IGNORECASE)
    summary = re.sub(r"</?summary.*?>", "", summary, flags=re.IGNORECASE)

    width = 70  # For safe rendering in PDF with proportional fonts

    if format_type == "markdown":
        return f"""<details>
    <summary><strong>AI Recommendations for {port_label}</strong></summary>

    ```markdown
    {summary}

    </details>"""

    elif format_type == "plain":
        return f"AI Recommendations for {port_label}:\n\n{summary}"

    elif format_type == "pdf":
        width = 72
        wrapped_lines = [f"AI Recommendations for {port_label}"]

        for paragraph in summary.splitlines():
            paragraph = paragraph.strip()
            if not paragraph:
                wrapped_lines.append("")
                continue

            # Strip markdown symbols
            paragraph = re.sub(r"[*_`#]", "", paragraph)

            # Shell command block hint
            if paragraph.lower() in ("bash", "sh", "shell", "powershell"):
                continue  # Drop this line
            elif paragraph.startswith("sudo ") or paragraph.startswith("nmap "):
                wrapped = textwrap.wrap(paragraph, width=width, break_long_words=False)
                wrapped_lines.extend(wrapped)
            elif re.match(r"^\d+\.", paragraph) or re.match(r"^[+*-] ", paragraph):
                # Numbered or bulleted list
                wrapped = textwrap.wrap(paragraph, width=width, break_long_words=False, subsequent_indent="   ")
                wrapped_lines.extend(wrapped)
            elif paragraph.upper() == paragraph and len(paragraph.split()) < 6:
                # Treat short all-caps lines as headings
                wrapped_lines.append("")
                wrapped_lines.append(paragraph.upper())
                wrapped_lines.append("")
            else:
                # Normal text
                wrapped = textwrap.wrap(paragraph, width=width, break_long_words=False)
                wrapped_lines.extend(wrapped)

        return "\n".join(wrapped_lines)

    return summary








def generate_plugin_code(port_data, provider="ollama"):
    safe_data = sanitize_plugin_input(port_data)

    system_prompt = (
        "You are a cybersecurity plugin generator. Write a Python class that inherits from ScanPlugin. "
        "The plugin should detect or extract information from a service on a specific port. "
        "Do not include `__init__`. The output must be usable as Python code. "
        "Avoid direct imports like 'from ScanPlugin import ScanPlugin'. Assume ScanPlugin is already available in the runtime environment."
    )

    user_prompt = f"""
    Create a plugin for a scanner tool.
    - Port: {safe_data['port']}
    - Service: {safe_data['service']}
    - Version: {safe_data['version']}
    - Banner: {safe_data['banner']}

    Requirements:
    - Inherit from `ScanPlugin`
    - Class name: Capitalized service_port + "Scan"
    - Define `should_run(self, host, port, port_data)` and `run(self, host, port, port_data)` methods
    - Return dict with banner or status in `run()`
    - Avoid problematic imports like `from ScanPlugin import ScanPlugin` or `import ScanPlugin`
    - Do NOT include `__init__`
    - Avoid referencing undefined names or unused variables
    - Ensure imports are not duplicated
    """

    if provider == "openai":
        plugin_code = _use_openai(system_prompt, user_prompt)
    else:
        plugin_code = _use_ollama(system_prompt, user_prompt)

    if plugin_code:
        plugin_code = _sanitize_generated_code(plugin_code)

    return plugin_code

def _sanitize_generated_code(code):
    """Remove direct ScanPlugin imports and duplicate import lines."""
    lines = code.splitlines()
    seen = set()
    sanitized = []
    for line in lines:
        if re.search(r"from\\s+ScanPlugin\\s+import\\s+ScanPlugin", line):
            continue
        if re.search(r"import\\s+ScanPlugin", line):
            continue
        if line in seen:
            continue
        seen.add(line)
        sanitized.append(line)
    return "\n".join(sanitized)

def _use_ollama(system_prompt, user_prompt):
    from utils.common import ollama_chat
    print_status("[🧠] Using Ollama for plugin generation", "info")
    return ollama_chat(system_prompt, user_prompt)

def _use_openai(system_prompt, user_prompt):
        
    api_key = CUSTOM_SETTINGS.get("openai_api_key")
    client = OpenAI(api_key=api_key)
    if not api_key:
        print_status("OpenAI API key not found in settings.", "error")
        return ""
    print_status("[🧠] Using OpenAI for plugin generation", "info")
    try:
        response = client.chat.completions.create(model=CUSTOM_SETTINGS.get("openai_model", "gpt-4"),
        messages=[
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt}
        ],
        temperature=0.4)
        # Access response using attributes instead of dictionary keys
        return response.choices[0].message.content
    except Exception as e:
        print_status(f"[!] OpenAI error: {e}", "error")
        return ""


