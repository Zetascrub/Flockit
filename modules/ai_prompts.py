import re
import textwrap

from utils.common import print_status


def sanitize_plugin_input(port_data):
    """Strip down to safe, non-sensitive data before it goes into a prompt."""
    return {
        "port": port_data.get("port"),
        "service": port_data.get("service", "").replace("-", "_"),
        "version": port_data.get("version", ""),
        "banner": port_data.get("banner", ""),
    }


def format_ai_summary(summary, port_info=None, format_type="markdown"):
    if not summary or not isinstance(summary, str):
        return "⚠️ No AI summary available."

    port_label = f"{port_info.get('port')}/tcp ({port_info.get('service')})" if port_info else ""

    summary = summary.strip().replace("\r", "")

    # Strip markdown elements
    summary = re.sub(r"\[([^\]]+)\]\(([^)]+)\)", r"\1 (\2)", summary)
    summary = summary.replace("**", "").replace("`", "")
    summary = re.sub(r"^```[a-z]*", "", summary, flags=re.MULTILINE)
    summary = re.sub(r"^(bash|sh|shell|powershell|python)\s*$", "", summary, flags=re.IGNORECASE | re.MULTILINE)
    summary = re.sub(r"^</?details.*?>", "", summary, flags=re.IGNORECASE)
    summary = re.sub(r"</?summary.*?>", "", summary, flags=re.IGNORECASE)
    summary = re.sub(r"\n{3,}", "\n\n", summary).strip()

    width = 70  # For safe rendering in PDF with proportional fonts

    if format_type == "markdown":
        return f"""<details>
<summary><strong>AI Recommendations for {port_label}</strong></summary>

```markdown
{summary}
```

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

            paragraph = re.sub(r"[*_`#]", "", paragraph)

            if paragraph.lower() in ("bash", "sh", "shell", "powershell"):
                continue
            elif paragraph.startswith("sudo ") or paragraph.startswith("nmap "):
                wrapped = textwrap.wrap(paragraph, width=width, break_long_words=False)
                wrapped_lines.extend(wrapped)
            elif re.match(r"^\d+\.", paragraph) or re.match(r"^[+*-] ", paragraph):
                wrapped = textwrap.wrap(paragraph, width=width, break_long_words=False, subsequent_indent="   ")
                wrapped_lines.extend(wrapped)
            elif paragraph.upper() == paragraph and len(paragraph.split()) < 6:
                wrapped_lines.append("")
                wrapped_lines.append(paragraph.upper())
                wrapped_lines.append("")
            else:
                wrapped = textwrap.wrap(paragraph, width=width, break_long_words=False)
                wrapped_lines.extend(wrapped)

        return "\n".join(wrapped_lines)

    return summary


def build_plugin_prompt(port_data):
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
    return system_prompt, user_prompt


def generate_plugin_code(port_data, ai_client) -> str:
    """Single canonical plugin-generation entry point. Both Ollama and OpenAI
    go through ai_client (utils.ai_client.AIClient), consolidating what used
    to be two divergent implementations split across magpie.py and kea.py."""
    system_prompt, user_prompt = build_plugin_prompt(port_data)
    print_status(f"[AI] Using {ai_client.config.provider} for plugin generation", "info")
    raw_response = ai_client.chat(system_prompt, user_prompt)
    if not raw_response:
        return ""
    return extract_python_code(raw_response)


def extract_python_code(ai_response: str) -> str:
    """Extracts the first Python code block from a markdown-formatted AI response.
    If no code block is found, returns the original string."""
    code_blocks = re.findall(r"```(?:python)?\n(.*?)```", ai_response, re.DOTALL)
    return code_blocks[0].strip() if code_blocks else ai_response.strip()
