import ast
from pathlib import Path
import re

def load_any_file(input_file: str):
    """
    Load any file:
    - Try JSON first
    - Then Python-style dict/list
    - Otherwise treat as raw string
    """
    content = Path(input_file).read_text(encoding='utf-8').strip()

    # Remove all double quotes
    content = content.replace('"', '')

    # Try JSON first
    try:
        import json
        return json.loads(content)
    except:
        pass

    # Try Python literal
    try:
        return ast.literal_eval(content)
    except:
        pass

    # Fallback: raw string
    return [{"raw": re.sub(r'\s+', ' ', content)}]

def write_custom_format(data, f, indent=0):
    """
    Write data in your custom format:
    - No quotes, no {} or []
    - Keep colons and commas
    - Indent nested structures
    """
    tab = '    ' * indent  # 4 spaces per indent for readability
    if isinstance(data, dict):
        items = list(data.items())
        for i, (k, v) in enumerate(items):
            is_last = (i == len(items) - 1)
            if isinstance(v, dict):
                f.write(f"{tab}{k}: \n")
                write_custom_format(v, f, indent + 1)
            elif isinstance(v, list):
                f.write(f"{tab}{k}: \n")
                for j, item in enumerate(v):
                    write_custom_format(item, f, indent + 1)
            else:
                f.write(f"{tab}{k}: {v}")
                if not is_last:
                    f.write(",")
                f.write("\n")
    elif isinstance(data, list):
        for item in data:
            write_custom_format(item, f, indent)
            f.write("\n")
    else:
        f.write(f"{tab}{data}\n")

def clean_file_custom(input_file: str, output_file: str):
    data = load_any_file(input_file)
    with open(output_file, 'w', encoding='utf-8') as f:
        write_custom_format(data, f)
    print(f"Cleaned output saved to: {output_file}")


if __name__ == "__main__":
    input_file = r"C:\Users\User\Downloads\UCKG\qa-engine\text2cypher\Data Generation\Dataset Generation Process\technical dataset\category check\dummy.json"   # can be JSON, txt, or invalid JSON
    output_file = r"C:\Users\User\Downloads\UCKG\qa-engine\text2cypher\Data Generation\Dataset Generation Process\technical dataset\category check\cleaned_dummy.json"

    clean_file_custom(input_file, output_file)
