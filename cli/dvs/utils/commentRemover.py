import re

def _preserve_space_repl(m: re.Match) -> str:
    return " " * (m.end() - m.start())

def remove_js_comments_preserve(text: str) -> str:
    """
    Remove JavaScript/TypeScript style comments (// line and /* block */)
    but replace them with spaces so character indices remain valid.
    """
    # Remove block comments first (/* ... */)
    text = re.sub(r'/\*[\s\S]*?\*/', _preserve_space_repl, text)
    # Remove single-line comments (// ...)
    text = re.sub(r'//.*?$', _preserve_space_repl, text, flags=re.MULTILINE)
    return text

def remove_html_comments_preserve(text: str) -> str:
    """
    Remove HTML comments <!-- ... -->, preserving spacing.
    """
    return re.sub(r'<!--[\s\S]*?-->', _preserve_space_repl, text)

