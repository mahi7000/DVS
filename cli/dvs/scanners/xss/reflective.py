
import re
from typing import List, Pattern
from ...utils.types import SourceFile, Vulnerability, SinkDefinition, Severity
from ...utils.commentRemover import remove_js_comments_preserve, remove_html_comments_preserve

# --- Confidence calculator (provided) ---
def calculate_confidence(snippet: str) -> float:
    """Calculate confidence based on snippet content"""
    confidence = 0.7  # Base confidence

    # Increase confidence for certain patterns
    low = snippet.lower()
    if any(keyword in low for keyword in ['innerhtml', 'eval', 'document.write']):
        confidence += 0.2

    if any(keyword in low for keyword in ['userinput', 'location.hash', 'req.query']):
        confidence += 0.1

    return min(confidence, 1.0)


# --- Utility: escape for UI/reporting (prevents accidental render/execution) ---
def escape_for_display(text: str) -> str:
    return (text.replace('&', '&amp;')
                .replace('<', '&lt;')
                .replace('>', '&gt;')
                .replace('"', '&quot;')
                .replace("'", '&#39;'))


# --- Detector ---
def detect_reflective_xss(source_files: List[SourceFile]) -> List[Vulnerability]:
    vulns: List[Vulnerability] = []

    # Sources (server-side) — compile them for performance
    server_source_patterns: List[Pattern] = [
        re.compile(r"req\.query"),
        re.compile(r"req\.body"),
        re.compile(r"req\.params"),
        re.compile(r"req\.headers"),
        re.compile(r"req\.cookies"),
    ]

    # Sinks (server) - definition objects (patterns are strings)
    server_sinks = [
        SinkDefinition(
            pattern=r"\w+(?:\.[a-zA-Z_]\w*\s*\([\s\S]*?\))*\.(send|write|end|jsonp)\s*\([\s\S]*?\)",
            description="Response HTML send/write/end/jsonp",
            context="html"
        ),
        SinkDefinition(
            pattern=r"\w+(?:\.[a-zA-Z_]\w*\s*\([\s\S]*?\))*\.json\s*\([\s\S]*?\)",
            description="Response JSON",
            context="json"
        ),
        SinkDefinition(
            pattern=r"\w+\.render\s*\(\s*[^,]+,\s*[\s\S]*?\)",
            description="render(view, data)",
            context="html"
        ),
        SinkDefinition(
            pattern=r"\w+\.redirect\s*\([\s\S]*?\)",
            description="redirect(url)",
            context="url"
        ),
        SinkDefinition(
            pattern=r"\w+\.(set|setHeader)\s*\(\s*['\"]content-type['\"]\s*,\s*['\"]text/html\b[^'\"]*['\"]\s*\)",
            description="set Content-Type: text/html",
            context="html"
        ),
        SinkDefinition(
            pattern=r"\w+\.type\s*\(\s*['\"]html?['\"]\s*\)[\s\S]*?\.(send|end)\s*\([\s\S]*?\)",
            description=".type('html').send/end(...)",
            context="html"
        ),
        SinkDefinition(
            pattern=r"\w+\.(set|setHeader)\s*\(\s*['\"]content-type['\"]\s*,\s*['\"]text/css\b[^'\"]*['\"]\s*\)",
            description="set Content-Type: text/css",
            context="css"
        ),
        SinkDefinition(
            pattern=r"\w+\.type\s*\(\s*['\"]css['\"]\s*\)[\s\S]*?\.(send|end|write)\s*\([\s\S]*?\)",
            description=".type('css').send/end/write(...)",
            context="css"
        ),
        SinkDefinition(
            pattern=r"<style[^>]*>[\s\S]*?(?:\+|\$\{)[\s\S]*?</style>",
            description="Inline <style> with dynamic interpolation",
            context="css"
        ),
        SinkDefinition(
            pattern=r"style\s*=\s*[\"\'`][\s\S]*?(?:\+|\$\{)[\s\S]*?[\"\'`]",
            description="style= attribute with dynamic interpolation",
            context="css"
        ),
        SinkDefinition(
            pattern=r"\w+(?:\.[a-zA-Z_]\w*\s*\([\s\S]*?\))*\.(send|write|end)\s*\([\s\S]*?(?:^|[,{;]\s*)[a-zA-Z-]{2,}\s*:\s*[\s\S]*?(?:\+|\$\{)[\s\S]*?[;}][\s\S]*?\)",
            description="Sending CSS-like properties with dynamic interpolation",
            context="css"
        ),
    ]

    # Precompile sink regexes (store compiled Pattern on the sink object)
    for sink in server_sinks:
        try:
            sink.compiled_re = re.compile(sink.pattern, re.MULTILINE)
        except re.error:
            # If compilation fails, ensure attribute exists but set to None so we skip it later
            sink.compiled_re = None

    # Sanitizers (precompiled)
    html_sanitizers = [
        re.compile(r"escapeHtml\s*\("),
        re.compile(r"(?:^|[\W_])(?:escape|_\.escape|validator\.escape)\s*\("),
        re.compile(r"DOMPurify\.sanitize\s*\("),
        re.compile(r"\.textContent\s*="),
        re.compile(r"createTextNode\s*\("),
    ]

    url_sanitizers = [
        re.compile(r"encodeURIComponent\s*\("),
        re.compile(r"encodeURI\s*\("),
    ]

    # Convert JS-style literal attempts into python-safe regexes (anchors or tokens)
    css_sanitizers = [
        re.compile(r"cssesc\s*\("),
        re.compile(r"sanitizeCss\s*\("),
        re.compile(r"safeStyle\s*\("),
        re.compile(r"styleSafe\s*\("),
        re.compile(r"isSafeCss\s*\("),
        # whitelist-looking regexes: anchor-style checks (these are patterns to search for in code,
        # they likely won't match literal JS regex in code, but left here as best-effort indicators)
        re.compile(r"\^#[0-9a-fA-F]{3,6}\$"),
        re.compile(r"\^[a-zA-Z0-9# ,.%()\-]+\$"),
    ]

    css_dangerous = [
        re.compile(r"expression\s*\(", re.IGNORECASE),
        re.compile(r"behavior\s*:\s*url\s*\(", re.IGNORECASE),
        re.compile(r"url\s*\(\s*['\"]?\s*javascript\s*:", re.IGNORECASE),
    ]

    # Template checks (precompiled)
    template_unescaped = [
        {
            "pattern": re.compile(r"<\?=\s*([^?]+)\s*\?>"),
            "recommendation": "Use <?= htmlspecialchars(...) ?> or escape output."
        },
        {
            "pattern": re.compile(r"\{\{\{\s*([^}]+)\s*\}\}\}"),
            "recommendation": "Use {{ var }} (escaped) instead of triple braces in Handlebars."
        },
        {
            "pattern": re.compile(r"<%-\s*([^%]+)\s*%>"),
            "recommendation": "Use <%= %> (escaped) instead of <%- %> in EJS."
        },
        {
            "pattern": re.compile(r"!=\s*\w+"),
            "recommendation": "Use #{var} (escaped) instead of != var in Pug."
        },
        {
            "pattern": re.compile(r"style\s*=\s*[\"\'`][\s\S]*?(?:\+|\$\{)[\s\S]*?[\"\'`]"),
            "recommendation": "Avoid dynamic style attributes or sanitize CSS tokens."
        },
    ]

    # --- helpers ---
    def line_from_index(text: str, idx: int) -> int:
        return text.count('\n', 0, idx) + 1

    def slice_has_source(slice_text: str, source_patterns: List[Pattern]) -> bool:
        return any(p.search(slice_text) for p in source_patterns)

    def slice_has_any(slice_text: str, patterns: List[Pattern]) -> bool:
        return any(p.search(slice_text) for p in patterns)

    def is_sanitized_for_context(slice_text: str, context: str) -> bool:
        if context == "url":
            return slice_has_any(slice_text, url_sanitizers)
        if context == "html":
            return slice_has_any(slice_text, html_sanitizers)
        if context == "css":
            return slice_has_any(slice_text, css_sanitizers)
        return False

    # --- main loop ---
    for file in source_files:
        content = file.content or ""
        # Create a scan-safe version of the content that has comments removed
        # but preserves the original character positions with spaces -> line numbers and indices stay correct.
        # For server code we remove JS-style comments; for templates we remove HTML comments.
        if file.is_server_code:
            content_for_scan = remove_js_comments_preserve(content)
        else:
            # For non-server code we at least remove HTML comments (templates or HTML files)
            content_for_scan = remove_html_comments_preserve(content)

        # -----------------
        # Template scanning (use content_for_scan so template comments are ignored)
        # -----------------
        if file.is_template:
            for template_check in template_unescaped:
                for match in template_check["pattern"].finditer(content_for_scan):
                    idx = match.start()
                    # get snippet from original content for context display (safe because indices preserved)
                    snippet_orig = content[max(0, idx - 50): idx + 50]
                    confidence = calculate_confidence(snippet_orig)
                    vulns.append(Vulnerability(
                        type="Reflective XSS (Template/Unescaped)",
                        file=file.path,
                        line=line_from_index(content, idx),
                        pattern=escape_for_display(match.group()),
                        recommendation=escape_for_display(template_check["recommendation"]),
                        severity=Severity.HIGH,
                        confidence=confidence,
                        snippet=escape_for_display(snippet_orig),
                        sanitized=False
                    ))

        # -----------------
        # Server-side sink scanning (use content_for_scan -> comments are ignored)
        # -----------------
        if file.is_server_code:
            for sink in server_sinks:
                if not getattr(sink, "compiled_re", None):
                    continue

                for match in sink.compiled_re.finditer(content_for_scan):
                    idx = match.start()
                    slice_start = max(0, idx - 300)
                    slice_end = min(len(content_for_scan), idx + len(match.group()) + 300)
                    slice_text = content_for_scan[slice_start:slice_end]

                    has_source = slice_has_source(slice_text, server_source_patterns)
                    sanitized = is_sanitized_for_context(slice_text, sink.context)
                    css_danger = sink.context == "css" and slice_has_any(slice_text, css_dangerous)

                    if has_source and (not sanitized or css_danger):
                        recommendation = ""
                        vulnerability_type = ""
                        severity = Severity.HIGH

                        if sink.context == "url":
                            recommendation = "Validate redirect/URL targets (allow-list) and encode parameters with encodeURIComponent()."
                            vulnerability_type = "Open Redirect / URL Injection"
                            severity = Severity.MEDIUM
                        elif sink.context == "css":
                            recommendation = ("Never inject raw user input into CSS. Restrict to a safe allow-list "
                                              "(e.g., /^#[0-9a-f]{3,6}$/i for colors), or sanitize tokens (cssesc). "
                                              "Disallow url(javascript:), expression(), and external URLs.")
                            vulnerability_type = "Reflective CSS Injection"
                            severity = Severity.CRITICAL if css_danger else Severity.HIGH
                        elif sink.context == "json":
                            recommendation = ("Ensure response is application/json and not embedded in HTML. "
                                              "Avoid reflecting untrusted JSON inside <script> without escaping.")
                            vulnerability_type = "Reflected JSON (check embedding)"
                            severity = Severity.MEDIUM
                        else:
                            recommendation = ("Escape/encode untrusted data before sending HTML "
                                              "(e.g., escapeHtml/validator.escape) or ensure the template auto-escapes.")
                            vulnerability_type = "Reflective XSS (Server)"
                            severity = Severity.HIGH

                        # Use the original content to get a nicer snippet (indices preserved)
                        snippet_orig = content[max(0, idx - 100): idx + 100]
                        # Calculate confidence from snippet and reduce it if we detected a sanitizer nearby
                        confidence = calculate_confidence(snippet_orig)
                        if sanitized:
                            # presence of sanitizer reduces certainty that this is exploitable
                            confidence = max(0.0, confidence * 0.75)

                        vulns.append(Vulnerability(
                            type=vulnerability_type,
                            file=file.path,
                            line=line_from_index(content, idx),
                            pattern=escape_for_display(sink.description),
                            recommendation=escape_for_display(recommendation),
                            severity=severity,
                            confidence=confidence,
                            snippet=escape_for_display(snippet_orig),
                            sanitized=sanitized
                        ))

    return vulns
