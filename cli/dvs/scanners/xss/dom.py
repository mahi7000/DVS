import re
from typing import List
from ...utils.types import SourceFile, Vulnerability, SinkDefinition, Severity
from ...utils.commentRemover import remove_js_comments_preserve, remove_html_comments_preserve
from ...utils.confidenceCalculator import calculate_confidence   # hypothetical util

ContextType = str  # "html", "js", "url", "attr", "css"

def detect_dom_xss(source_files: List[SourceFile]) -> List[Vulnerability]:
    vulns: List[Vulnerability] = []

    # Enhanced source patterns (where untrusted input may come from)
    dom_sources = [
        r"location\.hash",
        r"location\.search",
        r"location\.pathname",
        r"location\.href",
        r"document\.URL",
        r"document\.referrer",
        r"document\.cookie",
        r"window\.name",
        r"localStorage(?:\.getItem)?",
        r"sessionStorage(?:\.getItem)?",
        r"indexedDB",
        r"\.value\b",
        r"\.files\b",
        r"\.getAttribute\(",
        r"navigator\.(userAgent|language|plugins)",
        r"screen\.(width|height)",
        r"fetch\(",
        r"XMLHttpRequest",
        r"postMessage\(",
    ]

    # Dangerous sink patterns
    dom_sinks = [
        SinkDefinition(r"document\.(write|writeln)\s*\([^)]*\)", "document.write/writeln", "html"),
        SinkDefinition(r"(?:document\.getElementById\([^)]+\)|[\w.]+)\.(innerHTML|outerHTML)\s*=", "element.innerHTML/outerHTML =", "html"),
        SinkDefinition(r"\w+\.insertAdjacentHTML\s*\([^)]*\)", "insertAdjacentHTML()", "html"),
        SinkDefinition(r"eval\s*\([^)]*\)", "eval()", "js"),
        SinkDefinition(r"new\s+Function\s*\([^)]*\)", "new Function()", "js"),
        SinkDefinition(r"(?:setTimeout|setInterval)\s*\(\s*['\"`]", "setTimeout/setInterval(string)", "js"),
        SinkDefinition(r"location\s*=\s*[^;]+", "location = ...", "url"),
        SinkDefinition(r"location\.(href|assign|replace)\s*=", "location.href/assign/replace", "url"),
        SinkDefinition(r"window\.open\s*\([^)]*\)", "window.open()", "url"),
        SinkDefinition(r"\w+\.setAttribute\s*\([^)]*\)", "setAttribute() with dynamic value", "attr"),
        SinkDefinition(r"\w+\.on[a-z]+\s*=", "inline event handler assignment", "attr"),
        SinkDefinition(r"\w+\.style\.(cssText|innerHTML)\s*=", "style.cssText assignment", "css"),
        SinkDefinition(r"\w+\.style\.setProperty\s*\(", "style.setProperty()", "css"),
        SinkDefinition(r"\w+\.(src|href|action)\s*=", "URL-bearing attribute assignment", "url"),
    ]

    def line_from_index(text: str, idx: int) -> int:
        return text.count('\n', 0, idx) + 1

    def slice_has_any(slice_text: str, patterns: List[str]) -> bool:
        return any(re.search(pattern, slice_text) for pattern in patterns)

    for file in source_files:
        content = file.content
        if not content:
            continue

        # Remove comments before scanning to avoid false positives
        if file.language and file.language.lower() in ("js", "ts", "tsx", "jsx"):
            content = remove_js_comments_preserve(content)
        elif file.language and "html" in file.language.lower():
            content = remove_html_comments_preserve(content)

        looks_client = (
            file.is_client_code or
            file.is_template or
            (file.language and re.match(r'^(js|ts|tsx|jsx|html)$', file.language, re.IGNORECASE)) or
            re.search(r'\.(html?|jsx?|tsx?)$', file.path, re.IGNORECASE)
        )

        if not looks_client:
            continue

        # Scan all sinks
        for sink in dom_sinks:
            if not sink.compiled_re:
                continue

            for match in sink.compiled_re.finditer(content):
                idx = match.start()
                ctx = sink.context

                # Expand slice around sink for source detection
                slice_start = max(0, idx - 750)
                slice_end = min(len(content), idx + len(match.group()) + 750)
                code_slice = content[slice_start:slice_end]

                has_source = (
                    slice_has_any(code_slice, dom_sources) or
                    re.search(r'userInput|location\.hash', code_slice)
                )
                if not has_source:
                    continue

                # Severity & recommendations
                if ctx == "html":
                    vuln_type = "DOM-based HTML Injection"
                    recommendation = "Use textContent instead of innerHTML/outerHTML or sanitize with DOMPurify"
                    severity = Severity.HIGH
                elif ctx == "js":
                    vuln_type = "DOM-based JS Execution"
                    recommendation = "Never execute dynamic code from user input"
                    severity = Severity.CRITICAL
                elif ctx == "url":
                    vuln_type = "DOM-based URL Injection"
                    recommendation = "Validate all URLs and block javascript:/data: schemes"
                    severity = Severity.CRITICAL if "javascript:" in match.group().lower() else Severity.HIGH
                elif ctx == "attr":
                    vuln_type = "DOM-based Attribute Injection"
                    recommendation = "Avoid setting attributes with dynamic user input"
                    severity = Severity.HIGH
                elif ctx == "css":
                    vuln_type = "DOM-based CSS Injection"
                    recommendation = "Never inject user input into CSS properties"
                    severity = Severity.CRITICAL if re.search(r'expression\(|javascript:', match.group()) else Severity.HIGH
                else:
                    vuln_type = "DOM-based Injection"
                    recommendation = "Sanitize/escape user input"
                    severity = Severity.HIGH

                # ✅ Confidence calculator
                confidence = calculate_confidence(
                    has_source=has_source,
                    sanitized=False,
                    context=ctx
                )

                vulns.append(Vulnerability(
                    type=vuln_type,
                    file=file.path,
                    line=line_from_index(content, idx),
                    pattern=f"{sink.description}: {match.group().strip()}",
                    recommendation=recommendation,
                    severity=severity,
                    confidence=confidence,
                    snippet=match.group().strip(),
                    sanitized=False
                ))

        

    return vulns
