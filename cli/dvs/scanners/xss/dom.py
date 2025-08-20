import re
from typing import List, Tuple
from ...utils.types import SourceFile, Vulnerability, SinkDefinition, Severity

ContextType = str  # "html", "js", "url", "attr", "css"

def detect_dom_xss(source_files: List[SourceFile]) -> List[Vulnerability]:
    vulns: List[Vulnerability] = []

    # Enhanced source patterns
    dom_sources = [
        r"location\.hash",
        r"location\.hash\.substring\(",
        r"location\.hash\.slice\(",
        r"decodeURIComponent\(location\.hash\)",
        r"location\.search",
        r"location\.pathname",
        r"location\.href",
        r"document\.URL",
        r"document\.documentURI",
        r"document\.baseURI",
        r"document\.referrer",
        r"URLSearchParams",
        r"document\.cookie",
        r"window\.name",
        r"localStorage(?:\.getItem)?",
        r"sessionStorage(?:\.getItem)?",
        r"indexedDB",
        r"document\.forms",
        r"\.value\b",
        r"\.files\b",
        r"\.getAttribute\(",
        r"\.attributes\b",
        r"navigator\.userAgent",
        r"navigator\.language",
        r"navigator\.plugins",
        r"screen\.(width|height)",
        r"fetch\(",
        r"XMLHttpRequest",
        r"xhr\.",
        r"WebSocket\(",
        r"postMessage\(",
    ]

    # More comprehensive sink patterns
    dom_sinks = [
        # HTML injection
        SinkDefinition(
            pattern=r"document\.(write|writeln)\s*\([^)]*\)",
            description="document.write/writeln",
            context="html"
        ),
        SinkDefinition(
            pattern=r"(?:document\.getElementById\([^)]+\)|[\w.]+)\.(innerHTML|outerHTML)\s*=",
            description="element.innerHTML/outerHTML =",
            context="html"
        ),
        SinkDefinition(
            pattern=r"\w+\.insertAdjacentHTML\s*\([^)]*\)",
            description="insertAdjacentHTML()",
            context="html"
        ),

        # Script execution
        SinkDefinition(
            pattern=r"eval\s*\([^)]*\)",
            description="eval()",
            context="js"
        ),
        SinkDefinition(
            pattern=r"new\s+Function\s*\([^)]*\)",
            description="new Function()",
            context="js"
        ),
        SinkDefinition(
            pattern=r"(?:setTimeout|setInterval)\s*\(\s*['\"`]",
            description="setTimeout/setInterval(string)",
            context="js"
        ),

        # URL/navigation
        SinkDefinition(
            pattern=r"location\s*=\s*[^;]+",
            description="location = ...",
            context="url"
        ),
        SinkDefinition(
            pattern=r"location\.(href|assign|replace)\s*\([^)]*\)|location\.href\s*=",
            description="location.href/assign/replace",
            context="url"
        ),
        SinkDefinition(
            pattern=r"window\.open\s*\([^)]*\)",
            description="window.open()",
            context="url"
        ),

        # Attribute/event-handler assignments
        SinkDefinition(
            pattern=r"\w+\.setAttribute\s*\(\s*['\"][^'\"]+['\"]\s*,\s*(?:[^)]*?(?:\+|\$\{)[^)]*?|['\"][^'\"]*userInput[^'\"]*['\"])\)",
            description="setAttribute() with dynamic value",
            context="attr"
        ),
        SinkDefinition(
            pattern=r"\w+\.on[a-z]+\s*=\s*(?:[^;]*?(?:\+|\$\{)|['\"][^'\"]*userInput[^'\"]*['\"])",
            description="inline event handler with dynamic",
            context="attr"
        ),

        # CSS injection
        SinkDefinition(
            pattern=r"(?:document\.getElementById\([^)]+\)|[\w.]+)\.style\.(innerHTML|cssText)\s*=\s*(?:[^;]*?(?:\+|\$\{)|['\"][^'\"]*userInput[^'\"]*['\"])",
            description="style.innerHTML/cssText =",
            context="css"
        ),
        SinkDefinition(
            pattern=r"\w+\.style\.setProperty\s*\(\s*['\"][^'\"]+['\"]\s*,\s*(?:[^)]*?(?:\+|\$\{)|['\"][^'\"]*userInput[^'\"]*['\"])\)",
            description="style.setProperty()",
            context="css"
        ),

        # URL-bearing attributes
        SinkDefinition(
            pattern=r"\w+\.(src|href|srcdoc|data|code|formAction|action)\s*=\s*(?:[^;]*?(?:\+|\$\{)|['\"][^'\"]*userInput[^'\"]*['\"])",
            description="URL-bearing attribute assignment",
            context="url"
        ),
        SinkDefinition(
            pattern=r"<(?:iframe|frame|embed|object)\s+[^>]*(?:src|srcdoc)\s*=\s*(?:['\"][^'\"]*userInput[^'\"]*['\"]|`[^`]*\$\{[^}]*\}[^`]*`)",
            description="Embedded element src/srcdoc",
            context="url"
        ),
    ]

    def line_from_index(text: str, idx: int) -> int:
        return text.count('\n', 0, idx) + 1

    def slice_has_any(slice_text: str, patterns: List[str]) -> bool:
        return any(re.search(pattern, slice_text) for pattern in patterns)

    for file in source_files:
        content = file.content
        is_client_code = file.is_client_code
        language = file.language
        is_template = file.is_template

        looks_client = (
            is_client_code or
            is_template or
            (language and re.match(r'^(js|ts|tsx|jsx|html)$', language, re.IGNORECASE)) or
            re.search(r'\.(html?|jsx?|tsx?)$', file.path, re.IGNORECASE)
        )

        if not looks_client or not content:
            continue

        # First scan for all sinks
        for sink in dom_sinks:
            if not sink.compiled_re:
                continue
                
            for match in sink.compiled_re.finditer(content):
                idx = match.start()
                ctx = sink.context

                # Use larger window for better source detection
                slice_start = max(0, idx - 750)
                slice_end = min(len(content), idx + len(match.group()) + 750)
                code_slice = content[slice_start:slice_end]

                # More lenient source detection
                has_source = (
                    slice_has_any(code_slice, dom_sources) or
                    re.search(r'userInput|location\.hash', code_slice)
                )

                if not has_source:
                    continue

                severity = Severity.HIGH
                vuln_type = f"DOM-based {ctx.upper()} Injection"
                recommendation = ""

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
                    severity = Severity.CRITICAL if re.search(r'javascript:', match.group()) else Severity.HIGH
                elif ctx == "attr":
                    vuln_type = "DOM-based Attribute Injection"
                    recommendation = "Avoid setting attributes with dynamic user input"
                    severity = Severity.HIGH
                elif ctx == "css":
                    vuln_type = "DOM-based CSS Injection"
                    recommendation = "Never inject user input into CSS properties"
                    severity = Severity.CRITICAL if re.search(r'expression\(|javascript:', match.group()) else Severity.HIGH

                vulns.append(Vulnerability(
                    type=vuln_type,
                    file=file.path,
                    line=line_from_index(content, idx),
                    pattern=f"{sink.description}: {match.group().strip()}",
                    recommendation=recommendation,
                    severity=severity,
                    confidence=0.95,
                    snippet=f"{sink.description}: {match.group().strip()}",
                    sanitized=False
                ))

        # Special case for inline javascript: URLs
        inline_js_urls = re.compile(r'(?:href|src|action)\s*=\s*["\']\s*javascript:[^"\']*["\']', re.IGNORECASE)
        for match in inline_js_urls.finditer(content):
            idx = match.start()
            vulns.append(Vulnerability(
                type="DOM-based URL Injection",
                file=file.path,
                line=line_from_index(content, idx),
                pattern=match.group().strip(),
                recommendation="Remove all javascript: URLs - use event handlers instead",
                severity=Severity.CRITICAL,
                confidence=1.0,
                snippet=match.group().strip(),
                sanitized=False
            ))

    return vulns