import re
from typing import List, Dict, Any
from ...utils.commentRemover import remove_html_comments_preserve, remove_js_comments_preserve
from ...utils.confidenceCalculator import calculate_confidence
from ...utils.escapeForDisplay import escape_for_display
from ...utils.types import SourceFile, Vulnerability, SinkDefinition, Severity

def detect_stored_xss(source_files: List[SourceFile]) -> List[Vulnerability]:
    vulns: List[Vulnerability] = []


    # Sources (server & client)
    server_sources = [
        r"req\.query",
        r"req\.body",
        r"req\.params",
        r"req\.headers",
        r"req\.cookies",
        r"req\.files",
        r"req\.input",
        r"req\.rawBody",
        r"process\.env",
    ]


    client_sources = [
        r"window\.location",
        r"document\.location",
        r"location\.hash",
        r"location\.search",
        r"document\.cookie",
        r"localStorage\.getItem",
        r"sessionStorage\.getItem",
        r"indexedDB\.get",
        r"document\.referrer",
        r"window\.name",
        r"WebSocket\.data",
        r"postMessage\.data",
        r"messageEvent\.data",
        r"navigator\.clipboard\.readText",
    ]


    all_sources = server_sources + client_sources


    # Storage Operations
    storage_operations = [
        {"re": re.compile(r"(?:db|database|client)\.(?:insert|update|save|create|upsert|replace)\s*\("), "type": "database"},
        {"re": re.compile(r"Model\.(?:create|update|findOneAndUpdate|updateOne|updateMany|insertMany|save)\s*\("), "type": "orm"},
        {"re": re.compile(r"fs\.(?:writeFile|appendFile|createWriteStream|promises\.writeFile)\s*\("), "type": "filesystem"},
        {"re": re.compile(r"(?:localStorage|sessionStorage)\.setItem\s*\("), "type": "webstorage"},
        {"re": re.compile(r"indexedDB\.(?:put|add)\s*\("), "type": "indexeddb"},
        {"re": re.compile(r"document\.cookie\s*="), "type": "cookie"},
        {"re": re.compile(r"(?:s3|blobService)\.(?:putObject|upload|createBlockBlobFromText|createAppendBlobFromText)\s*\("), "type": "cloudstorage"},
        {"re": re.compile(r"(?:cache|redis)\.(?:set|setex|hset|put)\s*\("), "type": "cache"},
        {"re": re.compile(r"\w+\.(?:push|unshift|splice)\s*\("), "type": "array"},
        {"re": re.compile(r"\w+\s*=\s*[^;]+;"), "type": "var_assign"},
    ]


    # Output Sinks
    server_sinks = [
        SinkDefinition(
            pattern=r"\w+\.(send|write|end|jsonp|json)\s*\([\s\S]*?\)",
            description=".send/.write/.end/.json/.jsonp",
            context="html"
        ),
        SinkDefinition(
            pattern=r"\w+\.render\s*\(\s*[^,]+,\s*[\s\S]*?\)",
            description=".render(view, data)",
            context="html"
        ),
        SinkDefinition(
            pattern=r"\w+\.redirect\s*\([\s\S]*?\)",
            description=".redirect(url)",
            context="url"
        ),
    ]


    client_dom_sinks = [
        SinkDefinition(
            pattern=r"\w+\.innerHTML\s*=\s*[\s\S]*?;",
            description="innerHTML assignment",
            context="html"
        ),
        SinkDefinition(
            pattern=r"outerHTML\s*=\s*[\s\S]*?;",
            description="outerHTML assignment",
            context="html"
        ),
        SinkDefinition(
            pattern=r"insertAdjacentHTML\s*\([\s\S]*?\)",
            description="insertAdjacentHTML(...)",
            context="html"
        ),
        SinkDefinition(
            pattern=r"document\.write(?:ln)?\s*\([\s\S]*?\)",
            description="document.write / writeln",
            context="html"
        ),
        SinkDefinition(
            pattern=r"\$\([\s\S]*?\)\.html\s*\([\s\S]*?\)",
            description="jQuery.html()",
            context="html"
        ),
        SinkDefinition(
            pattern=r"\$\([\s\S]*?\)\.append\s*\([\s\S]*?\)",
            description="jQuery.append()",
            context="html"
        ),
        SinkDefinition(
            pattern=r"setAttribute\s*\(\s*[\"']on\w+[\"'],\s*[\s\S]*?\)",
            description="setAttribute with event handler",
            context="attr"
        ),
    ]


    html_sanitizers = [
        re.compile(r"(?:DOMPurify|escapeHtml|sanitizeHtml|he\.escape)\s*\("),
        re.compile(r"\.text(?:Content|Context)\s*="),
        re.compile(r"createTextNode\s*\("),
        re.compile(r"<%-?[^=](?!.*%>)"),
        re.compile(r"#\{.*?\}"),
    ]
   
    url_sanitizers = [
        re.compile(r"encodeURIComponent\s*\("),
        re.compile(r"encodeURI\s*\("),
    ]


    def line_from_index(text: str, idx: int) -> int:
        return text.count('\n', 0, idx) + 1


    def slice_has_source(slice_text: str, sources: List[str]) -> bool:
        return any(re.search(source, slice_text) for source in sources)


    def is_sanitized_for_context(slice_text: str, context: str) -> bool:
        if context == "url":
            return any(re.search(slice_text) for re in url_sanitizers)
        if context == "html":
            return any(re.search(slice_text) for re in html_sanitizers)
        return False


    for file in source_files:
        content = file.content

        if file.is_server_code:
            content = remove_js_comments_preserve(content)
        else:
            content = remove_html_comments_preserve(content)

        storage_points = []

        # Find storage ops
        for op in storage_operations:
            for match in op["re"].finditer(content):
                idx = match.start()
                slice_start = max(0, idx - 300)
                slice_end = min(len(content), idx + len(match.group()) + 300)
                code_slice = content[slice_start:slice_end]
               
                if slice_has_source(code_slice, all_sources):
                    storage_points.append({
                        "file": file,
                        "line": line_from_index(content, idx),
                        "operation": op["type"],
                        "context": code_slice
                    })


        # Sinks
        sinks = server_sinks if file.is_server_code else client_dom_sinks
        for sink in sinks:
            if not sink.compiled_re:
                continue
               
            for sink_match in sink.compiled_re.finditer(content):
                sink_idx = sink_match.start()
                sink_line = line_from_index(content, sink_idx)
               
                for storage in storage_points:
                    if storage["file"].path == file.path and sink_line > storage["line"]:
                        sink_slice_start = max(0, sink_idx - 300)
                        sink_slice_end = min(len(content), sink_idx + len(sink_match.group()) + 300)
                        sink_slice = content[sink_slice_start:sink_slice_end]
                       
                        sanitized = is_sanitized_for_context(sink_slice, sink.context)
                       
                        if not sanitized:
                            vulns.append(Vulnerability(
                                type="Stored XSS",
                                file=file.path,
                                line=sink_line,
                                pattern=escape_for_display(sink.description),
                                recommendation=escape_for_display("Sanitize stored data before output using DOMPurify or similar." if sink.context == "html" else "Properly encode/escape stored data for the context."),
                                severity=Severity.HIGH,
                                confidence=calculate_confidence(sink_match.group()),
                                snippet=escape_for_display(sink_match.group()[:200]),
                                sanitized=sanitized
                            ))


        # Direct storage → output
        if file.is_server_code:
            storage_to_output_patterns = [
                {
                    "re": re.compile(r"(?:const|let|var)\s+\w+\s*=\s*await\s+\w+\.(?:findOne|findById)\s*\([\s\S]*?\)[\s\S]*?res\.(?:send|render|json)\s*\([\s\S]*?\w+\.\w+"),
                    "desc": "DB query directly to output"
                },
                {
                    "re": re.compile(r"fs\.readFile\w*\s*\([\s\S]*?\)[\s\S]*?res\.(?:send|write)\s*\("),
                    "desc": "File read directly to output"
                },
                {
                    "re": re.compile(r"res\.(?:send|render|json)\([^)]*?\b\w+\.map\([^)]*?=>[^)]*?\$\{[^}]+?\}"),
                    "desc": "Direct array map to template output"
                },
            ]
           
            for pattern in storage_to_output_patterns:
                for match in pattern["re"].finditer(content):
                    idx = match.start()
                    slice_start = max(0, idx - 300)
                    slice_end = idx + len(match.group()) + 300
                    slice_text = content[slice_start:slice_end]
                   
                    if slice_has_source(slice_text, all_sources) and not is_sanitized_for_context(slice_text, "html"):
                        vulns.append(Vulnerability(
                            type="Stored XSS (Direct Storage to Output)",
                            file=file.path,
                            line=line_from_index(content, idx),
                            pattern=escape_for_display(pattern["desc"]),
                            recommendation=escape_for_display("Add sanitization between retrieval and output."),
                            severity=Severity.CRITICAL,
                            confidence=calculate_confidence(match.group()),
                            snippet=escape_for_display(match.group()[:200]),
                            sanitized=False
                        ))


    # Remove duplicates
    unique_vulns = []
    seen = set()
    for vuln in vulns:
        key = f"{vuln.file}:{vuln.line}:{vuln.pattern}"
        if key not in seen:
            seen.add(key)
            unique_vulns.append(vuln)
   
    return unique_vulns
