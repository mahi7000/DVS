import re
from typing import List, Optional
from types import SourceFile, Vulnerability, SinkDefinition

class BaseScanner:
    def __init__(self):
        self.sources: List[str] = []
        self.sinks: List[SinkDefinition] = []
        self._compile_patterns()

    def _compile_patterns(self):
        """Compile all regex patterns for performance"""
        for sink in self.sinks:
            if not hasattr(sink, 'compiled_re'):
                sink.compiled_re = re.compile(sink.pattern, re.MULTILINE)

    def _line_from_index(self, text: str, idx: int) -> int:
        """Calculate line number from character index"""
        return text.count('\n', 0, idx) + 1

    def _slice_has_any(self, text_slice: str, patterns: List[str]) -> bool:
        """Check if any pattern exists in the text slice"""
        return any(re.search(pattern, text_slice) for pattern in patterns)

    def scan(self, source_files: List[SourceFile]) -> List[Vulnerability]:
        """Base scan method to be implemented by subclasses"""
        raise NotImplementedError()