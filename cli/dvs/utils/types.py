from dataclasses import dataclass
from typing import List, Optional, Dict, Any
from enum import Enum
from datetime import datetime
import re

class Severity(Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

@dataclass
class SourceFile:
    path: str
    content: str
    is_template: bool = False
    is_server_code: bool = False
    is_client_code: bool = False
    language: Optional[str] = None
    framework: Optional[str] = None
    dependencies: Optional[List[str]] = None
    last_modified: Optional[datetime] = None
    size: Optional[int] = None

@dataclass
class SinkDefinition:
    pattern: str
    description: str
    context: str
    compiled_re: Optional[re.Pattern] = None
    
    def __post_init__(self):
        self.compiled_re = re.compile(self.pattern, re.MULTILINE | re.IGNORECASE)

@dataclass
class Vulnerability:
    type: str
    file: str
    line: Optional[int] = None
    pattern: str = ""
    recommendation: str = ""
    severity: Severity = Severity.HIGH
    confidence: float = 0.8
    snippet: Optional[str] = None
    sanitized: bool = False

class ScanResult:
    def __init__(self):
        self.reflective_xss: List[Vulnerability] = []
        self.stored_xss: List[Vulnerability] = []
        self.dom_xss: List[Vulnerability] = []
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "reflectiveXSS": [v.__dict__ for v in self.reflective_xss],
            "storedXSS": [v.__dict__ for v in self.stored_xss],
            "domXSS": [v.__dict__ for v in self.dom_xss]
        }
    
    def get(self, key: str, default: Any = None) -> Any:
        """Dictionary-like get method for compatibility"""
        attr_map = {
            'reflectiveXSS': 'reflective_xss',
            'storedXSS': 'stored_xss', 
            'domXSS': 'dom_xss'
        }
        
        actual_attr = attr_map.get(key)
        if actual_attr and hasattr(self, actual_attr):
            return getattr(self, actual_attr)
        return default