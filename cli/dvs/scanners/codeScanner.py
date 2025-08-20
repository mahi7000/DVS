from typing import List, Dict, Any
from .xss.reflective import detect_reflective_xss
from .xss.stored import detect_stored_xss
from .xss.dom import detect_dom_xss
from ..utils.types import SourceFile, ScanResult

def run_code_scan(source_files: List[SourceFile]) -> Dict[str, Any]:
    print("🔍 Running code scanner...")
    
    # Convert dictionaries to SourceFile instances if needed
    processed_files = []
    for file in source_files:
        if isinstance(file, dict):
            # Convert camelCase keys to snake_case
            converted_data = {}
            for key, value in file.items():
                # Convert camelCase to snake_case
                snake_key = ''.join(['_' + c.lower() if c.isupper() else c for c in key]).lstrip('_')
                converted_data[snake_key] = value
            processed_files.append(SourceFile(**converted_data))
        else:
            processed_files.append(file)
    
    # Run the detection functions
    reflective_xss_results = detect_reflective_xss(processed_files)
    stored_xss_results = detect_stored_xss(processed_files)
    dom_xss_results = detect_dom_xss(processed_files)
    
    # Create ScanResult instance and populate it
    result = ScanResult()
    result.reflective_xss = reflective_xss_results
    result.stored_xss = stored_xss_results
    result.dom_xss = dom_xss_results
    
    # Convert to dictionary for compatibility with dashboard
    return result.to_dict()