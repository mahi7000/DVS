def calculate_confidence(snippet: str) -> float:
    """Calculate confidence based on snippet content"""
    confidence = 0.7  # Base confidence
    
    # Increase confidence for certain patterns
    if any(keyword in snippet.lower() for keyword in ['innerhtml', 'eval', 'document.write']):
        confidence += 0.2
    
    if any(keyword in snippet.lower() for keyword in ['userinput', 'location.hash', 'req.query']):
        confidence += 0.1
    
    return min(confidence, 1.0)