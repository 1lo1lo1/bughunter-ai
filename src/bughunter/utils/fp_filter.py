"""
False Positive Filter for BugHunter AI
Reduces noise from CMS UUIDs, image hashes, etc.
"""
import re
from typing import Union, Any

# Patterns that indicate false positives
JCR_UUID_PATTERN = re.compile(r'jcr:[a-f0-9-]{36}', re.IGNORECASE)
IMAGE_HASH_PATTERN = re.compile(r'/hash/[a-f0-9]{32}', re.IGNORECASE)
CMS_IMAGING_PATTERN = re.compile(r'\.imaging/flex/', re.IGNORECASE)
VERSION_PATTERN = re.compile(r'version/\d+', re.IGNORECASE)
FILLCOLOR_PATTERN = re.compile(r'fillColor/-?\d+', re.IGNORECASE)

def is_likely_false_positive(secret_value: str, surrounding_context: str) -> tuple[bool, str]:
    """
    Check if a detected secret is likely a false positive.
    
    Returns:
        (is_fp: bool, reason: str)
    """
    # Check 1: Joomla/Adobe CRX content repository UUID
    if JCR_UUID_PATTERN.search(secret_value):
        return True, "Joomla/CRX content ID (not a secret)"
    
    # Check 2: Image hash in URL path
    if IMAGE_HASH_PATTERN.search(surrounding_context):
        return True, "Image processing hash (not a secret)"
    
    # Check 3: CMS imaging system
    if CMS_IMAGING_PATTERN.search(surrounding_context):
        return True, "CMS image URL (not a secret)"
    
    # Check 4: Version number in path
    if VERSION_PATTERN.search(surrounding_context):
        return True, "Version number in URL"
    
    # Check 5: fillColor parameter (image processing)
    if FILLCOLOR_PATTERN.search(surrounding_context):
        return True, "Image processing parameter"
    
    # Check 6: UUID in image src/srcset
    if any(x in surrounding_context.lower() for x in ['src=', 'srcset=', 'data-srcset=']):
        if re.match(r'^[a-f0-9-]{36}$', secret_value.replace('jcr:', '')):
            return True, "Image UUID in HTML attribute"
    
    return False, ""

def _get_finding_value(finding: Any, attr_name: str, default: str = '') -> str:
    """Get value from finding (dict or object)"""
    if isinstance(finding, dict):
        return finding.get(attr_name, default)
    else:
        # Vulnerability object
        return getattr(finding, attr_name, default)

def _get_snippet_content(finding: Any) -> str:
    """Get snippet content from finding"""
    if isinstance(finding, dict):
        snippet = finding.get('snippet', {})
        if isinstance(snippet, dict):
            return snippet.get('content', '')
        return str(snippet)
    else:
        # Vulnerability object
        snippet = getattr(finding, 'snippet', None)
        if snippet is None:
            return ''
        if hasattr(snippet, 'content'):
            return snippet.content
        return str(snippet)

def filter_findings(findings: list) -> list:
    """Filter out false positives from findings list."""
    filtered = []
    for finding in findings:
        # Get secret value and context from finding (works with both dict and Vulnerability object)
        secret_value = _get_finding_value(finding, 'matched_pattern', '')
        context = _get_snippet_content(finding)
        
        is_fp, reason = is_likely_false_positive(secret_value, context)
        
        if is_fp:
            # Mark as false positive but keep for reference
            if isinstance(finding, dict):
                finding['false_positive'] = True
                finding['false_positive_reason'] = reason
                finding['severity'] = 'INFO'
            else:
                # Vulnerability object
                finding.false_positive = True
                finding.false_positive_reason = reason
                finding.severity = 'INFO'
            # Skip false positives - don't add to filtered list
            continue
        
        filtered.append(finding)
    
    return filtered


class FalsePositiveFilter:
    """Wrapper class for backward compatibility with core.py"""
    
    def __init__(self):
        pass
    
    def check(self, secret_value: str, context: str) -> tuple[bool, str]:
        """Check if finding is false positive"""
        return is_likely_false_positive(secret_value, context)
    
    def filter_list(self, findings: list) -> list:
        """Filter list of findings"""
        return filter_findings(findings)
    
    def filter(self, findings: list) -> list:
        """Alias for filter_list for backward compatibility with core.py"""
        return self.filter_list(findings)
