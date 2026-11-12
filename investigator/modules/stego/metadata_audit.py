"""EXIF & Metadata Security Auditor.

Scans image metadata, XMP, and comments for hidden shellcode, base64 payloads,
web injection tags, command lines, and suspicious external URLs.
"""

from typing import Dict, Any, List
import re
import io
import contextlib
import exifread


SUSPICIOUS_PATTERNS = [
    (r"powershell(\.exe)?\s+", "PowerShell Execution Command"),
    (r"cmd(\.exe)?\s+/c", "Windows CMD Command"),
    (r"bash\s+-i", "Interactive Bash Reverse Shell"),
    (r"(curl|wget)\s+https?://", "Downloader / Web Drop Command"),
    (r"eval\s*\(", "Code Evaluation Function (eval)"),
    (r"base64_decode\s*\(", "PHP Base64 Decoder"),
    (r"system\s*\(", "System Execution Call"),
    (r"<script[\s>]", "HTML / JavaScript Injection"),
    (r"<\?php", "Embedded PHP Code"),
    (r"https?://(?:[0-9]{1,3}\.){3}[0-9]{1,3}", "Raw IP URL (C2/Drop Indicator)"),
    (r"^[A-Za-z0-9+/]{64,}={0,2}$", "Long Base64 Payload String"),
]


def audit_metadata(file_path: str) -> Dict[str, Any]:
    """Audits EXIF and raw metadata fields for malicious payload traces.
    
    Args:
        file_path: Path to target image.
        
    Returns:
        Dict with security score, detected anomalies, and raw tag list.
    """
    findings: List[Dict[str, Any]] = []
    suspicious_tags: List[Dict[str, Any]] = []
    
    # 1. Inspect structured EXIF tags
    try:
        devnull = io.StringIO()
        with open(file_path, "rb") as f:
            with contextlib.redirect_stdout(devnull), contextlib.redirect_stderr(devnull):
                tags = exifread.process_file(f, details=False)
    except Exception:
        tags = {}
        
    total_tags = len(tags)
    
    for tag_name, tag_val in tags.items():
        val_str = str(tag_val).strip()
        val_bytes_len = len(val_str.encode("utf-8", errors="replace"))
        
        # Check for unusually large metadata tags (> 512 bytes)
        if val_bytes_len > 512:
            findings.append({
                "tag": tag_name,
                "issue": f"Abnormally large metadata tag ({val_bytes_len} bytes)",
                "preview": val_str[:80] + "...",
                "severity": "MEDIUM"
            })
            
        # Pattern match for suspicious payload strings
        for pattern, label in SUSPICIOUS_PATTERNS:
            if re.search(pattern, val_str, re.IGNORECASE):
                findings.append({
                    "tag": tag_name,
                    "issue": f"Malicious pattern detected: {label}",
                    "preview": val_str[:120],
                    "severity": "CRITICAL"
                })
                suspicious_tags.append({
                    "tag": tag_name,
                    "label": label,
                    "value": val_str[:200]
                })
                
    # 2. Raw binary scan for embedded comments (JPEG COM marker 0xFFFE)
    with open(file_path, "rb") as f:
        content = f.read()
        
    com_marker = b"\xff\xfe"
    offset = 0
    while True:
        pos = content.find(com_marker, offset)
        if pos == -1:
            break
        if pos + 4 <= len(content):
            com_len = int.from_bytes(content[pos+2:pos+4], "big")
            com_data = content[pos+4:pos+2+com_len]
            com_str = com_data.decode("latin1", errors="replace").strip()
            
            for pattern, label in SUSPICIOUS_PATTERNS:
                if re.search(pattern, com_str, re.IGNORECASE):
                    findings.append({
                        "tag": "JPEG_COM_MARKER",
                        "issue": f"Suspicious JPEG comment payload: {label}",
                        "preview": com_str[:120],
                        "severity": "CRITICAL"
                    })
        offset = pos + 2
        
    # Calculate Security Score (0 - 100)
    score = 0.0
    for f in findings:
        if f["severity"] == "CRITICAL":
            score += 45.0
        elif f["severity"] == "MEDIUM":
            score += 20.0
            
    final_score = round(min(score, 100.0), 1)
    
    return {
        "score": final_score,
        "total_tags_found": total_tags,
        "suspicious_findings_count": len(findings),
        "findings": findings,
        "suspicious_tags": suspicious_tags
    }
