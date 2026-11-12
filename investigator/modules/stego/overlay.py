"""Overlay & Polyglot Trailing Bytes Analyzer.

Detects hidden archives, executables, scripts, and trailing data appended
after legitimate image End-Of-File (EOF) markers.
"""

import os
from typing import Dict, Any, List, Optional, Tuple
import math


KNOWN_SIGNATURES = [
    (b"PK\x03\x04", "ZIP Archive (or DOCX/JAR/APK)", ".zip"),
    (b"PK\x05\x06", "Empty/Spanned ZIP Archive", ".zip"),
    (b"Rar!\x1a\x07\x00", "RAR 4.x Archive", ".rar"),
    (b"Rar!\x1a\x07\x01\x00", "RAR 5.x Archive", ".rar"),
    (b"7z\xbc\xaf\x27\x1c", "7-Zip Archive", ".7z"),
    (b"\x1f\x8b\x08", "GZIP Compressed File", ".gz"),
    (b"%PDF-", "PDF Document", ".pdf"),
    (b"MZ", "Windows PE Executable / DLL", ".bin"),
    (b"\x7fELF", "Linux ELF Binary", ".elf"),
    (b"SQLite format 3\x00", "SQLite Database", ".db"),
    (b"<?php", "PHP Script", ".php"),
    (b"<script", "JavaScript / HTML Fragment", ".html"),
    (b"#!/bin/bash", "Bash Shell Script", ".sh"),
    (b"#!/bin/sh", "Shell Script", ".sh"),
]


def calculate_entropy(data: bytes) -> float:
    """Calculates Shannon entropy of a byte stream (0.0 to 8.0 bits/byte)."""
    if not data:
        return 0.0
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    total = len(data)
    entropy = 0.0
    for count in freq:
        if count > 0:
            p = count / total
            entropy -= p * math.log2(p)
    return round(entropy, 3)


def locate_jpeg_eof(raw_bytes: bytes) -> int:
    """Locates the true End-Of-Image (EOI 0xFFD9) by parsing JPEG markers."""
    if not raw_bytes.startswith(b"\xff\xd8"):
        return -1
        
    offset = 2
    n = len(raw_bytes)
    
    while offset < n:
        if raw_bytes[offset] != 0xff:
            # Desynchronized, fallback to last rfind
            break
            
        # Skip extra 0xFF fill bytes
        while offset < n and raw_bytes[offset] == 0xff:
            offset += 1
            
        if offset >= n:
            break
            
        marker = raw_bytes[offset]
        offset += 1
        
        # Standalone markers without length: SOI (0xD8), EOI (0xD9), RST0-RST7 (0xD0-0xD7)
        if marker in (0xd8, 0xd9) or (0xd0 <= marker <= 0xd7):
            if marker == 0xd9:
                return offset  # Found valid EOI
            continue
            
        # Start of Scan (SOS - 0xDA): Entropy-coded scan follows until EOI
        if marker == 0xda:
            if offset + 2 > n:
                break
            length = int.from_bytes(raw_bytes[offset:offset+2], "big")
            offset += length
            
            # Scan through compressed image data to find final 0xFFD9
            while offset < n - 1:
                if raw_bytes[offset] == 0xff:
                    next_byte = raw_bytes[offset + 1]
                    if next_byte == 0x00:
                        # Byte stuffing, skip
                        offset += 2
                        continue
                    elif 0xd0 <= next_byte <= 0xd7:
                        # Restart marker inside scan
                        offset += 2
                        continue
                    elif next_byte == 0xd9:
                        # EOI marker reached!
                        return offset + 2
                    elif next_byte != 0xff:
                        offset += 2
                        continue
                offset += 1
            break
            
        # Standard marker with 2-byte big-endian length
        if offset + 2 > n:
            break
        length = int.from_bytes(raw_bytes[offset:offset+2], "big")
        offset += length
        
    # Fallback: scan for last occurrence of 0xFFD9
    last_eoi = raw_bytes.rfind(b"\xff\xd9")
    if last_eoi != -1:
        return last_eoi + 2
    return -1


def locate_png_eof(raw_bytes: bytes) -> int:
    """Locates the end of PNG file by tracing chunks until IEND chunk."""
    if not raw_bytes.startswith(b"\x89PNG\r\n\x1a\n"):
        return -1
        
    offset = 8
    n = len(raw_bytes)
    
    while offset + 8 <= n:
        chunk_len = int.from_bytes(raw_bytes[offset:offset+4], "big")
        chunk_type = raw_bytes[offset+4:offset+8]
        # Chunk structure: 4 bytes length + 4 bytes type + chunk_len data + 4 bytes CRC
        chunk_total_len = 12 + chunk_len
        
        if chunk_type == b"IEND":
            return offset + chunk_total_len
            
        offset += chunk_total_len
        
    # Fallback to searching for IEND marker + 4 bytes CRC
    iend_pos = raw_bytes.rfind(b"IEND")
    if iend_pos != -1 and iend_pos + 8 <= n:
        return iend_pos + 8
    return -1


def locate_gif_eof(raw_bytes: bytes) -> int:
    """Locates GIF EOF (trailer byte 0x3B)."""
    if not (raw_bytes.startswith(b"GIF87a") or raw_bytes.startswith(b"GIF89a")):
        return -1
    last_trailer = raw_bytes.rfind(b"\x3b")
    if last_trailer != -1:
        return last_trailer + 1
    return -1


def scan_trailing_bytes(file_path: str) -> Dict[str, Any]:
    """Inspects file container for trailing overlay data and polyglot payloads."""
    with open(file_path, "rb") as f:
        raw_data = f.read()
        
    file_size = len(raw_data)
    eof_pos = -1
    format_name = "UNKNOWN"
    
    if raw_data.startswith(b"\xff\xd8"):
        format_name = "JPEG"
        eof_pos = locate_jpeg_eof(raw_data)
    elif raw_data.startswith(b"\x89PNG\r\n\x1a\n"):
        format_name = "PNG"
        eof_pos = locate_png_eof(raw_data)
    elif raw_data.startswith(b"GIF87a") or raw_data.startswith(b"GIF89a"):
        format_name = "GIF"
        eof_pos = locate_gif_eof(raw_data)
        
    has_trailing = False
    trailing_size = 0
    trailing_bytes = b""
    detected_payloads: List[Dict[str, Any]] = []
    trailing_entropy = 0.0
    
    if eof_pos != -1 and eof_pos < file_size:
        trailing_size = file_size - eof_pos
        # Allow up to 4 trailing padding null bytes before triggering
        if trailing_size > 4 or raw_data[eof_pos:].strip(b"\x00\r\n "):
            has_trailing = True
            trailing_bytes = raw_data[eof_pos:]
            trailing_entropy = calculate_entropy(trailing_bytes)
            
            # Scan trailing bytes for known embedded signatures
            for sig, label, ext in KNOWN_SIGNATURES:
                pos = trailing_bytes.find(sig)
                if pos != -1:
                    detected_payloads.append({
                        "signature": sig.decode("latin1", errors="replace"),
                        "type": label,
                        "file_extension": ext,
                        "offset_in_overlay": pos,
                        "absolute_file_offset": eof_pos + pos
                    })
                    
    # Also scan entire file for embedded secondary archives (e.g. polyglot headers)
    if not detected_payloads:
        # Search starting past the image header
        search_region = raw_data[16:]
        for sig, label, ext in KNOWN_SIGNATURES:
            pos = search_region.find(sig)
            if pos != -1:
                abs_offset = 16 + pos
                detected_payloads.append({
                    "signature": sig.decode("latin1", errors="replace"),
                    "type": f"Embedded {label}",
                    "file_extension": ext,
                    "offset_in_overlay": None,
                    "absolute_file_offset": abs_offset
                })
                
    # Calculate Risk Score
    score = 0.0
    if has_trailing:
        score += 40.0
        # If high entropy (indicates compressed or encrypted payload)
        if trailing_entropy > 7.0:
            score += 25.0
        elif trailing_entropy > 5.0:
            score += 15.0
            
    if detected_payloads:
        score += 35.0
        
    final_score = round(min(score, 100.0), 1)
    
    return {
        "score": final_score,
        "format": format_name,
        "total_file_size": file_size,
        "declared_eof_offset": eof_pos,
        "has_trailing_data": has_trailing,
        "trailing_bytes_count": trailing_size,
        "trailing_entropy": trailing_entropy,
        "detected_payloads": detected_payloads,
        "_raw_trailing": trailing_bytes,
        "_raw_full": raw_data
    }


def carve_payloads(analysis_result: Dict[str, Any], output_dir: str) -> List[str]:
    """Carves extracted trailing or embedded data into separate output files."""
    os.makedirs(output_dir, exist_ok=True)
    carved_files: List[str] = []
    
    trailing_data = analysis_result.get("_raw_trailing", b"")
    payloads = analysis_result.get("detected_payloads", [])
    
    # 1. Carve whole overlay if present
    if trailing_data:
        raw_overlay_path = os.path.join(output_dir, "carved_overlay_data.bin")
        with open(raw_overlay_path, "wb") as f:
            f.write(trailing_data)
        carved_files.append(raw_overlay_path)
        
    # 2. Carve individual recognized payloads
    full_data = analysis_result.get("_raw_full", b"")
    for idx, p in enumerate(payloads):
        offset = p["absolute_file_offset"]
        ext = p["file_extension"]
        carved_item_path = os.path.join(output_dir, f"carved_payload_{idx+1}{ext}")
        with open(carved_item_path, "wb") as f:
            f.write(full_data[offset:])
        carved_files.append(carved_item_path)
        
    return list(set(carved_files))

