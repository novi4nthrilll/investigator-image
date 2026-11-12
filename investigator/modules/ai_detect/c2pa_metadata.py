"""C2PA Content Credentials & Generative AI Metadata Scanner.

Extracts digital provenance manifests (C2PA/JUMBF), generator prompts,
workflow graphs (Stable Diffusion, ComfyUI, Midjourney), and synthetic media claims.
"""

from typing import Dict, Any, List, Optional
import json
import re
from PIL import Image


KNOWN_AI_SOFTWARE = [
    ("Midjourney", "Midjourney AI"),
    ("Stable Diffusion", "Stable Diffusion (Automatic1111 / ComfyUI)"),
    ("DALL·E", "OpenAI DALL-E"),
    ("DALL-E", "OpenAI DALL-E"),
    ("Adobe Firefly", "Adobe Firefly (Generative Fill)"),
    ("NovelAI", "NovelAI Image Generation"),
    ("Fooocus", "Fooocus Diffusion Suite"),
    ("Flux", "Flux Generative Model"),
    ("InvokeAI", "InvokeAI Platform"),
]


def extract_png_text_chunks(raw_bytes: bytes) -> Dict[str, str]:
    """Manually parses PNG text chunks (tEXt, iTXt, zTXt) to extract workflow/prompt data."""
    if not raw_bytes.startswith(b"\x89PNG\r\n\x1a\n"):
        return {}
        
    chunks = {}
    offset = 8
    n = len(raw_bytes)
    
    while offset + 8 <= n:
        chunk_len = int.from_bytes(raw_bytes[offset:offset+4], "big")
        chunk_type = raw_bytes[offset+4:offset+8]
        data_start = offset + 8
        data_end = data_start + chunk_len
        
        if data_end > n:
            break
            
        if chunk_type == b"tEXt":
            chunk_data = raw_bytes[data_start:data_end]
            if b"\x00" in chunk_data:
                key, val = chunk_data.split(b"\x00", 1)
                chunks[key.decode("latin1", errors="replace")] = val.decode("latin1", errors="replace")
                
        elif chunk_type == b"iTXt":
            # iTXt format: keyword\0 compression_flag compression_method lang_tag\0 trans_key\0 text
            chunk_data = raw_bytes[data_start:data_end]
            parts = chunk_data.split(b"\x00", 1)
            if parts:
                key = parts[0].decode("latin1", errors="replace")
                # Remaining text after headers
                rest = parts[1] if len(parts) > 1 else b""
                # Text payload is usually at the tail
                chunks[key] = rest.decode("utf-8", errors="replace")
                
        offset += 12 + chunk_len
        
    return chunks


def inspect_c2pa_manifest(raw_bytes: bytes) -> Dict[str, Any]:
    """Inspects JUMBF / C2PA provenance boxes for digital authenticity and AI claims."""
    c2pa_detected = False
    ai_actions = []
    
    # Check for C2PA marker box or URN
    c2pa_urn = b"urn:uuid:d8c0e270-4328-444a-8f5b-167389a91d79"
    c2pa_sig = b"c2pa"
    
    if c2pa_urn in raw_bytes or c2pa_sig in raw_bytes:
        c2pa_detected = True
        
        # Scan for common C2PA actions / claims
        claim_patterns = [
            (b"c2pa.created", "Asset Created"),
            (b"c2pa.edited", "Asset Edited / Modified"),
            (b"c2pa.ai_generated", "Generative AI Creation Claim"),
            (b"c2pa.trainedAlgorithmicMedia", "Trained Algorithmic Media (AI Model Generated)"),
            (b"generativeAi", "Generative AI Process"),
            (b"Adobe Firefly", "Adobe Firefly Origin"),
            (b"Microsoft Designer", "Microsoft Copilot / Designer"),
        ]
        
        for pat, label in claim_patterns:
            if pat in raw_bytes:
                ai_actions.append(label)
                
    return {
        "c2pa_present": c2pa_detected,
        "actions_found": ai_actions
    }


def scan_ai_metadata(file_path: str) -> Dict[str, Any]:
    """Scans image metadata for explicit generative AI provenance and prompt dumps.
    
    Args:
        file_path: Path to target image.
        
    Returns:
        Dict with detection status, generator tool name, extracted prompt, and raw fields.
    """
    with open(file_path, "rb") as f:
        raw_bytes = f.read()
        
    is_ai_metadata_confirmed = False
    detected_tool = None
    extracted_prompt = None
    extracted_workflow = None
    evidence_tags: List[str] = []
    
    # 1. C2PA / JUMBF Provenance Check
    c2pa_info = inspect_c2pa_manifest(raw_bytes)
    if c2pa_info["c2pa_present"]:
        evidence_tags.append("C2PA Content Credentials manifest present")
        if any("AI" in a or "Algorithmic" in a for a in c2pa_info["actions_found"]):
            is_ai_metadata_confirmed = True
            detected_tool = "C2PA Provenance Manifest (AI-Claimed)"
            evidence_tags.extend(c2pa_info["actions_found"])
            
    # 2. PNG Text Chunk Prompt / Workflow extraction
    png_chunks = extract_png_text_chunks(raw_bytes)
    for key, val in png_chunks.items():
        lower_key = key.lower()
        # Automatic1111 parameters chunk
        if lower_key == "parameters":
            is_ai_metadata_confirmed = True
            detected_tool = "Stable Diffusion (Automatic1111 / WebUI)"
            extracted_prompt = val
            evidence_tags.append(f"PNG 'parameters' prompt chunk ({len(val)} chars)")
            
        elif lower_key in ("prompt", "workflow"):
            try:
                # Often JSON in ComfyUI
                json_data = json.loads(val)
                is_ai_metadata_confirmed = True
                detected_tool = "ComfyUI Node Workflow"
                extracted_workflow = json_data
                evidence_tags.append(f"ComfyUI JSON '{key}' node graph")
            except Exception:
                if len(val) > 20:
                    evidence_tags.append(f"PNG '{key}' text entry")
                    
        elif "midjourney" in val.lower():
            is_ai_metadata_confirmed = True
            detected_tool = "Midjourney"
            extracted_prompt = val
            evidence_tags.append("Midjourney signature in PNG metadata")
            
    # 3. EXIF and Raw text scan for AI software signatures
    for kw, label in KNOWN_AI_SOFTWARE:
        if kw.encode("utf-8") in raw_bytes:
            evidence_tags.append(f"Signature match: '{kw}' in file bytes")
            if not detected_tool:
                detected_tool = label
            # If not just a passing reference
            is_ai_metadata_confirmed = True
            
    # Calculate Metadata Risk Score (0 - 100)
    if is_ai_metadata_confirmed:
        score = 100.0
    elif c2pa_info["c2pa_present"]:
        score = 30.0  # C2PA without AI claims is authentic provenance
    else:
        score = 0.0
        
    return {
        "score": score,
        "is_ai_confirmed": is_ai_metadata_confirmed,
        "detected_generator": detected_tool,
        "extracted_prompt": extracted_prompt,
        "extracted_workflow_json": extracted_workflow,
        "c2pa_info": c2pa_info,
        "evidence_tags": evidence_tags
    }

