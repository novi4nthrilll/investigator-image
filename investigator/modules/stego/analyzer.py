"""Unified Steganography & Malicious Payload Analyzer Orchestrator.

Combines trailing bytes / polyglot detection, LSB entropy analysis,
and metadata payload auditing into a single comprehensive forensic verdict.
"""

from typing import Dict, Any, Optional, List
import os
from PIL import Image

from investigator.utils.image_io import load_image_rgb, get_image_info
from investigator.modules.stego.overlay import scan_trailing_bytes, carve_payloads
from investigator.modules.stego.lsb import analyze_lsb_stego, extract_bitplane_image
from investigator.modules.stego.metadata_audit import audit_metadata


class StegoAnalyzer:
    """Orchestrates steganography detection and hidden payload inspection."""

    def analyze(
        self,
        file_path: str,
        extract_dir: Optional[str] = None,
        dump_lsb_path: Optional[str] = None
    ) -> Dict[str, Any]:
        """Runs full steganography and payload audit suite on target image."""
        info = get_image_info(file_path)
        pil_img, img_arr = load_image_rgb(file_path)
        
        # 1. Overlay & Polyglot Trailing Bytes Check
        overlay_res = scan_trailing_bytes(file_path)
        
        # 2. LSB Steganography & Bitplane Entropy
        lsb_res = analyze_lsb_stego(img_arr)
        
        # 3. EXIF & Metadata Security Audit
        meta_res = audit_metadata(file_path)
        
        # Carving actions if requested
        carved_files: List[str] = []
        if extract_dir:
            carved_files = carve_payloads(overlay_res, extract_dir)
            
        # Dump LSB bitplane visual image if requested
        saved_lsb_img = None
        if dump_lsb_path:
            lsb_img = extract_bitplane_image(img_arr, bit_index=0)
            os.makedirs(os.path.dirname(os.path.abspath(dump_lsb_path)), exist_ok=True)
            lsb_img.save(dump_lsb_path)
            saved_lsb_img = dump_lsb_path
            
        # Composite Stego / Payload Risk Score
        # Overlay/polyglot and malicious metadata carry heavy weights
        w_overlay = 0.45 * overlay_res["score"]
        w_lsb = 0.30 * lsb_res["score"]
        w_meta = 0.25 * meta_res["score"]
        
        composite_score = round(min(w_overlay + w_lsb + w_meta, 100.0), 1)
        
        # If active executable or shell script signature is found in overlay, elevate to CRITICAL
        has_executable = any("Executable" in p.get("type", "") or "ELF" in p.get("type", "") or "Script" in p.get("type", "") 
                             for p in overlay_res.get("detected_payloads", []))
        if has_executable:
            composite_score = max(composite_score, 85.0)
            
        # Classify verdict
        if composite_score >= 70.0:
            verdict = "CRITICAL / MALICIOUS PAYLOAD DETECTED"
            risk_color = "red"
        elif composite_score >= 40.0:
            verdict = "SUSPICIOUS / HIDDEN DATA DETECTED"
            risk_color = "yellow"
        elif composite_score >= 15.0:
            verdict = "LOW RISK / MINOR IRREGULARITIES"
            risk_color = "cyan"
        else:
            verdict = "CLEAN / NO STEGO DETECTED"
            risk_color = "green"
            
        # Synthesize forensic findings
        findings = []
        if overlay_res["has_trailing_data"]:
            findings.append(
                f"Trailing overlay detected: {overlay_res['trailing_bytes_count']} bytes appended after EOF "
                f"(Entropy: {overlay_res['trailing_entropy']}/8.0)."
            )
            for p in overlay_res["detected_payloads"]:
                findings.append(f"-> Signature identified: {p['type']} at offset {p['absolute_file_offset']}.")
        else:
            findings.append("File container strictly terminates at official image EOF marker.")
            
        if lsb_res["score"] > 40:
            findings.append(
                f"LSB bitplane 0 exhibits abnormal high entropy ({lsb_res['average_lsb_entropy']}) and Chi-Square distribution, "
                f"indicating probable encrypted/compressed stego payload."
            )
        else:
            findings.append("LSB bitplane entropy is consistent with natural camera sensor noise.")
            
        if meta_res["findings"]:
            findings.append(f"Metadata audit flagged {len(meta_res['findings'])} suspicious tag(s)/comment(s).")
            for f in meta_res["findings"][:3]:
                findings.append(f"-> [{f['severity']}] {f['issue']} in '{f['tag']}'.")
        else:
            findings.append("Metadata tags and comments appear benign with no injection patterns.")
            
        return {
            "image_info": info,
            "overall_score": composite_score,
            "verdict": verdict,
            "risk_color": risk_color,
            "findings": findings,
            "modules": {
                "overlay": {
                    "score": overlay_res["score"],
                    "has_trailing": overlay_res["has_trailing_data"],
                    "trailing_bytes": overlay_res["trailing_bytes_count"],
                    "entropy": overlay_res["trailing_entropy"],
                    "payloads": overlay_res["detected_payloads"]
                },
                "lsb": {
                    "score": lsb_res["score"],
                    "avg_entropy": lsb_res["average_lsb_entropy"],
                    "stego_probability": lsb_res["max_stego_probability"],
                    "channels": lsb_res["channels"]
                },
                "metadata": {
                    "score": meta_res["score"],
                    "tags_count": meta_res["total_tags_found"],
                    "findings": meta_res["findings"]
                }
            },
            "carved_files": carved_files,
            "dumped_lsb_path": saved_lsb_img
        }

