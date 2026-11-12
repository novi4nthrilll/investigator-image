"""Unified Tamper & Manipulation Analyzer Orchestrator.

Combines ELA, Noise Inconsistency, Copy-Move detection, and Gradient continuity
into an integrated forensic verdict.
"""

from typing import Dict, Any, Optional
import os
import numpy as np
from PIL import Image

from investigator.utils.image_io import load_image_rgb, get_image_info, save_heatmap_overlay
from investigator.modules.tamper.ela import perform_ela
from investigator.modules.tamper.noise import analyze_noise_inconsistency
from investigator.modules.tamper.copymove import detect_copy_move


class TamperAnalyzer:
    """Orchestrates comprehensive tampering and image manipulation analysis."""
    
    def __init__(self, ela_quality: int = 95, ela_scale: int = 15):
        self.ela_quality = ela_quality
        self.ela_scale = ela_scale

    def analyze(
        self,
        file_path: str,
        output_heatmap: Optional[str] = None
    ) -> Dict[str, Any]:
        """Runs full tampering suite on target image."""
        info = get_image_info(file_path)
        pil_img, img_arr = load_image_rgb(file_path)
        
        # 1. Error Level Analysis
        ela_res = perform_ela(
            pil_img,
            quality=self.ela_quality,
            scale=self.ela_scale
        )
        
        # 2. Sensor Noise Inconsistency
        noise_res = analyze_noise_inconsistency(img_arr)
        
        # 3. Copy-Move Forgery Detection
        cmfd_res = detect_copy_move(img_arr)
        
        # Calculate composite score with weighted indicators
        # Weights: ELA (35%), Noise (35%), Copy-Move (30%)
        # Note: If copy-move is strongly detected, it provides near-certain proof of tampering
        w_ela = 0.35 * ela_res["score"]
        w_noise = 0.35 * noise_res["score"]
        w_cmfd = 0.30 * cmfd_res["score"]
        
        composite_score = round(min(w_ela + w_noise + w_cmfd, 100.0), 1)
        if cmfd_res["detected"] and composite_score < 70.0:
            composite_score = max(composite_score, 75.0)
            
        # Determine verdict classification
        if composite_score >= 70.0:
            verdict = "CRITICAL / TAMPERED"
            risk_color = "red"
        elif composite_score >= 45.0:
            verdict = "SUSPICIOUS / ELEVATED RISK"
            risk_color = "yellow"
        elif composite_score >= 20.0:
            verdict = "LOW RISK / MINOR ANOMALIES"
            risk_color = "cyan"
        else:
            verdict = "AUTHENTIC / NO OBVIOUS TAMPERING"
            risk_color = "green"
            
        # Synthesize natural language findings
        findings = []
        if ela_res["score"] > 40:
            findings.append(
                f"ELA detected {ela_res['anomalous_blocks_count']} blocks with significant compression discrepancies "
                f"({ela_res['anomaly_percentage']}% of image area), indicating potential splicing or localized resaving."
            )
        else:
            findings.append("ELA compression profile is relatively uniform across the canvas.")
            
        if noise_res["score"] > 40:
            findings.append(
                f"High-frequency noise variance shows {noise_res['anomalous_blocks']} deviant blocks. "
                "Regions with mismatched noise floors may originate from an external photo or smoothing filter."
            )
        else:
            findings.append("Sensor noise residual appears statistically consistent with a single capture.")
            
        if cmfd_res["detected"]:
            findings.append(
                f"Copy-Move cloning detected: {cmfd_res['matches_count']} matching block pairs found across "
                f"{cmfd_res['clusters_count']} rigid translation shift vectors."
            )
        else:
            findings.append("No repetitive identical clone-stamp clusters detected.")
            
        # Optional visual heatmap generation
        saved_heatmap = None
        if output_heatmap:
            # Combine ELA diff and noise residual into normalized heatmap
            diff_mat = ela_res["diff_matrix"]
            max_d = np.max(diff_mat) if np.max(diff_mat) > 0 else 1.0
            norm_ela = diff_mat / max_d
            
            # Save overlay image
            saved_heatmap = save_heatmap_overlay(img_arr, norm_ela, output_heatmap)
            
        return {
            "image_info": info,
            "overall_score": composite_score,
            "verdict": verdict,
            "risk_color": risk_color,
            "findings": findings,
            "modules": {
                "ela": {
                    "score": ela_res["score"],
                    "global_mean": ela_res["global_mean"],
                    "anomalous_blocks": ela_res["anomalous_blocks_count"],
                    "anomaly_pct": ela_res["anomaly_percentage"],
                    "regions": ela_res["suspicious_regions"],
                },
                "noise": {
                    "score": noise_res["score"],
                    "median_variance": noise_res["median_variance"],
                    "anomalous_blocks": noise_res["anomalous_blocks"],
                    "anomaly_pct": noise_res["anomaly_percentage"],
                    "regions": noise_res["flagged_regions"],
                },
                "copy_move": {
                    "score": cmfd_res["score"],
                    "detected": cmfd_res["detected"],
                    "matches_count": cmfd_res["matches_count"],
                    "clusters": cmfd_res["shift_clusters"],
                }
            },
            "heatmap_path": saved_heatmap
        }

