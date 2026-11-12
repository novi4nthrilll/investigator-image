"""Unified AI-Generated & Deepfake Authenticator Orchestrator.

Combines 2D FFT frequency spectrum analysis, C2PA / metadata provenance,
and chroma distribution statistics into an integrated AI authenticity verdict.
"""

from typing import Dict, Any, Optional
import os
from PIL import Image

from investigator.utils.image_io import load_image_rgb, get_image_info
from investigator.modules.ai_detect.fft_spectrum import analyze_fft_spectrum
from investigator.modules.ai_detect.c2pa_metadata import scan_ai_metadata
from investigator.modules.ai_detect.chroma_stats import analyze_chroma_statistics


class AIAuthenticator:
    """Orchestrates comprehensive AI-generated and synthetic media authentication."""

    def analyze(
        self,
        file_path: str,
        fft_dump_path: Optional[str] = None,
        extract_prompt_path: Optional[str] = None
    ) -> Dict[str, Any]:
        """Runs full AI generation detection suite on target image."""
        info = get_image_info(file_path)
        pil_img, img_arr = load_image_rgb(file_path)
        
        # 1. Frequency Domain FFT Spectrum Analysis
        fft_res = analyze_fft_spectrum(img_arr)
        
        # 2. C2PA Provenance & Generator Metadata Scanner
        meta_res = scan_ai_metadata(file_path)
        
        # 3. Chroma & Saturation Distribution
        chroma_res = analyze_chroma_statistics(img_arr)
        
        # Export FFT Spectrum image if requested
        saved_fft_dump = None
        if fft_dump_path:
            os.makedirs(os.path.dirname(os.path.abspath(fft_dump_path)), exist_ok=True)
            fft_res["spectrum_pil"].save(fft_dump_path)
            saved_fft_dump = fft_dump_path
            
        # Export extracted prompt or workflow if requested
        saved_prompt_path = None
        if extract_prompt_path:
            prompt_content = meta_res.get("extracted_prompt")
            if not prompt_content and meta_res.get("extracted_workflow_json"):
                prompt_content = str(meta_res.get("extracted_workflow_json"))
            if prompt_content:
                os.makedirs(os.path.dirname(os.path.abspath(extract_prompt_path)), exist_ok=True)
                with open(extract_prompt_path, "w", encoding="utf-8") as f:
                    f.write(prompt_content)
                saved_prompt_path = extract_prompt_path
                
        # Calculate Composite AI Generation Score
        # If metadata / C2PA proves AI origin, score is 100%
        if meta_res["is_ai_confirmed"]:
            composite_score = 100.0
            verdict = "CONFIRMED AI-GENERATED (PROVENANCE / METADATA)"
            risk_color = "red"
        else:
            w_fft = 0.65 * fft_res["score"]
            w_chroma = 0.35 * chroma_res["score"]
            raw_score = w_fft + w_chroma
            composite_score = round(min(max(raw_score, 0.0), 100.0), 1)
            
            if composite_score >= 70.0:
                verdict = "HIGH PROBABILITY AI-GENERATED"
                risk_color = "red"
            elif composite_score >= 40.0:
                verdict = "SUSPICIOUS / SYNTHETIC TRACES DETECTED"
                risk_color = "yellow"
            elif composite_score >= 20.0:
                verdict = "LOW RISK / MINOR ARTIFACTS"
                risk_color = "cyan"
            else:
                verdict = "ORGANIC / CAMERA CAPTURE (AUTHENTIC)"
                risk_color = "green"
                
        # Synthesize forensic findings
        findings = []
        if meta_res["is_ai_confirmed"]:
            findings.append(f"Explicit AI Provenance: Identified as {meta_res['detected_generator']}.")
            if meta_res["extracted_prompt"]:
                findings.append(f"Extracted Generation Prompt: \"{meta_res['extracted_prompt'][:100]}...\"")
        else:
            findings.append("No explicit generative metadata or C2PA AI claims detected.")
            
        if fft_res["symmetrical_grid_peaks"] > 0:
            findings.append(
                f"2D FFT Frequency Spectrum revealed {fft_res['symmetrical_grid_peaks']} symmetrical conjugate peak pairs, "
                "characteristic of artificial upsampling grids and latent diffusion patches."
            )
        elif fft_res["spectral_peaks_count"] > 5:
            findings.append(f"2D FFT detected {fft_res['spectral_peaks_count']} localized spectral spikes.")
        else:
            findings.append("2D FFT frequency spectrum displays smooth, natural power-law falloff.")
            
        if chroma_res["extreme_saturation_pct"] > 20.0:
            findings.append(
                f"Elevated extreme chroma saturation ({chroma_res['extreme_saturation_pct']}%), "
                "typical of synthetic color grading in modern generative models."
            )
        else:
            findings.append("Chroma distribution and variance are consistent with optical sensor physics.")
            
        return {
            "image_info": info,
            "overall_score": composite_score,
            "verdict": verdict,
            "risk_color": risk_color,
            "findings": findings,
            "modules": {
                "fft": {
                    "score": fft_res["score"],
                    "peaks": fft_res["spectral_peaks_count"],
                    "symmetrical_grid_peaks": fft_res["symmetrical_grid_peaks"],
                    "alpha_slope": fft_res["alpha_decay_slope"],
                    "radial_residual_mse": fft_res["radial_fit_residual_mse"],
                    "high_freq_ratio": fft_res["high_frequency_ratio_pct"],
                },
                "metadata": {
                    "score": meta_res["score"],
                    "is_confirmed": meta_res["is_ai_confirmed"],
                    "generator": meta_res["detected_generator"],
                    "has_prompt": bool(meta_res["extracted_prompt"]),
                    "evidence": meta_res["evidence_tags"]
                },
                "chroma": {
                    "score": chroma_res["score"],
                    "extreme_sat_pct": chroma_res["extreme_saturation_pct"],
                    "chroma_variance": chroma_res["chroma_variance"]
                }
            },
            "fft_dump_path": saved_fft_dump,
            "prompt_dump_path": saved_prompt_path
        }

