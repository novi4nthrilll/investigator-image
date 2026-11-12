"""Chroma Distribution & Gradient Statistical Auditor.

Analyzes color channel covariance, YCbCr chroma transitions, and saturation dynamics.
Diffusion and GAN outputs often display distinct chroma clipping and oversmooth
gradient properties compared to optical camera sensors.
"""

from typing import Dict, Any
import numpy as np


def analyze_chroma_statistics(image_arr: np.ndarray) -> Dict[str, Any]:
    """Analyzes chroma channel characteristics and saturation distributions.
    
    Args:
        image_arr: RGB uint8 numpy array with shape (H, W, 3).
        
    Returns:
        Dict with chroma statistics, saturation extremes, and anomaly score.
    """
    img_f = image_arr.astype(np.float32)
    r = img_f[:, :, 0]
    g = img_f[:, :, 1]
    b = img_f[:, :, 2]
    
    # 1. Convert to YCbCr space
    # Y  =  0.299*R + 0.587*G + 0.114*B
    # Cb = -0.1687*R - 0.3313*G + 0.5*B + 128
    # Cr =  0.5*R - 0.4187*G - 0.0813*B + 128
    cb = -0.168736 * r - 0.331264 * g + 0.5 * b + 128.0
    cr = 0.5 * r - 0.418688 * g - 0.081312 * b + 128.0
    
    cb_std = float(np.std(cb))
    cr_std = float(np.std(cr))
    chroma_var = (cb_std ** 2 + cr_std ** 2) / 2.0
    
    # 2. Saturation Channel (HSV)
    max_c = np.maximum(np.maximum(r, g), b)
    min_c = np.minimum(np.minimum(r, g), b)
    delta = max_c - min_c
    
    # Saturation = delta / max_c
    sat = np.zeros_like(max_c)
    mask = max_c > 0.0
    sat[mask] = delta[mask] / max_c[mask]
    
    mean_sat = float(np.mean(sat))
    # Extreme saturation ratio (pixels with saturation > 0.90)
    extreme_sat_pct = round(float(np.count_nonzero(sat > 0.90)) / sat.size * 100, 2)
    
    # 3. Local Gradient Smoothness (Total Variation)
    # Generative AI flat areas are often mathematically over-smooth without sensor grain
    diff_y = np.abs(np.diff(img_f, axis=0))
    diff_x = np.abs(np.diff(img_f, axis=1))
    grad_norm = np.mean(diff_y) + np.mean(diff_x)
    
    # Anomaly scoring
    score = 0.0
    # AI images often have very high extreme saturation ratio (> 25%)
    if extreme_sat_pct > 25.0:
        score += min((extreme_sat_pct - 25.0) * 1.5, 35.0)
        
    # Unnatural chroma variance
    if chroma_var > 1200.0 or chroma_var < 80.0:
        score += 25.0
        
    final_score = round(min(max(score, 0.0), 100.0), 1)
    
    return {
        "score": final_score,
        "mean_saturation": round(mean_sat, 3),
        "extreme_saturation_pct": extreme_sat_pct,
        "chroma_variance": round(chroma_var, 2),
        "gradient_smoothness": round(float(grad_norm), 2),
    }

