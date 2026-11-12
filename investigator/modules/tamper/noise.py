"""Noise Inconsistency & Sensor Noise Residual Analysis.

Every camera sensor and optical capture creates a distinct noise footprint (PRNU / ISO noise).
When an element is cut-and-pasted or modified, the local noise variance often diverges
from the camera's baseline sensor noise floor.
"""

from typing import Dict, Any, List
import numpy as np
from scipy import ndimage


def analyze_noise_inconsistency(
    image_arr: np.ndarray,
    block_size: int = 32
) -> Dict[str, Any]:
    """Extracts high-frequency noise residuals and analyzes spatial variance consistency.
    
    Args:
        image_arr: RGB image array with shape (H, W, 3).
        block_size: Window size in pixels for local noise variance estimation.
        
    Returns:
        Dict containing noise variance stats, anomaly score, and flagged regions.
    """
    # Convert to grayscale luminance
    if len(image_arr.shape) == 3 and image_arr.shape[2] >= 3:
        gray = 0.299 * image_arr[:, :, 0] + 0.587 * image_arr[:, :, 1] + 0.114 * image_arr[:, :, 2]
    else:
        gray = image_arr.astype(np.float32)
        
    # High-pass filter using median filter residual: Noise = |Image - Median(Image)|
    denoised = ndimage.median_filter(gray, size=3)
    noise_residual = np.abs(gray - denoised)
    
    h, w = gray.shape
    block_variances = []
    block_coords = []
    
    for y in range(0, h - block_size + 1, block_size):
        for x in range(0, w - block_size + 1, block_size):
            block = noise_residual[y:y+block_size, x:x+block_size]
            var = float(np.var(block))
            block_variances.append(var)
            block_coords.append((x, y, x + block_size, y + block_size))
            
    if not block_variances:
        return {
            "score": 0.0,
            "median_variance": 0.0,
            "variance_iqr": 0.0,
            "anomalous_blocks": 0,
            "flagged_regions": [],
            "residual_matrix": noise_residual,
        }
        
    bv = np.array(block_variances)
    median_var = float(np.median(bv))
    q25 = float(np.percentile(bv, 25))
    q75 = float(np.percentile(bv, 75))
    iqr = max(q75 - q25, 0.01)
    
    # Identify outliers using robust IQR bounds: [Q25 - 2.5*IQR, Q75 + 2.5*IQR]
    upper_bound = q75 + (2.5 * iqr)
    lower_bound = max(0.0, q25 - (2.5 * iqr))
    
    suspicious_regions: List[Dict[str, Any]] = []
    for (x1, y1, x2, y2), var in zip(block_coords, block_variances):
        if var > upper_bound or var < lower_bound:
            deviation_factor = round(var / (median_var + 1e-5), 2)
            suspicious_regions.append({
                "bbox": (x1, y1, x2, y2),
                "variance": round(var, 3),
                "deviation_ratio": deviation_factor,
                "type": "unusually_noisy" if var > upper_bound else "unusually_smooth_or_inpainted"
            })
            
    total_blocks = len(block_variances)
    anomaly_pct = (len(suspicious_regions) / total_blocks) * 100
    
    # Calculate noise inconsistency risk score (0-100)
    # Higher anomaly percentage or extreme variance ratios increase risk score
    max_ratio = max([r["deviation_ratio"] for r in suspicious_regions], default=1.0)
    score_pct_factor = min(anomaly_pct * 7.0, 50.0)
    score_ratio_factor = min(max_ratio * 5.0, 50.0)
    noise_score = round(min(score_pct_factor + score_ratio_factor, 100.0), 1)
    
    return {
        "score": noise_score,
        "median_variance": round(median_var, 3),
        "variance_iqr": round(iqr, 3),
        "total_blocks": total_blocks,
        "anomalous_blocks": len(suspicious_regions),
        "anomaly_percentage": round(anomaly_pct, 2),
        "flagged_regions": suspicious_regions[:10],
        "residual_matrix": noise_residual,
    }

