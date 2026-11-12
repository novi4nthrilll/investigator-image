"""Error Level Analysis (ELA) Engine.

Identifies compression anomalies by measuring differences after re-saving at known JPEG quality levels.
Modified or spliced regions typically exhibit noticeably higher or lower error levels compared to
the surrounding background.
"""

import io
from typing import Dict, Any, List, Tuple
from PIL import Image, ImageChops, ImageEnhance
import numpy as np


def perform_ela(
    image: Image.Image,
    quality: int = 95,
    scale: int = 15,
    grid_size: int = 32
) -> Dict[str, Any]:
    """Performs Error Level Analysis (ELA) on an image.
    
    Args:
        image: PIL Image in RGB mode.
        quality: JPEG recompression quality (default: 95).
        scale: Multiplier for difference contrast (default: 15).
        grid_size: Tile size in pixels for spatial anomaly scanning.
        
    Returns:
        Dict with metrics, anomaly score, flagged regions, and PIL difference image.
    """
    rgb_img = image.convert("RGB")
    
    # Recompress to temporary in-memory buffer
    buffer = io.BytesIO()
    rgb_img.save(buffer, "JPEG", quality=quality)
    buffer.seek(0)
    recompressed = Image.open(buffer).convert("RGB")
    
    # Calculate absolute difference
    diff = ImageChops.difference(rgb_img, recompressed)
    
    # Enhance difference for visual representation
    enhanced = ImageEnhance.Brightness(diff).enhance(scale)
    
    # Numerical analysis on difference array
    diff_arr = np.array(diff, dtype=np.float32)  # shape: (H, W, 3)
    channel_diff = np.mean(diff_arr, axis=2)     # shape: (H, W)
    
    global_mean = float(np.mean(channel_diff))
    global_std = float(np.std(channel_diff))
    global_max = float(np.max(channel_diff))
    
    # Spatial grid anomaly detection
    h, w = channel_diff.shape
    suspicious_regions: List[Dict[str, Any]] = []
    block_scores = []
    
    # Avoid zero division
    effective_std = global_std if global_std > 0.05 else 0.05
    
    for y in range(0, h - grid_size + 1, grid_size):
        for x in range(0, w - grid_size + 1, grid_size):
            patch = channel_diff[y:y+grid_size, x:x+grid_size]
            patch_mean = float(np.mean(patch))
            patch_std = float(np.std(patch))
            
            # Z-score of patch mean compared to global mean
            z_score = abs(patch_mean - global_mean) / effective_std
            block_scores.append(z_score)
            
            # If patch deviates noticeably from global compression profile
            if z_score > 3.0:
                suspicious_regions.append({
                    "bbox": (x, y, x + grid_size, y + grid_size),
                    "mean_error": round(patch_mean, 2),
                    "z_score": round(z_score, 2),
                    "relative_intensity": "higher" if patch_mean > global_mean else "lower"
                })
                
    # Heuristic score calculation (0 - 100)
    # Factor 1: Percentage of anomalous grid tiles
    total_tiles = max(1, len(block_scores))
    anom_pct = (len(suspicious_regions) / total_tiles) * 100
    
    # Factor 2: Peak Z-Score
    max_z = max(block_scores) if block_scores else 0.0
    
    # Compute combined risk score
    raw_score = (min(anom_pct * 8.0, 50.0)) + (min(max_z * 8.0, 50.0))
    ela_score = round(min(max(raw_score, 0.0), 100.0), 1)
    
    return {
        "score": ela_score,
        "global_mean": round(global_mean, 3),
        "global_std": round(global_std, 3),
        "global_max": round(global_max, 3),
        "anomalous_blocks_count": len(suspicious_regions),
        "total_blocks": total_tiles,
        "anomaly_percentage": round(anom_pct, 2),
        "suspicious_regions": suspicious_regions[:10],  # Top 10 flagged regions
        "ela_image": enhanced,
        "diff_matrix": channel_diff,
    }

