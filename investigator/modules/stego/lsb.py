"""Least Significant Bit (LSB) Steganography & Bitplane Entropy Engine.

Performs Chi-Square (χ²) PoV attack, bitplane entropy profiling,
and bitplane visualization to detect hidden encrypted or compressed data.
"""

from typing import Dict, Any, Tuple
import math
import numpy as np
from PIL import Image


def calculate_bit_entropy(bit_array: np.ndarray) -> float:
    """Calculates Shannon entropy of binary bits [0, 1]."""
    total = bit_array.size
    if total == 0:
        return 0.0
    p1 = float(np.count_nonzero(bit_array)) / total
    p0 = 1.0 - p1
    if p0 == 0.0 or p1 == 0.0:
        return 0.0
    return round(-(p0 * math.log2(p0) + p1 * math.log2(p1)), 4)


def chi_square_pov_attack(channel_data: np.ndarray) -> Tuple[float, float]:
    """Applies the classic Westfeld & Pfitzmann Chi-Square test on Pairs of Values (PoVs).
    
    In natural images, adjacent pixel counts (2k and 2k+1) differ. LSB substitution
    equalizes them. Chi-square statistic measures this equalization.
    
    Returns:
        (chi_square_stat, p_value_stego_probability)
    """
    flat = channel_data.flatten()
    hist, _ = np.histogram(flat, bins=256, range=(0, 256))
    
    chi_square = 0.0
    degrees_of_freedom = 0
    
    # Analyze pairs: (0,1), (2,3), ..., (254,255)
    for k in range(0, 256, 2):
        n_2k = hist[k]
        n_2k1 = hist[k + 1]
        pair_sum = n_2k + n_2k1
        
        # Only evaluate non-empty pairs to avoid instability
        if pair_sum > 5:
            expected = pair_sum / 2.0
            # Observed differences from expected equal distribution
            chi_square += ((n_2k - expected) ** 2) / expected
            chi_square += ((n_2k1 - expected) ** 2) / expected
            degrees_of_freedom += 1
            
    if degrees_of_freedom < 10:
        return 0.0, 0.0
        
    # Under LSB steganography, chi-square is very LOW because counts are equalized.
    # We normalize to an empirical probability of stego presence
    norm_chi = chi_square / degrees_of_freedom
    # A natural image has high variance between 2k and 2k+1 (norm_chi > 1.5).
    # Stego images have norm_chi approaching 0.
    if norm_chi < 0.5:
        p_val = 0.95
    elif norm_chi < 1.0:
        p_val = max(0.0, 1.0 - (norm_chi - 0.5))
    else:
        p_val = max(0.0, 0.3 - (norm_chi - 1.0) * 0.1)
        
    return round(float(norm_chi), 3), round(float(p_val), 3)


def analyze_lsb_stego(image_arr: np.ndarray) -> Dict[str, Any]:
    """Analyzes bitplane 0 (LSB) across all RGB channels for steganographic anomalies.
    
    Args:
        image_arr: RGB uint8 numpy array.
        
    Returns:
        Dict with bit entropy, chi-square stats, and steganography probability score.
    """
    channels = ["Red", "Green", "Blue"]
    channel_results = {}
    channel_entropies = []
    stego_probs = []
    
    for idx, name in enumerate(channels):
        if idx >= image_arr.shape[2]:
            continue
        c_data = image_arr[:, :, idx]
        
        # Extract LSB (bit 0)
        lsb_bits = c_data & 1
        entropy = calculate_bit_entropy(lsb_bits)
        one_ratio = round(float(np.count_nonzero(lsb_bits)) / lsb_bits.size, 4)
        
        chi_stat, p_stego = chi_square_pov_attack(c_data)
        
        channel_results[name] = {
            "lsb_entropy": entropy,
            "bit1_ratio": one_ratio,
            "chi_square_ratio": chi_stat,
            "stego_probability": p_stego
        }
        channel_entropies.append(entropy)
        stego_probs.append(p_stego)
        
    avg_entropy = float(np.mean(channel_entropies)) if channel_entropies else 0.0
    max_stego_prob = max(stego_probs) if stego_probs else 0.0
    
    # Calculate Stego Risk Score (0 - 100)
    # High bit-0 entropy (> 0.99) combined with high chi-square equalization probability
    risk_score = 0.0
    if avg_entropy > 0.985:
        risk_score += (avg_entropy - 0.985) * 2000  # Scale high entropy
    risk_score += max_stego_prob * 60.0
    
    final_score = round(min(max(risk_score, 0.0), 100.0), 1)
    
    return {
        "score": final_score,
        "average_lsb_entropy": round(avg_entropy, 4),
        "max_stego_probability": round(max_stego_prob, 3),
        "channels": channel_results,
    }


def extract_bitplane_image(image_arr: np.ndarray, bit_index: int = 0) -> Image.Image:
    """Extracts a specific bitplane (default: bit 0 LSB) and scales to full 0/255 contrast."""
    bit_mask = 1 << bit_index
    extracted = ((image_arr & bit_mask) >> bit_index) * 255
    return Image.fromarray(extracted.astype(np.uint8))

