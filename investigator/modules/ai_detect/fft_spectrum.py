"""Frequency Domain FFT Spectrum Analyzer for AI / Deepfake Detection.

Generative models (GANs, Diffusion, Latent Autoencoders) leave distinct
structural artifacts in spatial frequency domain (2D FFT):
- Periodic grid spikes / harmonic frequency peaks (from upsampling & latent patch grids)
- Azimuthal / radial power spectrum deviations from natural 1/f^α decay law
- High-frequency cutoff anomalies
"""

from typing import Dict, Any, Tuple, List
import numpy as np
from PIL import Image
from scipy import ndimage


def compute_radial_profile(psd2d: np.ndarray, center: Tuple[int, int]) -> np.ndarray:
    """Computes the 1D radially averaged power spectrum profile (azimuthal average)."""
    y, x = np.indices(psd2d.shape)
    r = np.sqrt((x - center[0]) ** 2 + (y - center[1]) ** 2).astype(np.int32)
    
    # Calculate average value for each radial distance integer
    tbin = np.bincount(r.ravel(), psd2d.ravel())
    nr = np.bincount(r.ravel())
    radial_profile = tbin / np.maximum(nr, 1)
    return radial_profile


def analyze_fft_spectrum(
    image_arr: np.ndarray,
    crop_size: int = 512
) -> Dict[str, Any]:
    """Analyzes 2D Fast Fourier Transform (FFT) magnitude spectrum for generative artifacts.
    
    Args:
        image_arr: RGB uint8 numpy array.
        crop_size: Dimension of square center crop to normalize frequency resolution.
        
    Returns:
        Dict containing spectral metrics, peak anomalies, radial decay stats, and spectrum image.
    """
    # Convert to grayscale luminance
    if len(image_arr.shape) == 3 and image_arr.shape[2] >= 3:
        gray = 0.299 * image_arr[:, :, 0] + 0.587 * image_arr[:, :, 1] + 0.114 * image_arr[:, :, 2]
    else:
        gray = image_arr.astype(np.float32)
        
    h, w = gray.shape
    
    # Center crop to a power-of-two square (e.g. 512x512) for consistent FFT scale
    side = min(h, w, crop_size)
    # Ensure even dimension
    if side % 2 != 0:
        side -= 1
    start_y = (h - side) // 2
    start_x = (w - side) // 2
    cropped = gray[start_y:start_y+side, start_x:start_x+side].astype(np.float32)
    
    # Apply Hann window to eliminate edge discontinuity leakage in FFT
    hann_y = np.hanning(side)
    hann_x = np.hanning(side)
    window = np.outer(hann_y, hann_x)
    windowed = cropped * window
    
    # 2D FFT and shift zero-frequency component to center
    fft2 = np.fft.fft2(windowed)
    fft_shifted = np.fft.fftshift(fft2)
    magnitude = np.abs(fft_shifted)
    
    # Log-scaled power spectrum
    log_spectrum = np.log(magnitude + 1.0)
    
    center_y, center_x = side // 2, side // 2
    
    # 1. Radial Power Spectrum Analysis (1/f^α law)
    radial_profile = compute_radial_profile(log_spectrum, (center_x, center_y))
    # Exclude DC peak (r=0 to 3) and outer corners (r > side // 2)
    valid_r = np.arange(4, side // 2)
    valid_power = radial_profile[valid_r]
    
    # Fit linear slope in log-log space: log(Power) = -alpha * log(r) + c
    log_r = np.log(valid_r.astype(np.float32))
    log_p = np.log(np.maximum(valid_power, 1e-5))
    
    # Linear regression
    slope, intercept = np.polyfit(log_r, log_p, 1)
    predicted_p = slope * log_r + intercept
    # Mean squared error of fit: natural images fit tightly; AI models often have rippled deviations
    fit_residual_mse = float(np.mean((log_p - predicted_p) ** 2))
    alpha_decay = float(-slope)
    
    # 2. Harmonic Peak / Periodic Grid Artifact Detection
    # Deep generative upsampling creates localized isolated spikes in the frequency domain.
    # We find isolated peaks by subtracting a smooth background (Gaussian filter)
    smooth_spectrum = ndimage.gaussian_filter(log_spectrum, sigma=4.0)
    high_pass_spectrum = log_spectrum - smooth_spectrum
    
    # Mask out the low-frequency DC center area (radius < 15 px) where natural images are dense
    y_coords, x_coords = np.indices((side, side))
    dist_from_center = np.sqrt((x_coords - center_x) ** 2 + (y_coords - center_y) ** 2)
    high_pass_spectrum[dist_from_center < 15] = 0.0
    # Also ignore outer circle corner boundary
    high_pass_spectrum[dist_from_center >= (side // 2 - 2)] = 0.0
    
    # Statistical threshold for anomalous spectral spikes
    std_hp = float(np.std(high_pass_spectrum))
    mean_hp = float(np.mean(high_pass_spectrum))
    peak_threshold = mean_hp + (3.8 * std_hp)
    
    peak_indices = np.argwhere(high_pass_spectrum > peak_threshold)
    peak_count = len(peak_indices)
    
    # Measure symmetrical conjugate peak pairs (true periodic grid signals have conjugate symmetry: (dx, dy) and (-dx, -dy))
    symmetrical_peaks = 0
    for py, px in peak_indices[:50]:
        dy = py - center_y
        dx = px - center_x
        conj_y = center_y - dy
        conj_x = center_x - dx
        if 0 <= conj_y < side and 0 <= conj_x < side:
            if high_pass_spectrum[conj_y, conj_x] > (peak_threshold * 0.85):
                symmetrical_peaks += 1
                
    # 3. High-Frequency Energy Ratio
    high_freq_mask = dist_from_center > (side * 0.35)
    total_energy = float(np.sum(magnitude))
    high_energy = float(np.sum(magnitude[high_freq_mask]))
    high_freq_ratio = round((high_energy / (total_energy + 1e-6)) * 100, 2)
    
    # Calculate AI Spectral Anomaly Score (0 - 100)
    score = 0.0
    # Symmetrical peak spikes indicate GAN / Diffusion upsampler grid
    if symmetrical_peaks > 2:
        score += min(symmetrical_peaks * 8.0, 45.0)
    elif peak_count > 10:
        score += min(peak_count * 2.0, 30.0)
        
    # High radial fit residual (unnatural ripples in power distribution)
    if fit_residual_mse > 0.04:
        score += min((fit_residual_mse - 0.04) * 500.0, 35.0)
        
    # Decay factor alpha check: natural camera photos typically have alpha between 1.0 and 2.5
    if alpha_decay < 0.6 or alpha_decay > 2.8:
        score += 20.0
        
    final_score = round(min(max(score, 0.0), 100.0), 1)
    
    # Render normalized 2D FFT spectrum image for visual export
    norm_spec = (log_spectrum - np.min(log_spectrum)) / (np.max(log_spectrum) - np.min(log_spectrum) + 1e-6)
    spec_uint8 = (norm_spec * 255.0).astype(np.uint8)
    spec_pil = Image.fromarray(spec_uint8)
    
    return {
        "score": final_score,
        "spectral_peaks_count": peak_count,
        "symmetrical_grid_peaks": symmetrical_peaks,
        "alpha_decay_slope": round(alpha_decay, 3),
        "radial_fit_residual_mse": round(fit_residual_mse, 4),
        "high_frequency_ratio_pct": high_freq_ratio,
        "spectrum_pil": spec_pil,
    }

