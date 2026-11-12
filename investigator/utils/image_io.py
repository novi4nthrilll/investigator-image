"""Image I/O and Forensics Hash utilities.
"""

import hashlib
import os
from typing import Dict, Tuple, Any
from PIL import Image, ImageOps
import numpy as np


def compute_hashes(file_path: str) -> Dict[str, str]:
    """Compute standard cryptographic hashes for forensic integrity."""
    md5 = hashlib.md5()
    sha256 = hashlib.sha256()
    
    with open(file_path, "rb") as f:
        while chunk := f.read(65536):
            md5.update(chunk)
            sha256.update(chunk)
            
    return {
        "md5": md5.hexdigest(),
        "sha256": sha256.hexdigest(),
    }


def load_image_rgb(file_path: str) -> Tuple[Image.Image, np.ndarray]:
    """Loads an image, converts to RGB mode, and returns both PIL Image and NumPy ndarray."""
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"Image not found: {file_path}")
        
    img = Image.open(file_path)
    # Correct orientation if EXIF orientation tag exists
    img = ImageOps.exif_transpose(img) or img
    
    rgb_img = img.convert("RGB")
    arr = np.array(rgb_img, dtype=np.uint8)
    return rgb_img, arr


def get_image_info(file_path: str) -> Dict[str, Any]:
    """Inspects basic container and dimension attributes."""
    stat = os.stat(file_path)
    with Image.open(file_path) as img:
        width, height = img.size
        img_format = img.format or "UNKNOWN"
        mode = img.mode
        
    hashes = compute_hashes(file_path)
    return {
        "file_path": os.path.abspath(file_path),
        "file_name": os.path.basename(file_path),
        "file_size_bytes": stat.st_size,
        "dimensions": (width, height),
        "format": img_format,
        "mode": mode,
        "hashes": hashes,
    }


def save_heatmap_overlay(
    original_arr: np.ndarray,
    heatmap_norm: np.ndarray,
    output_path: str,
    alpha: float = 0.55
) -> str:
    """Overlays a single-channel normalized heatmap [0, 1] onto original image and saves it."""
    # Ensure heatmap is [0, 1]
    hm = np.clip(heatmap_norm, 0.0, 1.0)
    
    # Simple turbo-like colormap generation in NumPy:
    # low = blue/cyan, mid = green/yellow, high = bright red/magenta
    r = np.clip(1.5 * hm, 0, 1)
    g = np.clip(1.5 * (1.0 - np.abs(hm - 0.5) * 2), 0, 1)
    b = np.clip(1.5 * (1.0 - hm), 0, 1)
    colormap = (np.stack([r, g, b], axis=-1) * 255).astype(np.uint8)
    
    blended = (original_arr.astype(np.float32) * (1 - alpha) + colormap.astype(np.float32) * alpha).astype(np.uint8)
    out_img = Image.fromarray(blended)
    os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
    out_img.save(output_path)
    return output_path

