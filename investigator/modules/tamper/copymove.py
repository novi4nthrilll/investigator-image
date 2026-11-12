"""Copy-Move Forgery Detection (CMFD) Engine.

Detects cloned regions within the same image by extracting local block feature vectors,
matching similar blocks, and clustering identical spatial shift vectors (rigid translation).
"""

from typing import Dict, Any, List, Tuple
from collections import defaultdict
import numpy as np


def detect_copy_move(
    image_arr: np.ndarray,
    block_size: int = 16,
    stride: int = 8,
    similarity_thresh: float = 0.95,
    min_distance: int = 32,
    min_cluster_size: int = 4
) -> Dict[str, Any]:
    """Detects copy-move / clone-stamp forgery using shift-vector clustering.
    
    Args:
        image_arr: RGB image array.
        block_size: Size of square patch in pixels (e.g., 16x16).
        stride: Step size between patches (e.g., 8 px).
        similarity_thresh: Normalized correlation threshold for considering blocks identical.
        min_distance: Minimum spatial distance between candidate patches to prevent adjacent self-matches.
        min_cluster_size: Minimum number of matched block pairs sharing the same shift vector.
        
    Returns:
        Dict with detection status, risk score, matched pairs, and dominant shift vectors.
    """
    # Convert to grayscale
    if len(image_arr.shape) == 3 and image_arr.shape[2] >= 3:
        gray = (0.299 * image_arr[:, :, 0] + 0.587 * image_arr[:, :, 1] + 0.114 * image_arr[:, :, 2]).astype(np.float32)
    else:
        gray = image_arr.astype(np.float32)
        
    h, w = gray.shape
    
    # Resize down if image is huge to keep CLI execution under 2 seconds
    scale = 1.0
    max_dim = 800
    if max(h, w) > max_dim:
        scale = max_dim / max(h, w)
        new_w = int(w * scale)
        new_h = int(h * scale)
        # Quick nearest/area downsample
        y_indices = (np.linspace(0, h - 1, new_h)).astype(int)
        x_indices = (np.linspace(0, w - 1, new_w)).astype(int)
        gray = gray[np.ix_(y_indices, x_indices)]
        h, w = gray.shape

    blocks = []
    coords = []
    
    # Extract blocks and feature representations
    for y in range(0, h - block_size + 1, stride):
        for x in range(0, w - block_size + 1, stride):
            patch = gray[y:y+block_size, x:x+block_size]
            std = np.std(patch)
            # Skip flat/featureless patches (e.g. pure white/black solid background)
            if std < 5.0:
                continue
                
            # Normalize patch to zero mean, unit variance for illumination invariance
            norm_patch = (patch - np.mean(patch)) / (std + 1e-6)
            
            # Simple 8-dimensional DCT-like spatial mean representation
            # Sub-divide 16x16 into 4x4 sub-regions
            sub = norm_patch.reshape(4, 4, 4, 4).mean(axis=(1, 3)).flatten()
            
            blocks.append(sub)
            coords.append((x, y))
            
    if len(blocks) < 10:
        return {
            "score": 0.0,
            "detected": False,
            "matches_count": 0,
            "shift_clusters": [],
            "matched_pairs": [],
        }
        
    blocks_arr = np.array(blocks, dtype=np.float32)
    num_blocks = len(blocks_arr)
    
    # Lexicographically sort block features
    # Quantize vectors to discrete bins for hashing/grouping
    quantized = np.round(blocks_arr * 4.0).astype(np.int32)
    hash_buckets = defaultdict(list)
    for idx, q_vec in enumerate(quantized):
        key = tuple(q_vec)
        hash_buckets[key].append(idx)
        
    matched_pairs = []
    shift_vectors = defaultdict(list)
    
    # Check candidates sharing same hash or near neighbors
    for key, indices in hash_buckets.items():
        if len(indices) >= 2:
            for i in range(len(indices)):
                for j in range(i + 1, len(indices)):
                    idx1 = indices[i]
                    idx2 = indices[j]
                    
                    x1, y1 = coords[idx1]
                    x2, y2 = coords[idx2]
                    
                    # Compute spatial Euclidean distance
                    dist = np.sqrt((x1 - x2)**2 + (y1 - y2)**2)
                    if dist < min_distance:
                        continue
                        
                    # Compute full correlation
                    v1 = blocks_arr[idx1]
                    v2 = blocks_arr[idx2]
                    corr = float(np.dot(v1, v2) / (np.linalg.norm(v1) * np.linalg.norm(v2) + 1e-6))
                    
                    if corr >= similarity_thresh:
                        # Normalize shift vector so dx >= 0
                        dx = x2 - x1
                        dy = y2 - y1
                        if dx < 0 or (dx == 0 and dy < 0):
                            dx = -dx
                            dy = -dy
                            
                        # Quantize shift vector to cluster nearby translations
                        shift_key = (round(dx / 4) * 4, round(dy / 4) * 4)
                        shift_vectors[shift_key].append(((x1, y1), (x2, y2), corr))
                        
    # Filter clusters by minimum count
    significant_clusters = []
    for shift_key, pairs in shift_vectors.items():
        if len(pairs) >= min_cluster_size:
            significant_clusters.append({
                "shift_vector": shift_key,
                "cluster_size": len(pairs),
                "pairs": pairs[:5]  # Sample pairs
            })
            
    # Sort clusters descending by size
    significant_clusters.sort(key=lambda c: c["cluster_size"], reverse=True)
    
    total_matches = sum(c["cluster_size"] for c in significant_clusters)
    detected = len(significant_clusters) > 0
    
    # Calculate score based on dominant cluster size
    if significant_clusters:
        top_size = significant_clusters[0]["cluster_size"]
        raw_score = min(top_size * 12.0, 100.0)
    else:
        raw_score = 0.0
        
    return {
        "score": round(raw_score, 1),
        "detected": detected,
        "matches_count": total_matches,
        "clusters_count": len(significant_clusters),
        "shift_clusters": significant_clusters[:5],
    }

