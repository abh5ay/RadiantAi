import cv2
import numpy as np

def generate_heatmap(src_path, dst_path, mode='chest'):
    """Generates a pseudo-XAI heatmap (localized interest) for the diagnostic image."""
    img = cv2.imread(src_path)
    if img is None: return
    
    # Create mock heatmap based on intensity gradients
    gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
    heatmap = cv2.applyColorMap(gray, cv2.COLORMAP_JET)
    
    # Composite
    alpha = 0.4
    result = cv2.addWeighted(img, 1-alpha, heatmap, alpha, 0)
    
    cv2.imwrite(dst_path, result)
