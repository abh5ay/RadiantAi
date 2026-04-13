import os
os.environ["CUDA_VISIBLE_DEVICES"] = "-1"
import tensorflow as tf
# Disable GPU for stability on Mac M2
try:
    tf.config.set_visible_devices([], 'GPU')
except:
    pass
import numpy as np
import cv2

# Load model (path relative to root)
model = None
MODEL_PATH = "fracture_model.keras"

if os.path.exists(MODEL_PATH):
    model = tf.keras.models.load_model(MODEL_PATH, compile=False)

def predict_fracture(img_path):
    if not model:
        return "Model Missing", 0.0
        
    img = cv2.imread(img_path)
    img = cv2.resize(img, (224, 224))
    img = img / 255.0
    img = np.expand_dims(img, 0)

    pred = model.predict(img)[0][0]

    if pred > 0.35:
        return "Fracture Detected", float(pred * 100)
    else:
        return "Normal Bone", float((1 - pred) * 100)
