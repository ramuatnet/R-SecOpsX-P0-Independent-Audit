import os
import numpy as np
import tensorflow as tf
from flask import Flask, request, jsonify

app = Flask(__name__)

# ----- API key from environment – no hard‑coded secret -----
API_KEY = os.getenv("MODEL_API_KEY", "")

# Load model using TensorFlow's SavedModel format (safe)
def load_model(path):
    return tf.keras.models.load_model(path)   # no pickle

model = load_model("saved_model/")   # assume a trusted, verified model

@app.route("/predict", methods=["POST"])
def predict():
    # ----- Validate input shape and type (fixes CWE-94) -----
    data = request.get_json(force=True)
    if not isinstance(data, dict) or "features" not in data:
        return jsonify({"error": "invalid payload"}), 400
    feats = data["features"]
    if not isinstance(feats, list) or not all(isinstance(x, (int, float)) for x in feats):
        return jsonify({"error": "features must be list of numbers"}), 400
    vec = np.array(feats, dtype=np.float32).reshape(1, -1)
    pred = model.predict(vec)
    return jsonify({"prediction": pred.tolist()})

# ----- Disallow arbitrary code execution – use a controlled retraining endpoint -----
@app.route("/retrain", methods=["POST"])
def retrain():
    # Expect a JSON with new training data, not raw code
    payload = request.get_json(force=True)
    # In a real service you would validate the payload and call model.fit()
    # For this demo we just acknowledge.
    return jsonify({"status": "retraining scheduled"})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080, debug=False)
