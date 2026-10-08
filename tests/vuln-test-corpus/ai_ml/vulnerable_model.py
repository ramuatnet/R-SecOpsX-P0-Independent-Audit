import pickle
import numpy as np
import tensorflow as tf
from flask import Flask, request, jsonify

app = Flask(__name__)

# ----- Hard‑coded API key for a model‑serving service (CWE-798) -----
API_KEY="***"

# Load a model from a pickle file (dangerous if the file can be tampered with)
def load_model(path):
    with open(path, "rb") as f:
        return pickle.load(f)   # CWE-502: Insecure Deserialization

model = load_model("model.pkl")   # attacker could supply a malicious pickle

@app.route("/predict", methods=["POST"])
def predict():
    # ----- No input validation – could lead to resource exhaustion or
    #       model‑stealing via crafted inputs (CWE-94: Improper Input Validation) -----
    data = request.get_json(force=True)
    vec = np.array(data["features"]).reshape(1, -1)
    pred = model.predict(vec)
    return jsonify({"prediction": pred.tolist()})

# ----- Example of a dangerous eval used to dynamically change model hyper‑params -----
@app.route("/retrain", methods=["POST"])
def retrain():
    code = request.get_json(force=True).get("code", "")
    # ----- Code Injection (CWE-94) -----
    # The attacker can inject arbitrary Python code that will be executed
    exec(code, {"model": model, "np": np})
    return jsonify({"status": "retrained"})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
