"""Flask API for CyberSentinel AI (local use only, binds to 127.0.0.1)."""
import io
from pathlib import Path
import pandas as pd
from flask import Flask, jsonify, request, send_from_directory, Response

import dataset, model

ROOT = Path(__file__).resolve().parent.parent
app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 5 * 1024 * 1024
PIPE, METRICS = model.load()


@app.after_request
def cors(resp):  # the API is local and holds no secrets
    resp.headers["Access-Control-Allow-Origin"] = "*"
    resp.headers["Access-Control-Allow-Headers"] = "Content-Type"
    return resp


@app.route("/")
def index():
    return send_from_directory(ROOT, "index.html")


@app.route("/api/health")
def health():
    return jsonify(status="ok", trained=PIPE is not None)


@app.route("/api/dataset.csv")
def dataset_csv():
    return Response(dataset.generate().to_csv(index=False), mimetype="text/csv")


@app.route("/api/train", methods=["POST", "OPTIONS"])
def train():
    global PIPE, METRICS
    if request.method == "OPTIONS":
        return ("", 204)
    body = request.get_json(silent=True) or {}
    try:
        df = pd.read_csv(io.StringIO(body["csv"])) if body.get("csv") else dataset.generate()
        PIPE, METRICS = model.train(df)
    except (ValueError, KeyError, pd.errors.ParserError) as e:
        return jsonify(error=str(e)), 400
    return jsonify(METRICS)


@app.route("/api/metrics")
def metrics():
    return (jsonify(METRICS) if METRICS else (jsonify(error="Model not trained yet."), 404))


@app.route("/api/predict", methods=["POST", "OPTIONS"])
def predict():
    if request.method == "OPTIONS":
        return ("", 204)
    if PIPE is None:
        return jsonify(error="Model not trained yet."), 409
    try:
        return jsonify(model.predict(PIPE, request.get_json(force=True)))
    except (ValueError, KeyError, TypeError) as e:
        return jsonify(error=f"Invalid event: {e}"), 400


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
