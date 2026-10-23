"""The outbound destination is fixed at deploy time; the request path to this
view can never change where the server connects to."""
import requests
from flask import Flask

app = Flask(__name__)


@app.route("/status")
def fetch_status():
    return requests.get("https://api.internal/health", timeout=10).text
