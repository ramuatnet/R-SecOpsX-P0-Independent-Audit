"""SSRF: the outbound request destination is taken verbatim from the query."""
import requests
from flask import Flask, request

app = Flask(__name__)


@app.route("/fetch")
def fetch_feed():
    target = request.args["url"]
    return requests.get(target, timeout=10).text
