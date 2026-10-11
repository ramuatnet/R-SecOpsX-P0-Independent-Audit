"""Outbound HTTPS client for the dependency mirror."""
import ssl
import urllib.request


def build_opener():
    context = ssl.create_default_context(cafile="corporate-ca.pem")
    return urllib.request.build_opener(HTTPSHandler(context=context))
