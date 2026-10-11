import os

# Every value below is read from the environment at runtime, so no credential
# is present in this file.
DATABASE_URL = os.environ["DATABASE_URL"]
API_TOKEN = os.environ.get("API_TOKEN", "")
LOG_LEVEL = os.environ.get("LOG_LEVEL", "INFO")
