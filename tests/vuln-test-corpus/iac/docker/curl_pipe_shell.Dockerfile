FROM python:3.12-slim
USER app
RUN curl -fsSL https://get.example.com/install.sh | sh
WORKDIR /srv
CMD ["python", "app.py"]
