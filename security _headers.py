"""
ALPHA Security Headers
Basic security headers for a Flask application.

Install dependency:
    pip install flask
"""

from flask import Flask, jsonify

app = Flask(__name__)


@app.after_request
def add_security_headers(response):
    """Attach security-related HTTP response headers."""

    response.headers["X-Content-Type-Options"] = "nosniff"

    response.headers["X-Frame-Options"] = "DENY"

    response.headers["Referrer-Policy"] = (
        "strict-origin-when-cross-origin"
    )

    response.headers["Permissions-Policy"] = (
        "camera=(), microphone=(), geolocation=()"
    )

    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "object-src 'none'; "
        "base-uri 'self'; "
        "frame-ancestors 'none'"
    )

    return response


@app.get("/")
def home():
    return jsonify({
        "app": "ALPHA",
        "message": "Security headers are enabled."
    })


@app.get("/health")
def health():
    return jsonify({"status": "ok"})


if __name__ == "__main__":
    # Local testing only. Use a production WSGI server in deployment.
    app.run(host="127.0.0.1", port=5000, debug=False)
