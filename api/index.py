"""Vercel Python serverless entry point."""

from urllib.parse import urlsplit

from wsgi import app as flask_app


class VercelRewriteMiddleware:
    """Restore the public request path before Flask routing."""

    def __init__(self, application):
        self.application = application

    def __call__(self, environ, start_response):
        for header in (
            "HTTP_X_VERCEL_MATCHED_PATH",
            "HTTP_X_MATCHED_PATH",
            "HTTP_X_ORIGINAL_URI",
        ):
            matched_path = environ.get(header)
            if matched_path:
                path = urlsplit(matched_path).path
                if path:
                    environ["PATH_INFO"] = path
                    break
        else:
            current_path = environ.get("PATH_INFO", "")
            if current_path in ("", "/api", "/api/index", "/api/index.py"):
                environ["PATH_INFO"] = "/"

        return self.application(environ, start_response)


app = VercelRewriteMiddleware(flask_app)


__all__ = ["app"]
