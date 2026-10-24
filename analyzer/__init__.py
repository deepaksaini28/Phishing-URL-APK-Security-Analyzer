import os

from dotenv import load_dotenv
from flask import Flask, redirect, render_template, url_for

from analyzer.routes import api
from analyzer.storage import initialize_database


def create_app(test_config=None):
    project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    load_dotenv(os.path.join(project_root, ".env"), override=False)
    app = Flask(__name__, static_folder="static", template_folder="templates")
    app.config.from_mapping(
        SECRET_KEY="local-development-only",
        MAX_CONTENT_LENGTH=110 * 1024 * 1024,
        DATABASE=os.environ.get(
            "NORTHSTAR_DATABASE", os.path.join(project_root, "instance", "scans.sqlite3")
        ),
        DATASET_DIR=os.environ.get("NORTHSTAR_DATASET_DIR", os.path.join(project_root, "Dataset")),
        MODEL_DIR=os.environ.get("NORTHSTAR_MODEL_DIR", os.path.join(project_root, "models")),
        REMOVE_BG_API_KEY=os.environ.get("REMOVE_BG_API_KEY", ""),
    )
    if test_config:
        app.config.update(test_config)

    initialize_database(app.config["DATABASE"])
    app.register_blueprint(api, url_prefix="/api")

    pages = {
        "url": {
            "title": "Phishing URL scanner",
            "description": "Inspect a link's structure locally, without opening it or contacting its host.",
            "eyebrow": "LOCAL URL ANALYSIS",
        },
        "apk": {
            "title": "APK security scanner",
            "description": "Review an Android app package without installing or executing it.",
            "eyebrow": "STATIC APK INSPECTION",
        },
        "image": {
            "title": "Image background remover",
            "description": "Remove an image background and download the processed transparent PNG.",
            "eyebrow": "OPTIONAL IMAGE PROCESSING",
        },
    }

    def render_tool_page(page):
        return render_template("index.html", page=page, **pages[page])

    @app.get("/")
    def index():
        return redirect(url_for("url_page"))

    @app.get("/url")
    def url_page():
        return render_tool_page("url")

    @app.get("/apk")
    def apk_page():
        return render_tool_page("apk")

    @app.get("/image")
    def image_page():
        return render_tool_page("image")

    @app.errorhandler(413)
    def too_large(_error):
        return {"error": "Request exceeds the 110 MiB multipart upload limit."}, 413

    return app
