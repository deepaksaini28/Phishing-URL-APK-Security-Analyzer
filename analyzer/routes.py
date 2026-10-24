import hashlib
import io
import json
import os
import tempfile
from datetime import datetime, timezone

from flask import Blueprint, current_app, jsonify, request, send_file
from werkzeug.utils import secure_filename

from analyzer.apk_scanner import analyze_apk
from analyzer.datasets import inspect_datasets, network_flow_csv_count
from analyzer.image_processor import ImageProcessingError, RemoveBgError, process_with_remove_bg
from analyzer.storage import count_scans, database_connection, get_scan, list_scans, save_scan
from analyzer.url_scanner import analyze_url

api = Blueprint("api", __name__)
MAX_APK_BYTES = 100 * 1024 * 1024
MAX_IMAGE_BYTES = 20 * 1024 * 1024


def _settings():
    return current_app.config


def _save_result(result, sha256=None):
    scan_id, created_at = save_scan(
        _settings()["DATABASE"],
        result["kind"],
        result["subject"],
        sha256 or result.get("sha256"),
        result["risk"],
        result.get("score"),
        result,
    )
    result["id"] = scan_id
    result["created_at"] = created_at
    return result


def _upload():
    file = request.files.get("file")
    if file is None or not file.filename:
        raise ValueError("Choose a file to upload.")
    filename = secure_filename(file.filename)
    if not filename:
        raise ValueError("The uploaded file name is not valid.")
    return file, filename


@api.get("/health")
def health():
    return jsonify({"status": "ok", "service": "local analyzer"})


@api.get("/overview")
def overview():
    model_path = os.path.join(_settings()["MODEL_DIR"], "url_model.joblib")
    return jsonify({
        "scan_count": count_scans(_settings()["DATABASE"]),
        "datasets": {
            "network_flow_csv_count": network_flow_csv_count(_settings()["DATASET_DIR"]),
        },
        "url_model_available": os.path.isfile(model_path),
        "features": ["url", "apk", "image", "history", "reports"],
    })


@api.post("/scan/url")
def scan_url():
    payload = request.get_json(silent=True)
    if not isinstance(payload, dict) or not isinstance(payload.get("url"), str):
        return jsonify({"error": "Submit a URL in the 'url' field."}), 400
    try:
        result = analyze_url(payload["url"], _settings()["DATASET_DIR"], _settings()["MODEL_DIR"])
        if payload.get("save_history", True) is False:
            return jsonify(result)
        return jsonify(_save_result(result))
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400
    except RuntimeError as exc:
        return jsonify({"error": str(exc)}), 503


@api.post("/scan/apk")
def scan_apk():
    try:
        uploaded, filename = _upload()
        suffix = os.path.splitext(filename)[1].lower()
        if suffix != ".apk":
            return jsonify({"error": "Upload an Android APK file with a .apk extension."}), 400
        with tempfile.TemporaryDirectory(prefix="phishing-analyzer-") as directory:
            path = os.path.join(directory, "upload.apk")
            uploaded.save(path)
            if os.path.getsize(path) > MAX_APK_BYTES:
                return jsonify({"error": "APK uploads are limited to 100 MiB."}), 413
            result = analyze_apk(path, filename)
        return jsonify(_save_result(result))
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400
    except OSError:
        return jsonify({"error": "The APK could not be read safely."}), 400


@api.post("/scan/image")
def scan_image():
    try:
        uploaded, filename = _upload()
        if request.form.get("consent") != "true":
            uploaded.close()
            return jsonify({
                "error": "Confirm that you consent to sending this image to remove.bg before processing."
            }), 400
        try:
            raw = uploaded.stream.read(MAX_IMAGE_BYTES + 1)
        finally:
            uploaded.close()
        if len(raw) > MAX_IMAGE_BYTES:
            return jsonify({"error": "Image uploads are limited to 20 MiB."}), 413
        image_data = process_with_remove_bg(
            raw,
            filename,
            _settings()["REMOVE_BG_API_KEY"],
            max_pixels=40_000_000,
        )
        digest = hashlib.sha256(raw).hexdigest()
        details = {
            "kind": "image",
            "subject": filename,
            "sha256": digest,
            "risk": "Processed",
            "score": None,
            "findings": [{
                "severity": "info",
                "message": "The image was sent to remove.bg with your consent and processed by its background-removal API.",
            }],
            "limitations": [
                "Image processing is performed by remove.bg under its service terms and privacy policy.",
                "The original image is not retained by this application; review the provider's data-retention policy.",
            ],
        }
        _save_result(details, digest)
        response = send_file(
            io.BytesIO(image_data),
            mimetype="image/png",
            as_attachment=False,
            download_name=os.path.splitext(filename)[0] + "-no-background.png",
        )
        response.headers["Cache-Control"] = "no-store"
        response.headers["X-Content-Type-Options"] = "nosniff"
        return response
    except ImageProcessingError as exc:
        return jsonify({"error": str(exc)}), 400
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400
    except RemoveBgError as exc:
        return jsonify({"error": str(exc)}), exc.status_code


@api.get("/scans")
def scans():
    return jsonify({"scans": list_scans(_settings()["DATABASE"])})


@api.delete("/scans")
def clear_scans():
    with database_connection(_settings()["DATABASE"]) as connection:
        connection.execute("DELETE FROM scans")
    return jsonify({"message": "Local scan history cleared."})


@api.get("/scans/<int:scan_id>")
def scan_detail(scan_id):
    result = get_scan(_settings()["DATABASE"], scan_id)
    if result is None:
        return jsonify({"error": "Scan not found."}), 404
    return jsonify(result)


@api.get("/scans/<int:scan_id>/report")
def scan_report(scan_id):
    result = get_scan(_settings()["DATABASE"], scan_id)
    if result is None:
        return jsonify({"error": "Scan not found."}), 404
    report = {
        "report_version": 1,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "scan": result,
        "notice": "Static and heuristic analysis is not a guarantee of safety or malware detection.",
    }
    return send_file(
        io.BytesIO(json.dumps(report, indent=2).encode("utf-8")),
        mimetype="application/json",
        as_attachment=True,
        download_name=f"security-scan-{scan_id}.json",
    )


@api.get("/datasets")
def datasets():
    return jsonify(inspect_datasets(_settings()["DATASET_DIR"]))


@api.get("/evaluation")
def evaluation():
    path = os.path.join(_settings()["MODEL_DIR"], "url_model_evaluation.json")
    if not os.path.isfile(path):
        return jsonify({"available": False, "message": "No evaluation report found. Train using scripts/train_url_model.py."})
    try:
        with open(path, encoding="utf-8") as handle:
            report = json.load(handle)
    except (OSError, json.JSONDecodeError):
        return jsonify({"error": "The saved evaluation report could not be read."}), 500
    return jsonify({"available": True, "report": report})
