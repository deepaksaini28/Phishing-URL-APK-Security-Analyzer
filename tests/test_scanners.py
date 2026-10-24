import io
import os
import tempfile
import unittest
import zipfile

from PIL import Image

from analyzer import create_app
from analyzer.apk_scanner import analyze_apk
from analyzer.datasets import _summarize_csv
from analyzer.url_scanner import analyze_url


def create_test_image(image_format):
    output = io.BytesIO()
    Image.new("RGB", (8, 8), color=(220, 220, 220)).save(output, format=image_format)
    return output.getvalue()


class DatasetInspectionTests(unittest.TestCase):
    def test_malformed_csv_rows_are_excluded_from_label_counts(self):
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "sample.csv")
            with open(path, "w", encoding="utf-8", newline="") as handle:
                handle.write("url,label\nhttps://example.org,0\nbroken,row,extra\n")
            result = _summarize_csv(path, {
                "url_column": "url",
                "label_column": "label",
                "label_note": "test labels",
                "trainable": False,
            })
            self.assertEqual(result["rows"], 2)
            self.assertEqual(result["malformed_rows"], 1)
            self.assertEqual(result["labels"], {"0": 1})


class UrlScannerTests(unittest.TestCase):
    def test_suspicious_structure_is_explained(self):
        result = analyze_url(
            "http://192.0.2.5/login/verify?account=1",
            os.path.join("Dataset"),
            os.path.join("models"),
        )
        messages = " ".join(finding["message"] for finding in result["findings"])
        self.assertGreaterEqual(result["score"], 25)
        self.assertIn("IP address", messages)
        self.assertIn("HTTPS", messages)
        self.assertNotIn("subdomain levels", messages)
        self.assertEqual(result["domain"], "192.0.2.5")

    def test_credentials_in_url_are_rejected(self):
        with self.assertRaises(ValueError):
            analyze_url("https://user:secret@example.com", "Dataset", "models")


class ApkScannerTests(unittest.TestCase):
    def test_manifest_indicators_are_reported_without_execution(self):
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "sample.apk")
            manifest = b"""<manifest xmlns:android="http://schemas.android.com/apk/res/android"
                package="org.example.sample" android:versionName="1.2">
                <uses-permission android:name="android.permission.INTERNET"/>
                <uses-permission android:name="android.permission.SYSTEM_ALERT_WINDOW"/>
                <application/>
                </manifest>"""
            with zipfile.ZipFile(path, "w") as archive:
                archive.writestr("AndroidManifest.xml", manifest)
                archive.writestr("classes.dex", b"not executed")
            result = analyze_apk(path, "sample.apk")
            self.assertEqual(result["classification"], "Unknown")
            self.assertEqual(result["metadata"]["package"], "org.example.sample")
            self.assertTrue(any(item["category"] == "Adware-like indicators"
                                for item in result["findings"]))
            self.assertEqual(len(result["sha256"]), 64)

    def test_invalid_archive_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "broken.apk")
            with open(path, "wb") as handle:
                handle.write(b"not a zip")
            with self.assertRaises(ValueError):
                analyze_apk(path, "broken.apk")


class ApiTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.app = create_app({
            "TESTING": True,
            "DATABASE": os.path.join(self.temp_dir.name, "scans.sqlite3"),
            "DATASET_DIR": self.temp_dir.name,
            "MODEL_DIR": self.temp_dir.name,
            "REMOVE_BG_API_KEY": "",
        })
        self.client = self.app.test_client()

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_scan_history_and_report(self):
        response = self.client.post("/api/scan/url", json={"url": "https://example.org/"})
        self.assertEqual(response.status_code, 200)
        scan_id = response.get_json()["id"]
        self.assertEqual(self.client.get("/api/scans").get_json()["scans"][0]["id"], scan_id)
        report = self.client.get(f"/api/scans/{scan_id}/report")
        self.assertEqual(report.status_code, 200)
        self.assertIn(b"not a guarantee", report.data)

    def test_url_history_can_be_disabled(self):
        response = self.client.post(
            "/api/scan/url",
            json={"url": "https://example.org/", "save_history": False},
        )
        self.assertEqual(response.status_code, 200)
        self.assertNotIn("id", response.get_json())
        self.assertEqual(self.client.get("/api/scans").get_json()["scans"], [])

    def test_invalid_url_returns_actionable_error(self):
        response = self.client.post("/api/scan/url", json={"url": "not a url"})
        self.assertEqual(response.status_code, 400)
        self.assertIn("valid HTTP or HTTPS", response.get_json()["error"])

    def test_homepage_and_health_are_available(self):
        home = self.client.get("/")
        self.assertEqual(home.status_code, 302)
        self.assertEqual(home.headers["Location"], "/url")
        self.assertEqual(self.client.get("/api/health").get_json()["status"], "ok")

    def test_tool_navigation_renders_separate_pages(self):
        pages = (
            ("/url", b'id="url-form"', b'id="apk-form"', b'id="image-form"'),
            ("/apk", b'id="apk-form"', b'id="url-form"', b'id="image-form"'),
            ("/image", b'id="image-form"', b'id="url-form"', b'id="apk-form"'),
        )
        for path, present, absent_one, absent_two in pages:
            with self.subTest(path=path):
                response = self.client.get(path)
                self.assertEqual(response.status_code, 200)
                self.assertIn(present, response.data)
                self.assertNotIn(absent_one, response.data)
                self.assertNotIn(absent_two, response.data)
                self.assertIn(b'aria-current="page"', response.data)
                self.assertIn(b"Phishing URL &amp; APK Security Analyzer", response.data)

    def test_apk_upload_rejects_wrong_extension(self):
        response = self.client.post(
            "/api/scan/apk",
            data={"file": (bytes(b"test"), "sample.txt")},
            content_type="multipart/form-data",
        )
        self.assertEqual(response.status_code, 400)

    def test_apk_upload_is_analyzed_and_archived_to_history(self):
        manifest = b"""<manifest xmlns:android="http://schemas.android.com/apk/res/android"
            package="org.example.upload">
            <uses-permission android:name="android.permission.INTERNET"/>
            <application/>
            </manifest>"""
        apk = io.BytesIO()
        with zipfile.ZipFile(apk, "w") as archive:
            archive.writestr("AndroidManifest.xml", manifest)
        apk.seek(0)
        response = self.client.post(
            "/api/scan/apk",
            data={"file": (apk, "review.apk")},
            content_type="multipart/form-data",
        )
        self.assertEqual(response.status_code, 200)
        result = response.get_json()
        self.assertEqual(result["classification"], "Unknown")
        self.assertEqual(result["metadata"]["package"], "org.example.upload")
        self.assertEqual(len(result["sha256"]), 64)
        self.assertEqual(self.client.get("/api/scans").get_json()["scans"][0]["id"], result["id"])

    def test_image_requires_explicit_remove_bg_consent(self):
        response = self.client.post(
            "/api/scan/image",
            data={"file": (io.BytesIO(create_test_image("PNG")), "source.png")},
            content_type="multipart/form-data",
        )
        self.assertEqual(response.status_code, 400)
        self.assertIn("consent", response.get_json()["error"].lower())

    def test_image_rejects_unsupported_format_before_api_call(self):
        response = self.client.post(
            "/api/scan/image",
            data={
                "file": (io.BytesIO(create_test_image("GIF")), "source.gif"),
                "consent": "true",
            },
            content_type="multipart/form-data",
        )
        self.assertEqual(response.status_code, 400)
        self.assertIn("unsupported image format", response.get_json()["error"].lower())

    def test_image_reports_missing_remove_bg_key_without_network_call(self):
        response = self.client.post(
            "/api/scan/image",
            data={
                "file": (io.BytesIO(create_test_image("PNG")), "source.png"),
                "consent": "true",
            },
            content_type="multipart/form-data",
        )
        self.assertEqual(response.status_code, 503)
        self.assertIn("REMOVE_BG_API_KEY", response.get_json()["error"])

    def test_image_rejects_uploads_over_20_mib(self):
        response = self.client.post(
            "/api/scan/image",
            data={
                "file": (io.BytesIO(b"x" * (20 * 1024 * 1024 + 1)), "large.png"),
                "consent": "true",
            },
            content_type="multipart/form-data",
        )
        self.assertEqual(response.status_code, 413)
        self.assertIn("20 MiB", response.get_json()["error"])

    def test_frontend_never_contains_the_remove_bg_api_key(self):
        home = self.client.get("/image")
        self.assertEqual(home.status_code, 200)
        self.assertNotIn(b"REMOVE_BG_API_KEY", home.data)
        self.assertIn(b"remove.bg", home.data)

    def test_clear_history_removes_saved_records(self):
        self.client.post("/api/scan/url", json={"url": "https://example.org/"})
        response = self.client.delete("/api/scans")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(self.client.get("/api/scans").get_json()["scans"], [])


if __name__ == "__main__":
    unittest.main()
