import hashlib
import io
import os
import re
import zipfile
import xml.etree.ElementTree as ET


MAX_MEMBERS = 15000
MAX_EXPANDED_BYTES = 512 * 1024 * 1024
MAX_MANIFEST_BYTES = 5 * 1024 * 1024
ANDROID_NAMESPACE = "{http://schemas.android.com/apk/res/android}"

PERMISSION_GROUPS = {
    "Messaging and call access": (
        "SEND_SMS", "RECEIVE_SMS", "READ_SMS", "RECEIVE_MMS", "CALL_PHONE",
        "READ_CALL_LOG", "WRITE_CALL_LOG", "PROCESS_OUTGOING_CALLS",
    ),
    "Location": ("ACCESS_FINE_LOCATION", "ACCESS_COARSE_LOCATION", "ACCESS_BACKGROUND_LOCATION"),
    "Microphone and camera": ("RECORD_AUDIO", "CAMERA"),
    "Contacts and storage": ("READ_CONTACTS", "WRITE_CONTACTS", "READ_EXTERNAL_STORAGE",
                             "WRITE_EXTERNAL_STORAGE", "MANAGE_EXTERNAL_STORAGE"),
    "Device control": ("SYSTEM_ALERT_WINDOW", "BIND_ACCESSIBILITY_SERVICE",
                       "REQUEST_INSTALL_PACKAGES", "RECEIVE_BOOT_COMPLETED",
                       "BIND_DEVICE_ADMIN"),
}


def _manifest_from_apk(path):
    try:
        from androguard.core.apk import APK

        apk = APK(path)
        permissions = list(apk.get_permissions() or [])
        try:
            version_name = apk.get_androidversion_name() or "Not available"
        except KeyError:
            version_name = "Not available"
        try:
            version_code = apk.get_androidversion_code() or "Not available"
        except KeyError:
            version_code = "Not available"
        signature_schemes = {
            "v1": apk.is_signed_v1(),
            "v2": apk.is_signed_v2(),
            "v3": apk.is_signed_v3(),
            "v3.1": apk.is_signed_v31(),
        }
        certificates = []
        certificate_error = None
        try:
            certificates = [
                {
                    "subject": certificate.subject.human_friendly,
                    "issuer": certificate.issuer.human_friendly,
                    "serial_number": str(certificate.serial_number),
                    "sha256": certificate.sha256.hex(),
                }
                for certificate in apk.get_certificates()
            ]
        except (AttributeError, IndexError, KeyError, ValueError):
            certificate_error = "Certificate details could not be decoded."
        return {
            "package": apk.get_package() or "Not available",
            "version_name": version_name,
            "version_code": version_code,
            "permissions": sorted(set(permissions)),
            "manifest_available": True,
            "signing_info": {
                "is_signed": apk.is_signed(),
                "schemes": signature_schemes,
                "signature_files": apk.get_signature_names(),
                "certificates": certificates,
                "certificate_error": certificate_error,
            },
        }
    except ImportError:
        return None
    except Exception as exc:
        raise ValueError("The Android manifest could not be decoded.") from exc


def _manifest_from_xml(data):
    try:
        root = ET.fromstring(data)
    except ET.ParseError:
        return None
    application = root.find("application")
    return {
        "package": root.attrib.get("package", "Not available"),
        "version_name": root.attrib.get(ANDROID_NAMESPACE + "versionName", "Not available"),
        "version_code": root.attrib.get(ANDROID_NAMESPACE + "versionCode", "Not available"),
        "permissions": sorted({
            node.attrib.get(ANDROID_NAMESPACE + "name", "")
            for node in root
            if node.tag.rsplit("}", 1)[-1] in ("uses-permission", "uses-permission-sdk-23")
            and node.attrib.get(ANDROID_NAMESPACE + "name")
        }),
        "manifest_available": application is not None or root.tag.endswith("manifest"),
    }


def analyze_apk(path, original_name):
    if os.path.getsize(path) == 0:
        raise ValueError("The uploaded APK is empty.")
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)

    try:
        archive = zipfile.ZipFile(path)
    except (zipfile.BadZipFile, OSError) as exc:
        raise ValueError("The file is not a readable APK archive.") from exc

    with archive:
        members = archive.infolist()
        if len(members) > MAX_MEMBERS:
            raise ValueError("The archive contains too many entries to inspect safely.")
        expanded = sum(item.file_size for item in members)
        if expanded > MAX_EXPANDED_BYTES:
            raise ValueError("The archive expands beyond the 512 MB safety limit.")
        for item in members:
            if item.file_size > 0 and item.file_size / max(item.compress_size, 1) > 1000:
                raise ValueError("The archive contains a suspicious compression ratio.")
        names = [item.filename for item in members]
        if "AndroidManifest.xml" not in names:
            raise ValueError("No AndroidManifest.xml was found; upload a valid APK.")

        manifest_info = archive.getinfo("AndroidManifest.xml")
        if manifest_info.file_size > MAX_MANIFEST_BYTES:
            raise ValueError("The Android manifest is unexpectedly large.")
        manifest_bytes = archive.read("AndroidManifest.xml")

    metadata = _manifest_from_xml(manifest_bytes)
    if metadata is None:
        metadata = _manifest_from_apk(path)
    if metadata is None:
        metadata = {
            "package": "Not decoded (install androguard for binary manifests)",
            "version_name": "Not available",
            "version_code": "Not available",
            "permissions": [],
            "manifest_available": False,
        }

    permissions = metadata["permissions"]
    basename = os.path.basename(original_name)
    findings = []
    sensitive = []
    for group, suffixes in PERMISSION_GROUPS.items():
        matches = [permission for permission in permissions
                   if any(permission.endswith(suffix) for suffix in suffixes)]
        if matches:
            sensitive.extend(matches)
            findings.append({
                "category": group,
                "severity": "medium",
                "message": f"Requests {group.lower()} permissions.",
                "evidence": matches,
            })

    dex_files = [name for name in names if re.fullmatch(r"classes\d*\.dex", name)]
    native_files = [name for name in names if name.startswith("lib/") and name.endswith(".so")]
    signing_files = [name for name in names if name.upper().startswith("META-INF/")
                     and name.upper().endswith((".RSA", ".DSA", ".EC"))]
    signing_info = metadata.get("signing_info") or {
        "is_signed": None,
        "schemes": {},
        "signature_files": signing_files,
        "certificates": [],
        "certificate_error": None,
    }
    extensions = {}
    for name in names:
        extension = os.path.splitext(name)[1].lower() or "(none)"
        extensions[extension] = extensions.get(extension, 0) + 1
    has_internet = any(permission.endswith("INTERNET") for permission in permissions)
    has_overlay = any(permission.endswith("SYSTEM_ALERT_WINDOW") for permission in permissions)
    has_ad_id = any(permission.endswith("AD_ID") for permission in permissions)

    if has_internet and (has_overlay or has_ad_id):
        findings.append({
            "category": "Adware-like indicators",
            "severity": "low",
            "message": "An internet permission is combined with an overlay or advertising identifier permission.",
            "evidence": [p for p in permissions if p.endswith(("INTERNET", "SYSTEM_ALERT_WINDOW", "AD_ID"))],
        })
    install_permission = any(permission.endswith("REQUEST_INSTALL_PACKAGES")
                             for permission in permissions)
    if install_permission:
        findings.append({
            "category": "Potentially unwanted capability",
            "severity": "low",
            "message": "Requests permission to install packages; legitimate installer apps may need this capability.",
            "evidence": [permission for permission in permissions
                         if permission.endswith("REQUEST_INSTALL_PACKAGES")],
        })
    if len(permissions) >= 20:
        findings.append({
            "category": "Bloatware-like indicator",
            "severity": "low",
            "message": f"The manifest requests {len(permissions)} permissions; this is a broad-permission indicator, not proof of bloatware.",
            "evidence": [],
        })
    if signing_info["is_signed"] is False:
        findings.append({
            "category": "Signing metadata",
            "severity": "low",
            "message": "No supported APK signature scheme was detected; cryptographic signature validity is not verified.",
            "evidence": [],
        })
    elif signing_info["is_signed"] is None and not signing_files:
        findings.append({
            "category": "Signing metadata",
            "severity": "info",
            "message": "The manifest could be inspected, but signature schemes could not be decoded.",
            "evidence": [],
        })
    if signing_info["certificate_error"]:
        findings.append({
            "category": "Signing metadata",
            "severity": "low",
            "message": signing_info["certificate_error"],
            "evidence": [],
        })
    if not findings:
        findings.append({
            "category": "Static inspection",
            "severity": "info",
            "message": "No configured permission indicators were found in the readable manifest.",
            "evidence": [],
        })

    score = min(
        100,
        sum(15 if finding["severity"] == "medium" else 5
            for finding in findings if finding["severity"] != "info"),
    )
    return {
        "kind": "apk",
        "subject": basename,
        "sha256": digest.hexdigest(),
        "risk": "Elevated indicators" if score >= 30 else "Limited indicators",
        "score": score,
        "classification": "Unknown",
        "indicator_assessment": {
            "malware": "Not classified; no APK malware model or signature database is configured.",
            "potentially_unwanted": "Capability indicators present" if install_permission else "No configured indicator detected",
            "adware": "Adware-like indicators present" if has_internet and (has_overlay or has_ad_id) else "No configured indicator detected",
            "bloatware": "Broad-permission indicator present" if len(permissions) >= 20 else "No configured indicator detected",
        },
        "metadata": {
            **metadata,
            "archive_entries": len(members),
            "expanded_size_bytes": expanded,
            "dex_files": dex_files,
            "embedded_file_extensions": extensions,
            "native_library_count": len(native_files),
            "signing_entries": signing_files,
            "signing_info": signing_info,
            "sensitive_permissions": sorted(set(sensitive)),
        },
        "findings": findings,
        "limitations": [
            "Static inspection never executes the APK, follows network requests, or guarantees malware detection.",
            "A permission or adware-like indicator is not proof of malicious behavior.",
            "A clean indicator result does not mean the APK is safe; unknown results are expected without an APK classifier.",
            "Signing schemes and certificate fingerprints are reported when parseable; cryptographic signature and certificate-chain validity are not verified.",
            "No labelled APK sample dataset was supplied. The network-flow CSVs are not APK files or APK static features.",
        ],
    }
