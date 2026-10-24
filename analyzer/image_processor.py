import io
import os

import requests
from PIL import Image, UnidentifiedImageError


REMOVE_BG_ENDPOINT = "https://api.remove.bg/v1.0/removebg"
MAX_RESULT_BYTES = 100 * 1024 * 1024
SUPPORTED_FORMATS = {
    "PNG": ("image/png", ".png"),
    "JPEG": ("image/jpeg", ".jpg"),
    "WEBP": ("image/webp", ".webp"),
}


class ImageProcessingError(ValueError):
    pass


class RemoveBgError(Exception):
    def __init__(self, message, status_code=502):
        super().__init__(message)
        self.status_code = status_code


def _validate_image(image_bytes, max_pixels):
    try:
        with Image.open(io.BytesIO(image_bytes)) as image:
            image_format = image.format
            width, height = image.size
            image.verify()
    except (UnidentifiedImageError, OSError, Image.DecompressionBombError) as exc:
        raise ImageProcessingError(
            "Choose a valid PNG, JPEG, or WebP image. The image may be corrupt or unsupported."
        ) from exc

    if image_format not in SUPPORTED_FORMATS:
        raise ImageProcessingError("Unsupported image format. Choose a PNG, JPEG, or WebP image.")
    if width * height > max_pixels:
        raise ImageProcessingError("Image dimensions exceed the 40-megapixel safety limit.")
    return image_format


def _provider_error(response):
    status = response.status_code
    detail = ""
    try:
        payload = response.json()
    except (ValueError, requests.exceptions.JSONDecodeError):
        payload = {}
    if isinstance(payload, dict):
        errors = payload.get("errors", [])
        if isinstance(errors, list):
            detail = " ".join(
                f"{item.get('title', '')} {item.get('code', '')}"
                for item in errors
                if isinstance(item, dict)
            ).lower()

    if status in (402, 429) or any(
        word in detail for word in ("credit", "quota", "rate limit", "insufficient")
    ):
        return RemoveBgError(
            "remove.bg credits or request quota are unavailable. Check your account usage and plan.",
            429,
        )
    if status in (401, 403) or "api key" in detail or "auth" in detail:
        return RemoveBgError(
            "remove.bg rejected the API key. Check REMOVE_BG_API_KEY in your .env file.",
            502,
        )
    if status in (400, 415, 422):
        return RemoveBgError(
            "remove.bg could not process this image. Try a valid PNG, JPEG, or WebP image.",
            422,
        )
    if status == 413:
        return RemoveBgError(
            "This image exceeds remove.bg's upload limit. Try a smaller image.",
            413,
        )
    if status >= 500:
        return RemoveBgError(
            "remove.bg is temporarily unavailable. Please try again later.",
            502,
        )
    return RemoveBgError(
        f"remove.bg could not process this request (HTTP {status}). Please try again.",
        502,
    )


def _read_response(response):
    content_length = response.headers.get("Content-Length")
    if content_length:
        try:
            if int(content_length) > MAX_RESULT_BYTES:
                raise RemoveBgError("The processed image exceeds the 100 MiB result limit.", 502)
        except ValueError:
            pass

    chunks = []
    total = 0
    for chunk in response.iter_content(chunk_size=64 * 1024):
        if not chunk:
            continue
        total += len(chunk)
        if total > MAX_RESULT_BYTES:
            raise RemoveBgError("The processed image exceeds the 100 MiB result limit.", 502)
        chunks.append(chunk)
    return b"".join(chunks)


def _validate_result(result_bytes):
    try:
        with Image.open(io.BytesIO(result_bytes)) as image:
            if image.format != "PNG":
                raise RemoveBgError("remove.bg returned an unexpected format instead of a PNG.", 502)
            if "A" not in image.getbands() and "transparency" not in image.info:
                raise RemoveBgError("remove.bg returned a PNG without a transparency channel.", 502)
            image.load()
    except RemoveBgError:
        raise
    except (UnidentifiedImageError, OSError, Image.DecompressionBombError) as exc:
        raise RemoveBgError("remove.bg returned an invalid or incomplete image.", 502) from exc
    return result_bytes


def process_with_remove_bg(image_bytes, filename, api_key, max_pixels):
    if not image_bytes:
        raise ImageProcessingError("The uploaded image is empty.")

    image_format = _validate_image(image_bytes, max_pixels)
    if not api_key or not api_key.strip() or api_key.strip().lower().startswith("add-your-"):
        raise RemoveBgError(
            "Background removal is not configured. Add REMOVE_BG_API_KEY to the project .env file and restart the app.",
            503,
        )
    mime_type, extension = SUPPORTED_FORMATS[image_format]
    safe_filename = os.path.splitext(os.path.basename(filename))[0] + extension

    try:
        with requests.post(
            REMOVE_BG_ENDPOINT,
            files={"image_file": (safe_filename, image_bytes, mime_type)},
            data={"size": "auto", "format": "png"},
            headers={"X-Api-Key": api_key.strip()},
            timeout=(10, 120),
            stream=True,
        ) as response:
            if response.status_code != requests.codes.ok:
                raise _provider_error(response)
            content_type = response.headers.get("Content-Type", "").split(";", 1)[0].lower()
            if content_type != "image/png":
                raise _provider_error(response)
            result_bytes = _read_response(response)
    except requests.exceptions.Timeout as exc:
        raise RemoveBgError(
            "The request to remove.bg timed out. Check your connection and try again.",
            504,
        ) from exc
    except requests.exceptions.ConnectionError as exc:
        raise RemoveBgError(
            "Could not connect to remove.bg. Check your network connection and try again.",
            502,
        ) from exc
    except requests.exceptions.RequestException as exc:
        raise RemoveBgError(
            "A network error interrupted the remove.bg request. Please try again.",
            502,
        ) from exc

    return _validate_result(result_bytes)
