"""
TRUSTSHIELD - Input Validation Utilities
Validates and sanitizes user-provided URLs, email/text messages, and uploaded screenshots.
"""

from typing import Tuple, Optional, Any
import re
from urllib.parse import urlparse
import io

try:
    from PIL import Image
except ImportError:
    Image = None

# Maximum text length allowed for analysis (e.g. 50,000 characters)
MAX_TEXT_LENGTH = 50_000
# Supported image formats
ALLOWED_IMAGE_FORMATS = {"PNG", "JPEG", "JPG", "WEBP"}
# Max image size in bytes (10MB)
MAX_IMAGE_SIZE_BYTES = 10 * 1024 * 1024


def validate_url(url: str) -> Tuple[bool, Optional[str]]:
    """
    Validates if a given string is a syntactically valid HTTP/HTTPS URL.
    Returns (is_valid, error_message).
    """
    if not url or not url.strip():
        return False, "URL cannot be empty."

    cleaned_url = url.strip()

    # Automatically prepend https:// if protocol is missing for user convenience
    if not re.match(r"^https?://", cleaned_url, re.IGNORECASE):
        cleaned_url = f"https://{cleaned_url}"

    try:
        parsed = urlparse(cleaned_url)
        if not parsed.scheme or parsed.scheme.lower() not in ("http", "https"):
            return False, "URL must use http or https protocol."
        if not parsed.netloc:
            return False, "URL must contain a valid domain name."
        # Basic regex check for domain structure
        domain_pattern = r"^([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}(:\d+)?$"
        if not re.match(domain_pattern, parsed.netloc.split("@")[-1]):
            # Allow IP addresses as well
            ip_pattern = r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(:\d+)?$"
            if not re.match(ip_pattern, parsed.netloc):
                return False, "Domain or IP address format is invalid."
        return True, None
    except Exception as e:
        return False, f"Invalid URL syntax: {str(e)}"


def validate_text_message(text: str) -> Tuple[bool, Optional[str]]:
    """
    Validates user-submitted message/email text.
    Returns (is_valid, error_message).
    """
    if not text or not text.strip():
        return False, "Message or email text cannot be empty."
    
    cleaned = text.strip()
    if len(cleaned) < 5:
        return False, "Content is too short to analyze (minimum 5 characters)."
    if len(cleaned) > MAX_TEXT_LENGTH:
        return False, f"Content exceeds maximum limit of {MAX_TEXT_LENGTH:,} characters."

    return True, None


def validate_image_bytes(image_bytes: bytes) -> Tuple[bool, Optional[str], Optional[Any]]:
    """
    Validates uploaded image file bytes to ensure integrity and security.
    Returns (is_valid, error_message, image_object_or_none).
    """
    if not image_bytes:
        return False, "Uploaded image is empty.", None

    if len(image_bytes) > MAX_IMAGE_SIZE_BYTES:
        return False, "Image size exceeds 10MB limit.", None

    if Image is not None:
        try:
            img = Image.open(io.BytesIO(image_bytes))
            img.verify()  # Verify integrity without decoding fully
            
            # Re-open after verify() because verify() invalidates the stream
            img = Image.open(io.BytesIO(image_bytes))
            img_format = (img.format or "").upper()

            if img_format not in ALLOWED_IMAGE_FORMATS:
                return False, f"Unsupported image format: {img_format}. Allowed: PNG, JPEG, WEBP", None

            return True, None, img
        except Exception as e:
            return False, f"Corrupted or invalid image file: {str(e)}", None
    else:
        # Fallback magic header check if PIL is not installed
        if image_bytes.startswith(b"\x89PNG\r\n\x1a\n"):
            return True, None, None
        elif image_bytes.startswith(b"\xff\xd8\xff"):
            return True, None, None
        elif image_bytes.startswith(b"RIFF") and b"WEBP" in image_bytes[:16]:
            return True, None, None
        return False, "Unsupported or corrupted image file header.", None
