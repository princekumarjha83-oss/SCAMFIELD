"""
ScamShield AI - Screenshot Optical Character Recognition (OCR) Engine
Extracts legible text from uploaded screenshots and images using the native Windows Media OCR
engine (winocr) with Pillow validation and graceful fallbacks.
"""

import io
import logging
from typing import Dict, Any, Tuple
from PIL import Image

logger = logging.getLogger("scamshield.ocr")

ALLOWED_MIME_TYPES = {
    'image/png': 'PNG',
    'image/jpeg': 'JPEG',
    'image/jpg': 'JPEG',
    'image/webp': 'WEBP',
    'image/bmp': 'BMP',
}

MAX_FILE_SIZE_BYTES = 5 * 1024 * 1024  # 5 MB limit

def extract_text_from_image_bytes(image_bytes: bytes, filename: str = "screenshot.png") -> Tuple[str, Dict[str, Any]]:
    """
    Validates image bytes, dimensions, and performs optical character recognition.
    Returns:
    - extracted text (str)
    - metadata dictionary with dimensions, detected lines count, and engine info.
    """
    if not image_bytes or len(image_bytes) == 0:
        raise ValueError("Uploaded file is empty (0 bytes). Please upload a valid image.")

    if len(image_bytes) > MAX_FILE_SIZE_BYTES:
        raise ValueError(
            f"Uploaded file exceeds maximum limit of 5MB (size: {len(image_bytes)/(1024*1024):.2f}MB)."
        )

    # Validate image integrity using PIL
    try:
        image = Image.open(io.BytesIO(image_bytes))
        image.verify()
        # Re-open for actual processing
        image = Image.open(io.BytesIO(image_bytes))
    except Exception as e:
        raise ValueError(f"Uploaded file is not a valid or readable image: {str(e)}")

    width, height = image.size
    image_format = image.format or "UNKNOWN"

    extracted_text = ""
    lines_detected = 0
    engine_used = "native-winocr"

    # 1. Primary Engine: Native Windows Media OCR (winocr in isolated thread)
    try:
        import winocr
        import concurrent.futures

        image_rgba = image.convert('RGBA')

        # Execute winocr in an isolated thread so asyncio.run() doesn't conflict with any active server event loop
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit(winocr.recognize_pil_sync, image_rgba)
            result = future.result(timeout=15)

        if result and isinstance(result, dict):
            extracted_text = result.get('text', '').strip()
            lines = result.get('lines', [])
            lines_detected = len(lines) if lines else len(extracted_text.splitlines())
    except Exception as err:
        logger.warning(f"winocr execution failed: {err}. Attempting secondary fallback.")


    # 2. Secondary Fallback: pytesseract
    if not extracted_text:
        try:
            import pytesseract
            extracted_text = pytesseract.image_to_string(image).strip()
            if extracted_text:
                engine_used = "pytesseract"
                lines_detected = len(extracted_text.splitlines())
        except Exception:
            pass

    metadata = {
        'filename': filename,
        'width': width,
        'height': height,
        'format': image_format,
        'file_size_kb': round(len(image_bytes) / 1024, 1),
        'lines_detected': lines_detected,
        'engine': engine_used,
        'has_text': bool(extracted_text.strip()),
    }

    return extracted_text.strip(), metadata
