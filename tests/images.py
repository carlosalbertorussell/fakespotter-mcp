"""
Deterministic image / PDF fixtures built at test time with real Pillow,
PyMuPDF and qrcode (nothing binary is committed).
"""
from __future__ import annotations

import io

from PIL import Image, ImageDraw, ImageEnhance


def to_bytes(img: Image.Image, fmt: str = "PNG", **kw) -> bytes:
    buf = io.BytesIO()
    img.save(buf, format=fmt, **kw)
    return buf.getvalue()


def invoice_template(total: str = "1,234.56") -> Image.Image:
    """A fake supplier invoice: logo block, header bar, table lines, total."""
    img = Image.new("RGB", (600, 800), "white")
    d = ImageDraw.Draw(img)
    d.rectangle((30, 30, 190, 130), fill=(20, 60, 160))           # logo
    d.ellipse((60, 45, 160, 115), fill=(250, 200, 30))
    d.rectangle((220, 40, 570, 70), fill=(40, 40, 40))             # header bar
    d.rectangle((30, 160, 570, 200), fill=(200, 215, 235))         # table head
    for y in range(220, 620, 40):
        d.line((30, y, 570, y), fill=(120, 120, 120), width=2)
    d.rectangle((360, 650, 570, 720), outline=(0, 0, 0), width=4)  # total box
    d.text((380, 675), f"TOTAL USD {total}", fill=(0, 0, 0))
    return img


def near_duplicate(img: Image.Image) -> Image.Image:
    """Same template, edited total, slightly brighter, re-compressed as JPEG."""
    edited = img.copy()
    d = ImageDraw.Draw(edited)
    d.rectangle((362, 652, 568, 718), fill="white")
    d.text((380, 675), "TOTAL USD 9,234.56", fill=(0, 0, 0))
    edited = ImageEnhance.Brightness(edited).enhance(1.05)
    return Image.open(io.BytesIO(to_bytes(edited, "JPEG", quality=70))).convert("RGB")


def unrelated_image() -> Image.Image:
    """A different document: vertical stripes and a diagonal band."""
    img = Image.new("RGB", (600, 800), (235, 235, 235))
    d = ImageDraw.Draw(img)
    for x in range(0, 600, 60):
        d.rectangle((x, 0, x + 25, 800), fill=(30, 120, 60))
    d.polygon([(0, 800), (600, 0), (600, 200), (150, 800)], fill=(180, 30, 30))
    return img


def blank_image() -> Image.Image:
    return Image.new("RGB", (400, 400), "white")


def qr_image(data: str) -> Image.Image:
    import qrcode

    qr = qrcode.QRCode(error_correction=qrcode.constants.ERROR_CORRECT_M, box_size=8, border=4)
    qr.add_data(data)
    qr.make(fit=True)
    return qr.make_image(fill_color="black", back_color="white").get_image().convert("RGB")


def pdf_with_image(img_png: bytes | None, text: str = "INVOICE 0001") -> bytes:
    """One A4 page with ``text`` and, optionally, the PNG drawn at the top right."""
    import pymupdf

    doc = pymupdf.open()
    page = doc.new_page()
    page.insert_text((72, 72), text, fontsize=14)
    if img_png is not None:
        page.insert_image(pymupdf.Rect(330, 60, 530, 260), stream=img_png)
    data = doc.tobytes()
    doc.close()
    return data
