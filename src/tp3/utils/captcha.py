import io
from PIL import Image, ImageDraw
from tp3.utils.captcha import Captcha


class _FakeSession:
    def __init__(self, png: bytes) -> None:
        self.png = png

    def get(self, url, timeout=5):
        r = type("R", (), {})()
        r.content = self.png
        return r


def _png(code: str) -> bytes:
    img = Image.new("RGB", (220, 90), "white")
    ImageDraw.Draw(img).text((25, 30), code, fill="black")
    buf = io.BytesIO()
    img.save(buf, "PNG")
    return buf.getvalue()


def test_captcha_solve(monkeypatch):
    import tp3.utils.captcha as capmod
    
    monkeypatch.setattr(capmod.pytesseract, "image_to_string", lambda img, config="": "kxmtr\n")
    captcha = Captcha(_FakeSession(_png("KXMTR")), "http://x/captcha.png")
    captcha.capture()
    captcha.solve()
    assert captcha.get_value() == "KXMTR"