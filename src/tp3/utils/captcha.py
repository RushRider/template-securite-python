import io
import pytesseract
from PIL import Image


class Captcha:
    def __init__(self, session, url: str) -> None:
        self.session = session
        self.url = url
        self.image = None
        self.value = ""

    def capture(self) -> None:
        r = self.session.get(self.url, timeout=5)
        self.image = Image.open(io.BytesIO(r.content)).convert("L")

    def solve(self) -> None:
        bw = self.image.point(lambda p: 0 if p < 128 else 255)
        config = "--psm 7 -c tessedit_char_whitelist=ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
        self.value = pytesseract.image_to_string(bw, config=config).strip().upper()

    def get_value(self) -> str:
        return self.value