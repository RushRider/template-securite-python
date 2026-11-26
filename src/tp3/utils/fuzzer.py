from pathlib import Path
import requests



def fuzz(target: str) -> str:
    mots = (Path(__file__).parent / "wordlist.txt").read_text().split()
    for mot in mots:
        url = f"{target}/{mot}"
        r = requests.get(url, timeout=5)
        if r.status_code == 200 and "captcha" in r.text.lower():
            return url
    raise RuntimeError("endpoint pas trouvé :/")