import base64
import socket
import threading
from tp3.main import _xor, breach_network, breach_web
from tp3.utils import fuzzer


def test_xor_est_son_propre_inverse():
    data = b"token1234567890ab"
    key = bytes.fromhex("ff193b22")
    assert _xor(_xor(data, key), key) == data


def test_fuzz(monkeypatch):
    def _fake_get(url, timeout=5):
        texte = "<form>captcha</form>" if url.endswith("/internal-panel") else ""
        code = 200 if url.endswith("/internal-panel") else 404
        return type("R", (), {"status_code": code, "text": texte})()
    monkeypatch.setattr(fuzzer.requests, "get", _fake_get)
    assert fuzzer.fuzz("http://cible").endswith("/internal-panel")


def test_breach_network():
    key = bytes.fromhex("ff193b22")
    flag = "ESGI{chain_test}"
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    port = srv.getsockname()[1]

    def serveur():
        conn, _ = srv.accept()
        conn.sendall(b"intro\n")
        token = b"abcdef0123456789"
        conn.sendall(base64.b64encode(_xor(token, key)) + b"\n")
        if conn.recv(1024).strip() == token:
            conn.sendall(f"OK {flag}\n".encode())
        conn.close()

    threading.Thread(target=serveur, daemon=True).start()
    assert breach_network("127.0.0.1", port, key) == flag
    srv.close()


def test_breach_web(monkeypatch):
    import tp3.main as m

    monkeypatch.setattr(m, "fuzz", lambda t: f"{t}/internal-panel")

    class _FakeCaptcha:
        def __init__(self, s, u): ...
        def capture(self): ...
        def solve(self): ...
        def get_value(self): return "ABCDE"

    monkeypatch.setattr(m, "Captcha", _FakeCaptcha)

    class _Resp:
        status_code = 200
        def json(self):
            return {"flag1": "ESGI{web_test}", "host": "1.2.3.4", "port": 9090, "key": "ff193b22"}

    class _FakeSession:
        def get(self, u, timeout=5): ...
        def post(self, u, data=None, timeout=5): return _Resp()

    monkeypatch.setattr(m.requests, "Session", lambda: _FakeSession())
    host, port, key = m.breach_web("http://cible")
    assert (host, port, key) == ("1.2.3.4", 9090, bytes.fromhex("ff193b22"))