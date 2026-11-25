import json

from tp2.utils.report import Report
from tp2.utils.sample import Sample
from tp2.utils.scanner import YaraScanner


def _sample(tmp_path, data: bytes) -> Sample:
    f = tmp_path / "echantillon.bin"
    f.write_bytes(data)
    return Sample(str(f))



def test_get_file_metadata(tmp_path):
    sample = _sample(tmp_path, b"hello world")
    meta = sample.get_file_metadata()
    assert meta["size"] == 11
    assert len(meta["sha256"]) == 64
    assert "entropy" in meta


def test_shannon_entropy(tmp_path):
    sample = _sample(tmp_path, b"\x00" * 100)
    assert sample.shannon_entropy() == 0.0


def test_extract_iocs(tmp_path):
    sample = _sample(tmp_path, b"http://c2.example.test/gate.php 185.10.20.30")
    iocs = sample.extract_iocs()
    assert "185.10.20.30" in iocs["ips"]
    assert "c2.example.test" in iocs["domains"]


def test_extract_flag(tmp_path):
    data = b"FLAG=ESGI{vraiflagtututu_123} ... confirmed flag is ESGI{leurre_456}"
    sample = _sample(tmp_path, data)
    assert sample.extract_flag() == "ESGI{vraiflagtututu_123}"


def test_yara_scan(tmp_path):
    regle = tmp_path / "test.yar"
    regle.write_text('rule Demo { strings: $a = "malware" condition: $a }')
    scanner = YaraScanner(str(tmp_path))
    assert "Demo" in scanner.scan(b"malware alert")


def test_generate_json(tmp_path):
    out = tmp_path / "res.json"
    Report({"flag": "ESGI{x}"}).generate_json(str(out))
    assert json.loads(out.read_text())["flag"] == "ESGI{x}"