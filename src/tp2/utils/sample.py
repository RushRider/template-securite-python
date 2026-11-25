import math
from collections import Counter
import hashlib
import magic
import re


class Sample:
    def __init__(self, path: str) -> None:
        self.path = path
        self.data = open(path, "rb").read()


    def get_file_metadata(self) -> dict:
        sha = hashlib.sha256(self.data).hexdigest()
        md5 = hashlib.md5(self.data).hexdigest()
        taille = len(self.data)
        fichier_type = magic.from_buffer(self.data)
        entropie = self.shannon_entropy()

        return {"sha256": sha, "md5": md5, "size": taille, "file_type": fichier_type, "entropy": entropie}

    def shannon_entropy(self) -> float:
        if not self.data:
            return 0.0
        freq = Counter(self.data)
        n = len(self.data)
        return -sum((c / n) * math.log2(c / n) for c in freq.values())



    def extract_iocs(self) -> dict:

        chaine = re.findall(rb"[\x20-\x7e]{4,}", self.data)
        text = "\n".join(c.decode("ascii") for c in chaine)

        domains = re.findall(r"(?:[a-z0-9-]+\.)+test\b", text)
        ips = re.findall(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", text)
        urls = re.findall(r"https?://[^\s\"'<>]+", text)
        mutex = re.findall(r"(?:Global|Local)\\[^\s\"'<>]+", text)
        registry = re.findall(r"HK(?:LM|CU|CR|U|CC)\\[^\s\"'<>]+", text)

        return {
            "domains": domains,
            "ips": ips,
            "urls": urls,
            "mutex": mutex,
            "registry": registry
        }


    def extract_flag(self) -> str:
        m = re.search(rb"FLAG=(ESGI\{[^}]*\})", self.data)
        if m:
            flag = m.group(1).decode("ascii")
            return flag
        return ""


    def parse_binary(self) -> dict:
        """imports / sections via lief (si PE/ELF)."""
        raise NotImplementedError
