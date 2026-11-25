import math
from collections import Counter
import hashlib
import magic


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
        """domaines, ips, urls, mutex, registry (regex sur les strings)."""
        raise NotImplementedError

    def parse_binary(self) -> dict:
        """imports / sections via lief (si PE/ELF)."""
        raise NotImplementedError
