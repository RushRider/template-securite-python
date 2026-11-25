from tp2.utils.config import logger
from tp2.utils.llm import LLMTriage
from tp2.utils.sample import Sample
from tp2.utils.scanner import YaraScanner


class Triage:
    def __init__(self, path: str, backend: str, rules: str) -> None:
        self.path = path
        self.backend = backend
        self.scanner = YaraScanner(rules)
        self.llm = LLMTriage(backend)

    def run(self) -> dict:
        sample = Sample(self.path)
        logger.info(f"Triage de {self.path} ({len(sample.data)} octets)")

        meta = sample.get_file_metadata()
        iocs = sample.extract_iocs()
        flag = sample.extract_flag()
        # bininfo = sample.parse_binary()
        matches = self.scanner.scan(sample.data)
        # summary = json.dumps({"meta": meta, "iocs": iocs, "yara": matches, "bin": bininfo})
        # verdict = self.llm.triage(summary)

        return {
            "sha256": meta["sha256"],
            "md5": meta["md5"],
            "size": meta["size"],
            "entropy": meta["entropy"],
            "file_type": meta["file_type"],
            "iocs": iocs,
            "imports": [],
            "yara_matches": matches,
            "family_guess": "",
            "mitre_attack": [],
            "llm_summary": "",
            "score": 0,
            "flag": flag
        }