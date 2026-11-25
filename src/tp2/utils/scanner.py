from pathlib import Path
import yara


class YaraScanner:
    def __init__(self, rules_path: str = "rules/rules.yar") -> None:
        self.rules_path = rules_path

    def scan(self, data: bytes) -> list[str]:
        file = {p.stem: str(p) for p in Path(self.rules_path).glob("*.yar")}
        if not file:
            return []
        rules = yara.compile(filepaths=file)
        match = rules.match(data=data)
        return [m.rule for m in match]
