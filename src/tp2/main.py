import argparse

from tp2.utils.report import Report
from tp2.utils.triage import Triage

from pathlib import Path

def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--samples", required=True)
    ap.add_argument("--rules", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--llm", choices=["openrouter", "ollama"], default="openrouter")
    args = ap.parse_args()


    Path(args.out).mkdir(parents=True, exist_ok=True)
    for file in Path(args.samples).iterdir():
        if not file.is_file():
            continue

        triage = Triage(str(file), args.llm, args.rules)
        result = triage.run()

        report_name = Path(args.out) / f"{file.name}.triage.json"

        report = Report(result)
        report.generate_json(str(report_name))


if __name__ == "__main__":
    main()
