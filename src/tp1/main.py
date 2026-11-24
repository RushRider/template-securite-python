from tp1.utils.capture import Capture
from tp1.utils.config import logger
import argparse
import json


def main():

    #fix pour lire les arguments

    parser = argparse.ArgumentParser("tp1")
    parser.add_argument("--pcap", required=True)
    parser.add_argument("--out", required=True)
    args = parser.parse_args()

    logger.info("Starting TP1")

    #ouverture du pcap et lancement de l'analyse

    capture = Capture(args.pcap)

    logger.info("Analyse de la capture")

    capture.analyse()

    # création du json pour le rapport

    report = {
        "protocols": capture.get_protocols(),
        "attacks": capture.get_attacks(),
        "flag": capture.get_flag(),
    }

    #ecriture du rapport dans le chemin output

    with open(args.out, "w") as f:
        json.dump(report, f, indent=2)

    logger.info(f"Rapport écrit dans {args.out}")

if __name__ == "__main__":
    main()
