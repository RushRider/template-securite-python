from collections import Counter

from scapy.all import rdpcap, Ether, ARP, IP, TCP, UDP, ICMP
from scapy.layers.dns import DNS

from tp1.utils.config import logger


class Capture:
    def __init__(self, pcap_path: str):
        logger.info(f"Lecture du pcap {pcap_path}")
        self.packets = rdpcap(pcap_path)
        self.protocols: dict[str, int] = {}
        self.attacks: list[dict] = []
        self.flag = ""

    def analyse(self):
        self.count_protocols()
        self.detect_arp_spoof()
        self.detect_port_scan()

    def detect_arp_spoof(self):

        # detection de l'arp spoofing

        ip_mac = {}

        for pkt in self.packets:
            if pkt.haslayer(ARP):
                ip = pkt[ARP].psrc
                mac = pkt[ARP].hwsrc
                ip_mac.setdefault(ip, set()).add(mac)

        for ip, macs in ip_mac.items():
            if len(macs) >= 2:
                for mac in macs:
                    self.attacks.append({"type": "arp_spoofing", "attacker": mac})


    def detect_port_scan(self):

        # detection d'un scan de port

        ip_ports = {}

        for pkt in self.packets:
            if pkt.haslayer(TCP) and pkt[TCP].flags == "S":
                ip = pkt[IP].src
                port = pkt[TCP].dport
                ip_ports.setdefault(ip, set()).add(port)

        for ip, ports in ip_ports.items():
            if len(ports) >= 20:
                self.attacks.append({"type": "port_scan", "attacker": ip})



    def count_protocols(self):
        compteur = Counter()    
        couches = {
            "Ethernet": Ether, "ARP": ARP, "IP": IP,
            "TCP": TCP, "UDP": UDP, "ICMP": ICMP, "DNS": DNS,
        }
        for pkt in self.packets:
            for nom, couche in couches.items():
                if pkt.haslayer(couche):
                    compteur[nom] += 1
        self.protocols = dict(compteur)

    def get_protocols(self) -> dict:
        return self.protocols

    def get_attacks(self) -> list:
        return self.attacks

    def get_flag(self) -> str:
        return self.flag