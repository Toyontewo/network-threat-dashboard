"""
generate_sample_pcap.py — creates a synthetic .pcap file containing
simulated threat traffic for testing without root privileges.

Run once:
    python generate_sample_pcap.py

Then test the dashboard:
    python main.py --pcap samples/capture.pcap --report
"""

import os, logging
os.environ["SCAPY_DISABLE_IPV6"] = "1"
logging.getLogger("scapy").setLevel(logging.CRITICAL)

from scapy.config import conf
conf.verb = 0

from scapy.layers.l2 import Ether, ARP
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.dns import DNS, DNSQR
from scapy.utils import wrpcap

import random
random.seed(42)

packets = []

def syn(src, dst, dport):
    return IP(src=src, dst=dst, ttl=64) / TCP(sport=random.randint(1024, 65535), dport=dport, flags="S")

def arp_reply(src_mac, src_ip, dst_ip):
    return Ether(src=src_mac, dst="ff:ff:ff:ff:ff:ff") / ARP(
        op=2, hwsrc=src_mac, psrc=src_ip, pdst=dst_ip
    )

def dns_query(src, dst, qname):
    return (
        IP(src=src, dst=dst) /
        UDP(sport=random.randint(1024, 65535), dport=53) /
        DNS(rd=1, qd=DNSQR(qname=qname))
    )

def normal_tcp(src, dst, dport):
    return IP(src=src, dst=dst) / TCP(sport=random.randint(1024, 65535), dport=dport, flags="S")

# 1. Normal background traffic
NORMAL_IPS = ["192.168.1.10", "192.168.1.20", "192.168.1.30"]
for i in range(80):
    src = random.choice(NORMAL_IPS)
    packets.append(normal_tcp(src, "8.8.8.8", random.choice([80, 443, 8080])))

# 2. Port scan (CRITICAL — 38 ports)
scanner = "10.0.0.99"
target = "192.168.1.1"
for port in range(1, 39):
    packets.append(syn(scanner, target, port))

# 3. ARP spoofing
packets.append(arp_reply("aa:bb:cc:dd:ee:ff", "192.168.1.1", "192.168.1.10"))
packets.append(arp_reply("de:ad:be:ef:ca:fe", "192.168.1.1", "192.168.1.10"))

# 4. Suspicious DNS
for d in ["xf93nkqp2malware.xyz", "c2-botnet-endpoint.ru",
          "hgfkwpqmzjxlnbvsdacrtu.top", "exfil-data-pipe.tk"]:
    packets.append(dns_query("192.168.1.10", "8.8.8.8", d))

# 5. SSH brute force (55 SYNs)
for _ in range(55):
    packets.append(syn("203.0.113.77", "192.168.1.50", 22))

# 6. FTP brute force
for _ in range(30):
    packets.append(syn("198.51.100.5", "192.168.1.60", 21))

# 7. More normal traffic
for i in range(40):
    packets.append(normal_tcp(random.choice(NORMAL_IPS), "1.1.1.1", 443))

os.makedirs("samples", exist_ok=True)
wrpcap("samples/capture.pcap", packets)
print(f"[+] Written {len(packets)} packets -> samples/capture.pcap")
print("[+] Now run:  python main.py --pcap samples/capture.pcap --report")
