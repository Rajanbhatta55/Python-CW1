import scapy.all as scapy
import re
from collections import defaultdict
import time
import smtplib
from email.mime.text import MIMEText
import matplotlib.pyplot as plt
import threading
import argparse


class IntrusionDetectionSystem:
    def __init__(self, interface, email=None, threshold=100):
        self.interface = interface
        self.email = email
        self.threshold = threshold
        self.packet_count = defaultdict(int)
        self.signatures = {
            "SQL Injection": re.compile(r'SELECT|UNION|DROP|INSERT|DELETE|UPDATE', re.IGNORECASE),
            "XSS Attack": re.compile(r'<script>|javascript:', re.IGNORECASE),
            "Port Scan": re.compile(r'TCP SYN .* Flags=S', re.IGNORECASE),
            "DoS Attack": re.compile(r'ICMP .* Type=8', re.IGNORECASE)
        }

        self.log_file = "ids_log.txt"
        self.running = False

    def start(self):
        self.running = True
        print(f"Starting IDS on interface {self.interface}...")
        sniff_thread = threading.Thread(target=self._sniff_packets, daemon=True)
        sniff_thread.start()

    def stop(self):
        self.running = False
        print("IDS stopped.")

    def _sniff_packets(self):
        while self.running:
            try:
                scapy.sniff(iface=self.interface, prn=self._analyze_packet, store=False, timeout=1)
            except Exception as e:
                print(f"Sniffing error: {e}")
                self.running = False

    def _analyze_packet(self, packet):
        if not self.running:
            return

        if packet.haslayer(scapy.IP):
            self._detect_signature_based(packet)
            self._detect_anomaly(packet)

    def _detect_signature_based(self, packet):
        for attack_type, pattern in self.signatures.items():
            if packet.haslayer(scapy.Raw):
                payload = str(packet[scapy.Raw].load)
                if pattern.search(payload):
                    self._log_alert(f"{attack_type} detected from {packet[scapy.IP].src}")
                    self._send_alert(f"{attack_type} detected from {packet[scapy.IP].src}")

    def _detect_anomaly(self, packet):
        src_ip = packet[scapy.IP].src
        self.packet_count[src_ip] += 1
        if self.packet_count[src_ip] > self.threshold:
            self._log_alert(f"Anomaly detected: High traffic from {src_ip}")
            self._send_alert(f"Anomaly detected: High traffic from {src_ip}")

    def _log_alert(self, message):
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        log_entry = f"[{timestamp}] {message}\n"
        with open(self.log_file, "a") as log:
            log.write(log_entry)
        print(log_entry.strip())

    def _send_alert(self, message):
        if self.email:
            try:
                msg = MIMEText(message)
                msg['Subject'] = 'IDS Alert'
                msg['From'] = 'ids@example.com'
                msg['To'] = self.email

                server = smtplib.SMTP('localhost')
                server.send_message(msg)
                server.quit()
            except Exception as e:
                print(f"Failed to send email: {e}")

    def plot_traffic(self):
        if not self.packet_count:
            print("No traffic data to plot.")
            return
        ips = list(self.packet_count.keys())
        counts = list(self.packet_count.values())
        plt.bar(ips, counts, color='blue')
        plt.xlabel('IP Address')
        plt.ylabel('Packet Count')
        plt.title('Network Traffic by IP')
        plt.xticks(rotation=45)
        plt.tight_layout()
        plt.savefig('traffic_plot.png')
        plt.show()


def main():
    parser = argparse.ArgumentParser(description="Advanced Intrusion Detection System (IDS)")
    parser.add_argument("interface", help="Network interface to monitor")
    parser.add_argument("--email", help="Email address to send alerts to", default=None)
    parser.add_argument("--threshold", type=int, default=100, help="Traffic threshold for anomaly detection")
    args = parser.parse_args()

    ids = IntrusionDetectionSystem(args.interface, args.email, args.threshold)
    try:
        ids.start()
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        ids.stop()
        ids.plot_traffic()


if __name__ == "__main__":
    main()
