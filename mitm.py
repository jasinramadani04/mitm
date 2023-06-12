import sys
import time
import threading
from scapy.all import *
from scapy.layers import http

# Funksioni i përpunimit të paketave
def process_packet(packet):
    if packet.haslayer(http.HTTPRequest):
        # Përzgjidhni dhe modifikoni kërkesën HTTP sipas nevojës tuaj
        packet.show()
        
# Funksioni i pranimit të paketave
def sniff_packets(iface):
    sniff(iface=iface, prn=process_packet, store=False)

# Funksioni për të injektuar një kërkesë HTTP e modifikuar
def inject_packet(packet):
    # Modifikoni kërkesën HTTP sipas nevojës tuaj
    modified_packet = packet
    send(modified_packet)

# Funksioni i injektimit të paketave
def inject_packets(iface):
    sniff(iface=iface, prn=inject_packet, store=False)

# Main funksioni
def main():
    if len(sys.argv) != 2:
        print("Usage: python mitm.py [interface]")
        sys.exit(1)

    interface = sys.argv[1]

    # Filtroni dhe përpunoni paketat e rrjetit
    sniff_thread = threading.Thread(target=sniff_packets, args=(interface,))
    sniff_thread.start()

    # Injektoni paketa e modifikuar
    inject_thread = threading.Thread(target=inject_packets, args=(interface,))
    inject_thread.start()

    # Prisni derisa të mbyllet programi
    while True:
        try:
            time.sleep(1)
        except KeyboardInterrupt:
            print("Exiting...")
            sys.exit(0)

if __name__ == "__main__":
    main()
