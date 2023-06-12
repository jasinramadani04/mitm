from scapy.all import *

def process_packet(packet):
    if packet.haslayer(http.HTTPRequest):
        http_layer = packet.getlayer(http.HTTPRequest)
        host = http_layer.Host.decode()

        if "sems.uni-pr.edu" in host:
            # Kërkesa është nga uebsajti i synuar
            print("Kërkesa nga uebsajti i synuar: ", host)
            # Shtoni logjikën tuaj për të shfaqur ose ruajtur informacione për përdoruesit
            # në varësi të kërkesave të dërguara nga uebsajti
            # ...

def main(interface):
    sniff(iface=interface, prn=process_packet, store=0)

if __name__ == "__main__":
    interface = "eth0"  # Ndryshoni ndërfaqen e rrjetit nëse është e nevojshme
    main(interface)
