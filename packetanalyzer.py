import scapy.all as scapy

def sniff_packets(interface, count):
    print("[+] Sniffing started on interface " + interface)
    scapy.sniff(iface=interface, count=count, prn=process_packet)

def process_packet(packet):
    if packet.haslayer(scapy.IP):
        ip_src = packet[scapy.IP].src
        ip_dst = packet[scapy.IP].dst
        protocol = packet[scapy.IP].proto

        print(f"IP Source: {ip_src} --> IP Destination: {ip_dst} Protocol: {protocol}")

        if packet.haslayer(scapy.Raw):
            payload = packet[scapy.Raw].load
            print(f"Raw Data: {payload.hex()}")

def main():
    interface = input("Enter the interface to sniff on (e.g., eth0): ")
    count = int(input("Enter the number of packets to capture: "))
    sniff_packets(interface, count)

if __name__ == "__main__":
    main()
