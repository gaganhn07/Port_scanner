#!/bin/python3
import re
from scapy.all import *

def scan_ports(host, ports):
    print("\n\nScanning..")
    print("Host: ", host)
    print("Ports: ", ports)

    # Send SYN packets to specified ports
    ans, unans = sr(IP(dst=host) / TCP(dport=ports, flags="S"), verbose=0, timeout=2)

    # Display open ports
    for response in ans:
        s, r = response
        if r.haslayer(TCP) and r.getlayer(TCP).flags == 0x12:  # SYN-ACK response
            print("[+] Port {} is Open".format(s[TCP].dport))
            # Send RST to close the connection
            sr(IP(dst=host) / TCP(dport=s[TCP].dport, flags="R"), timeout=1, verbose=0)

    # Display closed or filtered ports
    for response in unans:
        s = response
        print("[-] Port {} is Closed or Filtered".format(s[TCP].dport))

def main():
    try:
        # Input host and ports
        host = input("Enter a host address (IP or domain name): ").strip()
        ports_input = input("Enter the ports to scan (comma-separated): ").strip()

        # Validate host as an IP address or domain name
        ip_regex = r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$"
        domain_regex = r"^(?!\-)([A-Za-z0-9\-]{1,63}(?<!\-)\.)+[A-Za-z]{2,6}$"

        if not (re.match(ip_regex, host) or re.match(domain_regex, host)):
            print("[-] Invalid IP address or domain name format.")
            return

        # Validate and convert port numbers
        if ports_input:
            ports = []
            for p in ports_input.split(","):
                try:
                    port = int(p.strip())
                    if 1 <= port <= 65535:
                        ports.append(port)
                    else:
                        print(f"[-] Port number {port} is out of range (1-65535).")
                except ValueError:
                    print(f"[-] Invalid port number: {p}. Please enter numeric values only.")
                    return
        else:
            print("[-] No ports specified.")
            return

        # Proceed to port scanning
        scan_ports(host, ports)

    except Exception as e:
        print("[-] An unexpected error occurred:", e)
        print("[-] Exiting...")

if __name__ == "__main__":
    main()
