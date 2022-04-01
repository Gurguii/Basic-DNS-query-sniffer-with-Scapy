from scapy.all import IP,sniff,DNS
import argparse
import re
import os

parser=argparse.ArgumentParser(description="DNS query sniffer")

parser.add_argument("-ip", required=True, help="Host objetivo // Target host")
parser.add_argument("-auto", required=False,action="store_true", help="")

args=parser.parse_args()

if not re.match("^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$", args.ip):
    print("Por favor introduce una IP correcta")
    print("Saliendo...")

def DNSqrSniffer(packet):
    if IP in packet:
        ip_origen=packet[IP].src
        ip_destino=packet[IP].dst
        if packet.haslayer(DNS) and packet.getlayer(DNS).qr == 0:
            print(f"{ip_origen}         {ip_destino}              {packet.getlayer(DNS).qd.qname}")
            
if args.auto:
    print("Pulsa ctrl+c para terminar la esnifada")
    print(" ORIGEN                  DESTINO                     QUERY")
    sniff(filter=f"host {args.ip} and port 53", store=0, prn=DNSqrSniffer).summary()
    print("Cerrando...")
else:
    while True:
        try:
            int(input("¿Cuantos paquetes quieres capturar?: "))
            break
        except KeyboardInterrupt:
            os.system("clear")
            print("Bye bye :)")
            exit()
        except ValueError :
            os.system("clear")
            print("Por favor introduce un numero")
            continue
    sniff(filter=f"host {args.ip} and port 53", store=0, prn=DNSqrSniffer).summary()
    print("Cerrando...")

