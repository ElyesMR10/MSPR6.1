import socket
import subprocess
import json
from pathlib import Path
from datetime import datetime
import nmap
import requests
devices_list = []
def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
    finally:
        s.close()
    return local_ip

def decouverte_nmap():
    local_ip = get_local_ip()
    mn = nmap.PortScanner()
    mn.scan(hosts=f"{local_ip}/24", arguments="-sn")
    hosts_list = []
    for host in mn.all_hosts():
        hosts_list.append(host)
    return hosts_list

def nmap_scan(ip):
    nm = nmap.PortScanner()
    nm.scan(ip, arguments="-sn -A")
    for host in nm.all_hosts():
        devices = {
            "ip": host,
            "state": nm[host].state(),
            "hostnames": nm[host].hostnames(),
            "latency": nm[host].latency() if 'latency' in nm[host] else None,
            "mac": nm[host].get('addresses', {}).get('mac', None),
            "ports": nm[host].all_tcp()
        }
        devices_list.append(devices)
    return devices_list

if __name__ == "__main__":
    resusltat_decouverte = decouverte_nmap()
    """print("----------------------------------------")
    for Host in resusltat_decouverte:
        print(f"IP: {Host}")"""

    for ip in resusltat_decouverte:
        resultat = nmap_scan(ip)
        print(f"recherche {ip}")    

    print(devices_list)



#API_url = 'http://127.0.0.1:5000/infos'
#data = {"ip_local": ip_local, "devices_list": devices_list}
#response = requests.post(API_url, json=data)
