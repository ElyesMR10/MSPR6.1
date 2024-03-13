import socket
from pathlib import Path
import nmap
import tkinter as tk
import requests
from getmac import get_mac_address
import json


fenetre = tk.Tk()
fenetre.title("HARVESTER")
fenetre.geometry("500x500")

def update_scan():
    list_box.delete(0, tk.END)
    with open("test3.json") as f:
        devices_list = json.load(f)
        for device in devices_list:
            list_box.insert(tk.END, f"{device['ip']}\t{device['state']}\t{device['latency']}\t{device['hostnames']}\t{device['mac']}\t{device['ports']}")

def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
    finally:
        s.close()
    return local_ip

def name_host():
    hostname = socket.gethostname()
    return hostname

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
    mac = get_mac_address(ip=ip)
    nm.scan(ip)
    devices = {
        "ip": ip,
        "state": nm[ip].state(),
        "hostnames": nm[ip].hostnames(),
        "timestr": nm.scanstats()["timestr"],
        "latency": nm.scanstats()["elapsed"],
        "mac": mac,
        "ports": nm[ip].all_tcp()
    }
    with open ("test3.json", "w") as f:
        json.dump(devices, f)

    devices_list.append(devices)
    return devices_list


def onclick():
    list_box.delete(0, tk.END)
    for ip in decouverte_nmap():
        devices_list.append(nmap_scan(ip))
    update_widget()

def update_widget():
    entry.delete(0, tk.END)
    entry.insert(0, len(devices_list))
    entry2.delete(0, tk.END)
    entry2.insert(0, name_host())
    entry3.delete(0, tk.END)
    entry3.insert(0, get_local_ip())

    list_box.delete(0, tk.END)
    for device in devices_list:
        if isinstance(device, list):
            device = device[0]
        list_box.insert(tk.END, f"{device['ip']}\t{device['state']}\t{device['latency']}\t{device['hostnames']}\t{device['mac']}\t{device['ports']}")

devices_list = []
def nombre_hotes():
    return len(decouverte_nmap())

def move_entry(event):
    x, y = event.x, event.y
    entry.place(x=x, y=y)

def move_label(event):
    x, y = event.x, event.y
    entry.place(x=x, y=y)

def move_listbox(event):
    x, y = event.x, event.y
    entry.place(x=x, y=y)



entry = tk.Entry(fenetre,width=10)
entry.place(x=180, y=30)
entry.insert(0, nombre_hotes())

entry2 = tk.Entry(fenetre,width=30)
entry2.place(x=180, y=60)
entry2.insert(0, name_host())

entry3 = tk.Entry(fenetre,width=30)
entry3.place(x=180, y=90)
entry3.insert(0, get_local_ip())

label = tk.Label(fenetre, text="Nombre d'hotes actifs")
label.place(x=30, y=30)

label2 = tk.Label(fenetre, text="Nom de l'hote")
label2.place(x=30, y=60)

label3 = tk.Label(fenetre, text="IP de l'hote")
label3.place(x=30, y=90)


list_box = tk.Listbox(fenetre, font="Arial 15", bg="#999595", width=49, height=15)
list_box.place(x=30, y=180)
list_box.insert(0, devices_list)


botton_scan = tk.Button(fenetre, text="scan", font="Arial 15", bg="#999595", width=45,command=onclick)
botton_scan.place(x=30, y=130)



update_widget()



#API_url = 'http://127.0.0.1:5000/infos'
#data = { "devices_list": devices_list}
#response = requests.post(API_url, json=data)
    


fenetre.mainloop()