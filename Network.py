import psutil
import socket
import logging
import os
from tqdm import tqdm
from scapy.all import sniff, conf, IP
import subprocess

log_file = 'network_activity.log'


if os.path.exists(log_file):
    os.remove(log_file)

# Configure logging
logging.basicConfig(filename=log_file, level=logging.INFO)

def list_connections():
    connections = psutil.net_connections()
    
    for conn in tqdm(connections, desc='Processing connections', unit='connection'):
        if conn.status == 'ESTABLISHED':
            laddr = f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "N/A"
            raddr = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "N/A"
            try:
                process = psutil.Process(conn.pid)
                pname = process.name()
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                pname = "N/A"
            
            logging.info(f"Proto: {conn.type} | Local Address: {laddr} | Remote Address: {raddr} | Status: {conn.status} | PID: {conn.pid} | Process Name: {pname}")
    logging.info(f"/////////////////////////////////////////////////////////////////////////////////////////////////")
    for conn in tqdm(connections, desc='Processing connections', unit='connection'):
        if conn.status == 'CLOSE_WAIT':
            laddr = f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "N/A"
            raddr = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "N/A"
            try:
                process = psutil.Process(conn.pid)
                pname = process.name()
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                pname = "N/A"
            
            logging.info(f"Proto: {conn.type} | Local Address: {laddr} | Remote Address: {raddr} | Status: {conn.status} | PID: {conn.pid} | Process Name: {pname}")
    logging.info(f"/////////////////////////////////////////////////////////////////////////////////////////////////")
    for conn in tqdm(connections, desc='Processing connections', unit='connection'):
        if conn.status == 'LISTEN':
            laddr = f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "N/A"
            raddr = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "N/A"
            try:
                process = psutil.Process(conn.pid)
                pname = process.name()
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                pname = "N/A"
            
            logging.info(f"Proto: {conn.type} | Local Address: {laddr} | Remote Address: {raddr} | Status: {conn.status} | PID: {conn.pid} | Process Name: {pname}")
    logging.info(f"/////////////////////////////////////////////////////////////////////////////////////////////////")


def list_interfaces_psutil():
    interfaces = psutil.net_if_addrs()
    for interface, addrs in interfaces.items():
        for addr in addrs:
            if addr.family == socket.AF_INET:
                logging.info(f"Interface: {interface} | IP: {addr.address} | Netmask: {addr.netmask}")
            elif addr.family == psutil.AF_LINK:
                logging.info(f"Interface: {interface} | MAC: {addr.address}")

def packet_callback(packet):
    logging.info(packet.summary())

def start_sniffing():
    conf.L3socket = conf.L3socket
    sniff(prn=packet_callback, count=10, filter="ip")  # Capture 10 IP packets

def run_command(command):
    result = subprocess.run(command, shell=True, capture_output=True, text=True)
    logging.info(result.stdout)

if __name__ == "__main__":
    list_connections()
    list_interfaces_psutil()
    start_sniffing()
    run_command('netsh advfirewall show allprofiles')  
