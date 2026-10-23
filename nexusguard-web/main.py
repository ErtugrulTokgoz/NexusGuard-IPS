from scapy.all import sniff, ARP, TCP, IP, Ether
import requests
import time
import subprocess
from collections import defaultdict

NEXUSGUARD_API = "http://localhost:3000"
WEBHOOK_SECRET = "nexusguard_super_secret_2024"
WHITELIST_IPS = ["212.156.190.140", "192.168.1.1", "172.20.10.1"]

arp_cache = {}
syn_counts = defaultdict(set)
dos_counts = defaultdict(int)
dos_timers = defaultdict(float)
alert_cooldowns = defaultdict(float)
blocked_ips = set() # Aynı IP'yi tekrar tekrar engellemeye çalışmamak için

def block_ip_windows(ip_address):
    """Windows Güvenlik Duvarı üzerinden IP'yi kalıcı olarak engeller."""
    if ip_address in blocked_ips or ip_address in WHITELIST_IPS:
        return
    
    rule_name = f"NexusGuard_Block_{ip_address}"
    command = f'netsh advfirewall firewall add rule name="{rule_name}" dir=in action=block remoteip={ip_address}'
    
    try:
        subprocess.run(command, shell=True, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        blocked_ips.add(ip_address)
        print(f"\n[!] KILL-SWITCH AKTİF: {ip_address} güvenlik duvarından engellendi!")
    except subprocess.CalledProcessError:
        print(f"\n[HATA] {ip_address} engellenemedi. Terminali Yönetici olarak çalıştırdığınızdan emin olun.")

def send_threat_alert(data):
    try:
        requests.post(f"{NEXUSGUARD_API}/api/threat-alert", headers={"x-ips-secret": WEBHOOK_SECRET}, json=data, timeout=3)
    except:
        pass

def analyze_packet(packet):
    # 1. ARP Spoofing Tespiti ve Engellemesi
    if packet.haslayer(ARP) and packet[ARP].op == 2:
        real_mac = arp_cache.get(packet[ARP].psrc)
        sender_mac = packet[ARP].hwsrc
        attacker_ip = packet[ARP].psrc
        
        if real_mac and real_mac != sender_mac:
            send_threat_alert({"threat_type": "ARP_SPOOFING", "attacker_ip": attacker_ip, "attacker_mac": sender_mac, "victim_ip": packet[ARP].pdst, "kill_switch_triggered": True, "details": {"expected_mac": real_mac, "received_mac": sender_mac}})
            block_ip_windows(attacker_ip)
        else:
            arp_cache[attacker_ip] = sender_mac
    
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        
        if src_ip in WHITELIST_IPS:
            return

        mac_addr = packet[Ether].src if packet.haslayer(Ether) else "Bilinmiyor"
        current_time = time.time()

        # 2. Port Scan Tespiti (Sadece loglar, engellemez)
        if packet.haslayer(TCP) and packet[TCP].flags == 'S':
            syn_counts[src_ip].add(packet[TCP].dport)
            if len(syn_counts[src_ip]) > 10:
                syn_counts[src_ip].clear()
                if current_time - alert_cooldowns[f"PORT_{src_ip}"] > 60:
                    send_threat_alert({"threat_type": "PORT_SCAN", "attacker_ip": src_ip, "attacker_mac": mac_addr, "victim_ip": dst_ip, "kill_switch_triggered": False, "details": {"scanned_ports": 15}})
                    alert_cooldowns[f"PORT_{src_ip}"] = current_time

        # 3. DoS Tespiti ve Engellemesi
        if not dos_timers[src_ip]:
            dos_timers[src_ip] = current_time
        
        dos_counts[src_ip] += 1
        time_diff = current_time - dos_timers[src_ip]

        if time_diff < 2:
            if dos_counts[src_ip] > 100:
                dos_counts[src_ip] = 0
                dos_timers[src_ip] = current_time
                if current_time - alert_cooldowns[f"DOS_{src_ip}"] > 60:
                    send_threat_alert({"threat_type": "DOS", "attacker_ip": src_ip, "attacker_mac": mac_addr, "victim_ip": dst_ip, "kill_switch_triggered": True, "details": {"packet_count": 1000}})
                    alert_cooldowns[f"DOS_{src_ip}"] = current_time
                    block_ip_windows(src_ip)
        else:
            dos_counts[src_ip] = 1
            dos_timers[src_ip] = current_time

print("[NexusGuard IPS] Aktif Koruma ve Dinleme Motoru Başlatıldı...")
sniff(prn=analyze_packet, store=False)