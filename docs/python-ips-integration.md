# NexusGuard IPS — Python Motoru Entegrasyon Rehberi

Bu belge, Python (Scapy) IPS motorunun Next.js web sunucusuna nasıl veri göndereceğini açıklar.

## Gereksinimler

```bash
pip install requests
```

## Webhook Endpoint'leri

### 1. Tehdit Bildirimi — `/api/threat-alert`

```python
import requests

NEXUSGUARD_API = "http://localhost:3000"
# .env.local'deki IPS_WEBHOOK_SECRET ile aynı olmalı
WEBHOOK_SECRET = "nexusguard_super_secret_2024"

def send_threat_alert(threat_data: dict) -> bool:
    """Tespit edilen tehdidi NexusGuard web sunucusuna bildir."""
    try:
        response = requests.post(
            f"{NEXUSGUARD_API}/api/threat-alert",
            headers={
                "Content-Type": "application/json",
                "x-ips-secret": WEBHOOK_SECRET,
            },
            json=threat_data,
            timeout=5,
        )
        if response.status_code == 200:
            data = response.json()
            print(f"[IPS] Tehdit kaydedildi: {data['log_id']}")
            return True
        else:
            print(f"[IPS] Hata: {response.text}")
            return False
    except requests.RequestException as e:
        print(f"[IPS] Bağlantı hatası: {e}")
        return False


# ── ARP Zehirlenmesi tespitinde kullanım ──────────────────────────────
send_threat_alert({
    "threat_type": "ARP_SPOOFING",      # ARP_SPOOFING | PORT_SCAN | MITM | DOS
    "attacker_ip": "192.168.1.105",
    "attacker_mac": "aa:bb:cc:dd:ee:ff",
    "victim_ip": "192.168.1.1",
    "victim_mac": "11:22:33:44:55:66",
    "kill_switch_triggered": True,
    "details": {
        "packet_count": 150,
        "interface": "eth0",
        "detection_method": "gratuitous_arp",
    },
})
```

### 2. Cihaz Listesi Güncelleme — `/api/devices`

```python
def update_device_list(devices: list) -> bool:
    """Ağda tespit edilen cihaz listesini toplu güncelle."""
    try:
        response = requests.post(
            f"{NEXUSGUARD_API}/api/devices",
            headers={
                "Content-Type": "application/json",
                "x-ips-secret": WEBHOOK_SECRET,
            },
            json={"devices": devices},
            timeout=5,
        )
        return response.status_code == 200
    except requests.RequestException as e:
        print(f"[IPS] Cihaz güncelleme hatası: {e}")
        return False


# ── ARP taraması sonrası kullanım ─────────────────────────────────────
update_device_list([
    {
        "ip_address":  "192.168.1.1",
        "mac_address": "aa:bb:cc:dd:ee:01",
        "hostname":    "router",
        "vendor":      "Cisco",
    },
    {
        "ip_address":  "192.168.1.100",
        "mac_address": "aa:bb:cc:dd:ee:02",
        "hostname":    "laptop-erkan",
        "vendor":      "Apple",
    },
])
```

### 3. Örnek Scapy Entegrasyonu

```python
from scapy.all import sniff, ARP
import requests, threading, time

NEXUSGUARD_API  = "http://localhost:3000"
WEBHOOK_SECRET  = "nexusguard_super_secret_2024"
arp_cache: dict = {}   # {ip: mac} doğru ARP tablosu

def detect_arp_spoofing(packet):
    """Scapy callback — her ARP paketini incele."""
    if packet.haslayer(ARP) and packet[ARP].op == 2:  # is-at (yanıt)
        real_mac   = arp_cache.get(packet[ARP].psrc)
        sender_mac = packet[ARP].hwsrc

        if real_mac and real_mac != sender_mac:
            # ARP zehirlenmesi tespit edildi!
            send_threat_alert({
                "threat_type":            "ARP_SPOOFING",
                "attacker_ip":            packet[ARP].psrc,
                "attacker_mac":           sender_mac,
                "victim_ip":              packet[ARP].pdst,
                "kill_switch_triggered":  True,
                "details": {
                    "expected_mac": real_mac,
                    "received_mac": sender_mac,
                },
            })
        else:
            # ARP tablosunu güncelle
            arp_cache[packet[ARP].psrc] = sender_mac

def send_threat_alert(data):
    requests.post(
        f"{NEXUSGUARD_API}/api/threat-alert",
        headers={"x-ips-secret": WEBHOOK_SECRET},
        json=data,
        timeout=3,
    )

# Dinlemeyi başlat
sniff(filter="arp", prn=detect_arp_spoofing, store=False)
```

## Notlar

- `IPS_WEBHOOK_SECRET` değeri `.env.local` ve Python betiğinizde **aynı** olmalıdır.
- Next.js geliştirme sunucusu varsayılan olarak `http://localhost:3000` üzerinde çalışır.
- Production'da URL'yi sunucu IP/domain ile değiştirin ve HTTPS kullanın.
