import time
from scapy.all import send, ARP

# Simülasyon için rastgele bir IP ve iki farklı MAC adresi belirliyoruz
test_ip = "192.168.1.99"
orijinal_mac = "00:11:22:33:44:55"
sahte_mac = "AA:BB:CC:DD:EE:FF"

print("[*] Asama 1: Sisteme temiz bir cihazmis gibi orijinal MAC ile kayit olunuyor...")
send(ARP(op=2, psrc=test_ip, hwsrc=orijinal_mac), verbose=False)
time.sleep(1)

print("[*] Asama 2: Esik degeri (10 paket) test ediliyor. 15 sahte MAC paketi firlatiliyor...")
for i in range(15):
    send(ARP(op=2, psrc=test_ip, hwsrc=sahte_mac), verbose=False)
    time.sleep(0.1)

print("[+] Test tamamlandi! ARP Defender ekranina ve Windows bildirimlerine bak.")