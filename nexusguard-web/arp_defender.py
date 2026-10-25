import os
import time
from dotenv import load_dotenv
from scapy.all import sniff, ARP
from supabase import create_client, Client
from win11toast import toast

# Gizli .env dosyasından anahtarları yükle
load_dotenv()

SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_KEY")
supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)

ip_mac_map = {}
suspicious_packets = {}  # Her IP için sahte paket geliş zamanlarını tutar
last_alert_time = 0      # Bildirim spaminin önüne geçmek için

def process_packet(packet):
    global last_alert_time
    if packet.haslayer(ARP) and packet[ARP].op == 2:
        sender_ip = packet[ARP].psrc
        sender_mac = packet[ARP].hwsrc

        if sender_ip in ip_mac_map:
            # Uyumsuz MAC yakalandı
            if ip_mac_map[sender_ip] != sender_mac:
                current_time = time.time()
                
                if sender_ip not in suspicious_packets:
                    suspicious_packets[sender_ip] = []
                    
                # Anlık zamanı kaydet ve 3 saniyeden eski olanları sil (Zaman Penceresi)
                suspicious_packets[sender_ip].append(current_time)
                suspicious_packets[sender_ip] = [t for t in suspicious_packets[sender_ip] if current_time - t <= 3]
                
                # 3 saniye içinde 10 paketi geçtiyse (Eşik Değeri)
                if len(suspicious_packets[sender_ip]) >= 10:
                    
                    # Aynı uyarıyı saniyede bir vermemek için 15 saniye bekleme süresi
                    if current_time - last_alert_time > 15:
                        last_alert_time = current_time
                        print(f"[!] EŞİK AŞILDI: {sender_ip} adresinden MITM Saldırısı! Bildirim gönderiliyor...")
                        
                        # Veritabanına Yaz
                        try:
                            supabase.table('network_alerts').insert({
                                "target_ip": sender_ip,
                                "original_mac": ip_mac_map[sender_ip],
                                "attacker_mac": sender_mac
                            }).execute()
                        except Exception as e:
                            pass
                        
                        # Windows Etkileşimli Panik Bildirimi
                        toast(
                            "⚠️ NexusGuard: Ağ Saldırısı (MITM)!", 
                            f"{sender_ip} IP'sinden yüksek yoğunluklu ARP zehirlenmesi tespit edildi.\nBağlantıyı kesmek istiyor musunuz?",
                            duration="long",
                            audio={"src": "ms-winsoundevent:Notification.Looping.Alarm", "loop": "false"},
                            buttons=[
                                {'activationType': 'protocol', 'arguments': 'http://localhost:3000', 'content': 'Ağı Kapat / Panele Git'}
                            ]
                        )
        else:
            # Ağa yeni katılan normal cihazlar
            ip_mac_map[sender_ip] = sender_mac
            print(f"[+] Cihaz Kaydedildi: {sender_ip} -> {sender_mac}")

print("Akıllı Eşik Değerli IDS Motoru aktif... (Durdurmak için Ctrl+C)")
sniff(filter="arp", prn=process_packet, store=False)