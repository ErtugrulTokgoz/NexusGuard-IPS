from scapy.all import sniff, ARP
from supabase import create_client, Client

# Supabase Bağlantı Ayarları
SUPABASE_URL = "https://zfjuivwfndrqaaqoxofn.supabase.co"
SUPABASE_KEY = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InpmanVpdndmbmRycWFhcW94b2ZuIiwicm9sZSI6ImFub24iLCJpYXQiOjE3OTI3NzM1ODcsImV4cCI6MjEwODM0OTU4N30.ChGKrv3CSiDduky7cuVXi3OIes3xBYWBb3cTL20a3VE"

supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)

# Ağdaki orijinal IP - MAC eşleşmelerini tutacağımız bellek
ip_mac_map = {}

def process_packet(packet):
    # Sadece ARP yanıtlarını (op=2: is-at) incele
    if packet.haslayer(ARP) and packet[ARP].op == 2:
        sender_ip = packet[ARP].psrc
        sender_mac = packet[ARP].hwsrc

        if sender_ip in ip_mac_map:
            # Kayıtlı MAC ile gelen MAC uyuşmuyorsa biri araya girmiştir
            if ip_mac_map[sender_ip] != sender_mac:
                print(f"[!] DİKKAT ARP ZEHİRLENMESİ (MITM) TESPİT EDİLDİ!")
                print(f"    Hedef IP: {sender_ip}")
                print(f"    Saldırgan MAC: {sender_mac}")
                
                # Alarmı anında Supabase'e gönder
                try:
                    data, count = supabase.table('network_alerts').insert({
                        "target_ip": sender_ip,
                        "original_mac": ip_mac_map[sender_ip],
                        "attacker_mac": sender_mac
                    }).execute()
                    print("    [+] Tehdit kaydı Supabase'e başarıyla iletildi!\n")
                except Exception as e:
                    print(f"    [-] Veritabanına gönderilemedi: {e}\n")
                    
        else:
            # Cihaz ağa ilk kez sesleniyorsa kaydet
            ip_mac_map[sender_ip] = sender_mac
            print(f"[+] Cihaz Kaydedildi: {sender_ip} -> {sender_mac}")

print("ARP paketleri dinleniyor ve Supabase'e bağlı... (Durdurmak için Ctrl+C)")
sniff(filter="arp", prn=process_packet, store=False)