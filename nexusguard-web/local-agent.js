require('dotenv').config({ path: '.env.local' });
const { createClient } = require('@supabase/supabase-js');
const { execFile } = require('child_process');

const supabaseUrl = process.env.NEXT_PUBLIC_SUPABASE_URL;
const supabaseKey = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY;

if (!supabaseUrl || !supabaseKey) {
  console.error("HATA: .env dosyasında Supabase bilgileri eksik!");
  process.exit(1);
}

const supabase = createClient(supabaseUrl, supabaseKey);

const isValidIP = (ip) => {
  const ipv4Regex = /^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
  return ipv4Regex.test(ip);
};

console.log("NexusGuard ZTNA Yerel Ajanı Başlatıldı. İzole dinleme aktif...");

supabase
  .channel('kill-switch-listener')
  .on(
    'postgres_changes',
    { event: 'UPDATE', schema: 'public', table: 'threat_logs' },
    (payload) => {
      const newData = payload.new;

      if (newData.kill_switch_triggered === false && newData.status === 'MITIGATED') {
        const targetIp = newData.attacker_ip;

        if (!isValidIP(targetIp)) {
          console.error(`[GÜVENLİK İHLALİ] Geçersiz IP formatı: ${targetIp}.`);
          return;
        }

        const args = ['advfirewall', 'firewall', 'delete', 'rule', `name=Block_${targetIp}`];
        
        execFile('netsh', args, (error, stdout, stderr) => {
          if (error) {
            console.error(`[HATA] Kural silinemedi: ${error.message}`);
            return;
          }
          console.log(`[GÜVENLİ İŞLEM] ${targetIp} için ağ engeli kaldırıldı.`);
        });
      }
    }
  )
  .subscribe();
setInterval(() => {}, 60000);
