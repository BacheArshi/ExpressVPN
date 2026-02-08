import requests
from bs4 import BeautifulSoup
import re
import os
import html
import json
import base64
import urllib.parse
from datetime import datetime, timezone

# =============================================================
#  بخش تنظیمات (Settings)
# =============================================================
PINNED_CONFIGS = [
    "ss://bm9uZTpmOGY3YUN6Y1BLYnNGOHAz@lil:360#%F0%9F%91%91%20%40express_alaki",
]

# >>> تنظیمات جدید قالب اسم <<<
MY_CHANNEL_ID = "@express_alaki"  # آیدی ثابت برای همه کانفیگ‌ها
SEPARATOR = "|"                   # جداکننده
NOT_FOUND_FLAG = "🌐"

SUPPORTED_PROTOCOLS = ['vless://', 'vmess://', 'trojan://', 'hysteria2://', 'hy2://']

EXPIRY_HOURS = 12       
SEARCH_LIMIT_HOURS = 1  
ROTATION_LIMIT = 65      
ROTATION_LIMIT_2 = 1000   
# =============================================================

def get_only_flag(text):
    """استخراج دقیق ایموجی پرچم"""
    if not text: return NOT_FOUND_FLAG
    try:
        text = urllib.parse.unquote(urllib.parse.unquote(str(text)))
    except: pass
    flag_pattern = re.compile(r'[\U0001F1E6-\U0001F1FF]{2}')
    flags = flag_pattern.findall(text)
    return flags[0] if flags else NOT_FOUND_FLAG

def parse_vmess_uri(config):
    """تحلیل VMess برای استخراج فرمت JSON"""
    try:
        b64_str = config[8:]
        b64_str += "=" * (-len(b64_str) % 4)
        data = json.loads(base64.b64decode(b64_str).decode('utf-8'))
        
        raw_name = data.get('ps', '')
        net = data.get('net', 'tcp').lower()
        tls = data.get('tls', '').lower()
        
        transport = net
        security = 'TLS' if tls == 'tls' else 'None'
        return data, raw_name, transport, security, True
    except:
        return None, "", "TCP", "None", False

def analyze_and_rename(config, source_channel_name):
    """
    تحلیل فنی و تغییر نام به قالب: Flag Transport-Security | @express_alaki
    توجه: source_channel_name فقط برای لاگ یا دیباگ استفاده میشه و در اسم نهایی نمیاد
    """
    try:
        config = config.strip()
        
        transport = "TCP"
        security = "None"
        flag = NOT_FOUND_FLAG
        base_url = config
        
        # --- استراتژی ۱: VMess ---
        if config.startswith("vmess://"):
            data, raw_name, v_trans, v_sec, is_json = parse_vmess_uri(config)
            if is_json:
                transport = v_trans
                security = v_sec
                flag = get_only_flag(raw_name)
                
                t_map = {'tcp': 'TCP', 'ws': 'WS', 'grpc': 'GRPC', 'kcp': 'KCP', 'h2': 'H2', 'quic': 'QUIC', 'httpupgrade': 'HTTPUpgrade', 'xhttp': 'XHTTP'}
                transport = t_map.get(transport.lower(), 'TCP')
                
                # قالب جدید: Flag Transport-Security | @express_alaki
                new_ps = f"{flag} {transport}-{security} {SEPARATOR} {MY_CHANNEL_ID}"
                data['ps'] = new_ps
                return "vmess://" + base64.b64encode(json.dumps(data).encode('utf-8')).decode('utf-8')

        # --- استراتژی ۲: سایر پروتکل‌ها ---
        if '#' in config:
            parts = config.split('#', 1)
            base_url = parts[0]
            raw_fragment = parts[1]
        else:
            base_url = config
            raw_fragment = ""

        flag = get_only_flag(raw_fragment)
        parsed = urllib.parse.urlparse(base_url)
        params = dict(urllib.parse.parse_qsl(parsed.query))
        params = {k.lower(): v.lower() for k, v in params.items()}

        # تشخیص Security
        if 'security' in params:
            sec_val = params['security']
            if sec_val in ['tls', 'xtls', 'ssl']: security = 'TLS'
            elif sec_val == 'reality': security = 'Reality'
        elif 'sni' in params and params['sni']: 
             security = 'TLS'
        
        if 'pbk' in params or 'sid' in params or 'fp' in params:
            security = 'Reality'

        # تشخیص Transport
        if 'type' in params: t_val = params['type']
        elif 'headerType' in params and params['headerType'] != 'none': t_val = 'tcp'
        elif 'net' in params: t_val = params['net']
        else: t_val = 'tcp'

        t_map = {'tcp': 'TCP', 'ws': 'WS', 'grpc': 'GRPC', 'kcp': 'KCP', 'httpupgrade': 'HTTPUpgrade', 'xhttp': 'XHTTP', 'h2': 'H2', 'quic': 'QUIC'}
        transport = t_map.get(t_val, 'TCP')

        if config.startswith(('hysteria2://', 'hy2://')):
            transport, security = "Hysteria", "TLS"

        # قالب جدید نهایی
        final_name = f"{flag} {transport}-{security} {SEPARATOR} {MY_CHANNEL_ID}"
        
        return f"{base_url}#{urllib.parse.quote(final_name)}"

    except Exception:
        # در صورت خطا، باز هم سعی میکنیم اسم کانال خودمان را بچسبانیم
        try:
             base = config.split('#')[0]
             return f"{base}#{urllib.parse.quote(f'🌐 Unknown {SEPARATOR} {MY_CHANNEL_ID}')}"
        except:
            return config

def extract_configs_logic(msg_div):
    for img in msg_div.find_all("img"):
        if 'emoji' in img.get('class', []) and img.get('alt'):
            img.replace_with(img['alt'])
    for br in msg_div.find_all("br"): br.replace_with("\n")
    full_text = html.unescape(msg_div.get_text())
    
    extracted = []
    for line in full_text.split('\n'):
        line = line.strip()
        starts = []
        for proto in SUPPORTED_PROTOCOLS:
            for m in re.finditer(re.escape(proto), line): starts.append((m.start(), proto))
        starts.sort(key=lambda x: x[0])
        
        for i in range(len(starts)):
            start_pos = starts[i][0]
            candidate = line[start_pos:starts[i+1][0]] if i+1 < len(starts) else line[start_pos:]
            final_cfg = candidate.strip()
            if len(final_cfg) > 15:
                extracted.append(final_cfg)
    return extracted

def run():
    if not os.path.exists('channels.txt'): return
    with open('channels.txt', 'r') as f:
        channels = [line.strip() for line in f if line.strip()]

    # دیتابیس همچنان منبع را ذخیره می‌کند: [timestamp, source_channel, config]
    db_data = []
    if os.path.exists('data.temp'):
        with open('data.temp', 'r', encoding='utf-8') as f:
            for line in f:
                parts = line.strip().split('|')
                if len(parts) == 3: db_data.append(parts)

    all_raw_configs = [d[2] for d in db_data]
    now = datetime.now().timestamp()

    for ch in channels:
        url = f"https://t.me/s/{ch}"
        try:
            resp = requests.get(url, timeout=15)
            if resp.status_code != 200: continue
            soup = BeautifulSoup(resp.text, 'html.parser')
            for wrap in soup.find_all('div', class_='tgme_widget_message_wrap'):
                time_tag = wrap.find('time')
                if not time_tag: continue
                msg_time = datetime.fromisoformat(time_tag['datetime'])
                if (datetime.now(timezone.utc) - msg_time).total_seconds() > (SEARCH_LIMIT_HOURS * 3600): continue
                
                msg_text = wrap.find('div', class_='tgme_widget_message_text')
                if not msg_text: continue
                
                raw_found = extract_configs_logic(msg_text)
                for c in raw_found:
                    if c not in all_raw_configs and c not in PINNED_CONFIGS:
                        # ذخیره نام کانال منبع در دیتابیس (برای عدم تکرار)
                        db_data.append([str(now), ch, c])
                        all_raw_configs.append(c)
        except: continue

    valid_db = [item for item in db_data if now - float(item[0]) < (EXPIRY_HOURS * 3600)]

    current_index = 0
    if os.path.exists('pointer.txt'):
        try:
            with open('pointer.txt', 'r') as f: current_index = int(f.read().strip())
        except: current_index = 0
    if current_index >= len(valid_db): current_index = 0

    def get_rotated_batch(size):
        if not valid_db: return []
        if current_index + size <= len(valid_db):
            return valid_db[current_index : current_index + size]
        return valid_db[current_index:] + valid_db[:size - (len(valid_db) - current_index)]

    batch1 = get_rotated_batch(ROTATION_LIMIT)
    batch2 = get_rotated_batch(ROTATION_LIMIT_2)

    def save_output(filename, batch):
        seen = set(PINNED_CONFIGS)
        with open(filename, 'w', encoding='utf-8') as f:
            for pin in PINNED_CONFIGS: f.write(pin + "\n\n")
            for ts, source_ch, raw_cfg in batch:
                # اینجا اسم کانال منبع را می‌فرستیم ولی در تابع تغییر نام نادیده گرفته می‌شود
                renamed = analyze_and_rename(raw_cfg, source_ch)
                if renamed not in seen:
                    f.write(renamed + "\n\n")
                    seen.add(renamed)

    save_output('configs.txt', batch1)
    save_output('configs2.txt', batch2)

    with open('data.temp', 'w', encoding='utf-8') as f:
        for item in valid_db: f.write("|".join(item) + "\n")
    with open('pointer.txt', 'w', encoding='utf-8') as f:
        f.write(str((current_index + ROTATION_LIMIT) % len(valid_db) if valid_db else 0))

if __name__ == "__main__":
    run()
