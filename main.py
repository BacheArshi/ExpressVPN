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

SOURCE_ICON = "📁" 
NOT_FOUND_FLAG = "🌐"
SUPPORTED_PROTOCOLS = ['vless://', 'vmess://', 'trojan://', 'hysteria2://', 'hy2://']

EXPIRY_HOURS = 12       
SEARCH_LIMIT_HOURS = 1  
ROTATION_LIMIT = 65      
ROTATION_LIMIT_2 = 1000   
# =============================================================

def get_only_flag(text):
    """استخراج دقیق ایموجی پرچم با پاک‌سازی متن"""
    if not text: return NOT_FOUND_FLAG
    # ابتدا متن را از حالت کدگذاری خارج می‌کنیم (مثل %F0%9F)
    try:
        text = urllib.parse.unquote(str(text))
    except: pass
    
    flag_pattern = re.compile(r'[\U0001F1E6-\U0001F1FF]{2}')
    flags = flag_pattern.findall(text)
    return flags[0] if flags else NOT_FOUND_FLAG

def analyze_and_rename(config, channel_name):
    """تحلیل فنی عمیق با تمرکز بر جداسازی Reality از TLS"""
    try:
        config = config.strip()
        clean_channel = channel_name.replace("https://t.me/", "@").replace("t.me/", "@")
        if not clean_channel.startswith("@"): clean_channel = f"@{clean_channel}"

        transport = "TCP"
        security = "None"

        # --- ۱. پردازش VMess ---
        if config.startswith("vmess://"):
            try:
                b64_str = config[8:]
                b64_str += "=" * (-len(b64_str) % 4)
                data = json.loads(base64.b64decode(b64_str).decode('utf-8'))
                
                # پاک‌سازی نام برای استخراج پرچم
                flag = get_only_flag(data.get('ps', ''))
                
                net = data.get('net', 'tcp').lower()
                t_map = {'tcp': 'TCP', 'ws': 'WS', 'grpc': 'GRPC', 'kcp': 'KCP', 'h2': 'H2', 'quic': 'QUIC', 'httpupgrade': 'HTTPUpgrade', 'xhttp': 'XHTTP'}
                transport = t_map.get(net, 'TCP')
                
                # در وی‌مس ریالیتی نداریم، فقط TLS یا None
                if str(data.get('tls')).lower() == 'tls': security = 'TLS'
                
                data['ps'] = f"{flag} {transport}-{security} {SOURCE_ICON} {clean_channel}"
                return "vmess://" + base64.b64encode(json.dumps(data).encode('utf-8')).decode('utf-8')
            except: return config

        # --- ۲. پردازش VLESS, Trojan, Hy2 ---
        else:
            # جداسازی بخش اصلی از نام (Fragment) و پاک‌سازی هر دو بخش
            if '#' in config:
                base_part, remark = config.split('#', 1)
                remark = urllib.parse.unquote(remark)
            else:
                base_part, remark = config, ""
            
            flag = get_only_flag(remark)

            # استخراج و پاک‌سازی پارامترها (Query String)
            parsed_url = urllib.parse.urlparse(base_part)
            # استفاده از parse_qsl برای هندل کردن کاراکترهای عجیب در پارامترها
            params = {k.lower(): v.lower() for k, v in urllib.parse.parse_qsl(parsed_url.query)}
            
            # --- منطق تشخیص امنیت (دقیق و بدون وابستگی به پورت) ---
            sec_val = params.get('security', '')
            
            # الف) بررسی Reality (اولیت اول)
            # اگر کلمه reality ذکر شده باشد یا پارامترهای مخصوص آن (مثل pbk) موجود باشد
            if sec_val == 'reality' or 'pbk' in params or 'sid' in params:
                security = 'Reality'
            # ب) بررسی TLS
            elif sec_val in ['tls', 'xtls', 'ssl'] or 'sni' in params:
                security = 'TLS'

            # --- تشخیص ترنسپورت ---
            t_val = params.get('type', 'tcp')
            t_map = {'tcp': 'TCP', 'ws': 'WS', 'grpc': 'GRPC', 'kcp': 'KCP', 'httpupgrade': 'HTTPUpgrade', 'xhttp': 'XHTTP', 'h2': 'H2', 'quic': 'QUIC'}
            transport = t_map.get(t_val, 'TCP')

            # حالت خاص Hysteria
            if config.startswith(('hysteria2://', 'hy2://')):
                transport, security = "Hysteria", "TLS"

            # ساخت لینک نهایی با نام استاندارد شده
            new_name = f"{flag} {transport}-{security} {SOURCE_ICON} {clean_channel}"
            return f"{base_part}#{urllib.parse.quote(new_name)}"

    except Exception:
        return config

def extract_configs_logic(msg_div):
    """استخراج کانفیگ‌های خام با هندل کردن اموجی‌های تلگرام"""
    for img in msg_div.find_all("img"):
        if 'emoji' in img.get('class', []) and img.get('alt'):
            img.replace_with(img['alt'])
    for br in msg_div.find_all("br"): br.replace_with("\n")
    full_text = html.unescape(msg_div.get_text())
    
    extracted = []
    for line in full_text.split('\n'):
        starts = []
        for proto in SUPPORTED_PROTOCOLS:
            for m in re.finditer(re.escape(proto), line): starts.append((m.start(), proto))
        starts.sort(key=lambda x: x[0])
        for i in range(len(starts)):
            start_pos = starts[i][0]
            candidate = line[start_pos:starts[i+1][0]] if i+1 < len(starts) else line[start_pos:]
            final_cfg = candidate.strip()
            if any(final_cfg.startswith(p) for p in SUPPORTED_PROTOCOLS) and len(final_cfg) > 10:
                extracted.append(final_cfg)
    return extracted

def run():
    if not os.path.exists('channels.txt'): return
    with open('channels.txt', 'r') as f:
        channels = [line.strip() for line in f if line.strip()]

    # دیتابیس (خام): [زمان|کانال|کانفیگ]
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
            for ts, ch, raw_cfg in batch:
                renamed = analyze_and_rename(raw_cfg, ch)
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
