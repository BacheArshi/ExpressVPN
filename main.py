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
#  بخش تنظیمات (Settings) - هر تغییری اینجا بدهید، دفعه بعد اعمال می‌شود
# =============================================================
PINNED_CONFIGS = [
    "ss://bm9uZTpmOGY3YUN6Y1BLYnNGOHAz@lil:360#%F0%9F%91%91%20%40express_alaki",
]

# ۱. آیکون‌ها و علائم ظاهری
SOURCE_ICON = "📁" 
NOT_FOUND_FLAG = "🌐"

# ۲. لیست پروتکل‌های مورد حمایت (قابل تغییر)
SUPPORTED_PROTOCOLS = ['vless://', 'vmess://', 'trojan://', 'hysteria2://', 'hy2://']

# ۳. تنظیمات چرخش و انقضا
EXPIRY_HOURS = 12       
SEARCH_LIMIT_HOURS = 1  
ROTATION_LIMIT = 65      
ROTATION_LIMIT_2 = 1000   
# =============================================================

def get_only_flag(text):
    """فقط استخراج ایموجی پرچم"""
    if not text: return NOT_FOUND_FLAG
    flag_pattern = re.compile(r'[\U0001F1E6-\U0001F1FF]{2}')
    flags = flag_pattern.findall(text)
    return flags[0] if flags else NOT_FOUND_FLAG

def analyze_and_rename(config, channel_name):
    """فرآیند تغییر نام کانفیگ خام (فراخوانی هنگام ساخت فایل خروجی)"""
    try:
        clean_channel = channel_name.replace("https://t.me/", "@").replace("t.me/", "@")
        if not clean_channel.startswith("@"): clean_channel = f"@{clean_channel}"

        transport = "TCP"
        security = "None"
        flag = NOT_FOUND_FLAG

        if config.startswith("vmess://"):
            b64_data = config[8:]
            b64_data += "=" * (-len(b64_data) % 4)
            data = json.loads(base64.b64decode(b64_data).decode('utf-8'))
            flag = get_only_flag(data.get('ps', ''))
            net = data.get('net', 'tcp').lower()
            t_map = {'tcp': 'TCP', 'ws': 'WS', 'grpc': 'GRPC', 'kcp': 'KCP', 'h2': 'H2', 'quic': 'QUIC', 'httpupgrade': 'HTTPUpgrade', 'xhttp': 'XHTTP'}
            transport = t_map.get(net, 'TCP')
            if data.get('tls') == 'tls': security = 'TLS'
            data['ps'] = f"{flag} {transport}-{security} {SOURCE_ICON} {clean_channel}"
            return "vmess://" + base64.b64encode(json.dumps(data).encode('utf-8')).decode('utf-8')
        else:
            parsed = urllib.parse.urlparse(config)
            query = urllib.parse.parse_qs(parsed.query)
            remark = urllib.parse.unquote(parsed.fragment)
            flag = get_only_flag(remark)
            if config.startswith(('hysteria2://', 'hy2://')):
                transport, security = "Hysteria", "TLS"
            else:
                t_type = query.get('type', ['tcp'])[0].lower()
                t_map = {'tcp': 'TCP', 'ws': 'WS', 'grpc': 'GRPC', 'kcp': 'KCP', 'httpupgrade': 'HTTPUpgrade', 'xhttp': 'XHTTP', 'h2': 'H2', 'quic': 'QUIC'}
                transport = t_map.get(t_type, 'TCP')
                sec = query.get('security', ['none'])[0].lower()
                if sec == 'tls': security = 'TLS'
                elif sec == 'reality': security = 'Reality'
            new_name = f"{flag} {transport}-{security} {SOURCE_ICON} {clean_channel}"
            return urllib.parse.urlunparse(parsed._replace(fragment=urllib.parse.quote(new_name)))
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

    # دیتابیس: [timestamp, channel_name, raw_config]
    db_data = []
    if os.path.exists('data.temp'):
        with open('data.temp', 'r', encoding='utf-8') as f:
            for line in f:
                parts = line.strip().split('|')
                if len(parts) == 3: db_data.append(parts)

    all_raw_configs = [d[2] for d in db_data]
    now = datetime.now().timestamp()

    # استخراج موارد جدید (ذخیره به صورت خام)
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

    # پاکسازی موارد منقضی شده
    valid_db = [item for item in db_data if now - float(item[0]) < (EXPIRY_HOURS * 3600)]

    # مدیریت پوینتر
    current_index = 0
    if os.path.exists('pointer.txt'):
        try:
            with open('pointer.txt', 'r') as f: current_index = int(f.read().strip())
        except: current_index = 0
    if current_index >= len(valid_db): current_index = 0

    # انتخاب برای چرخش
    def get_rotated_batch(size):
        if not valid_db: return []
        if current_index + size <= len(valid_db):
            return valid_db[current_index : current_index + size]
        return valid_db[current_index:] + valid_db[:size - (len(valid_db) - current_index)]

    batch1 = get_rotated_batch(ROTATION_LIMIT)
    batch2 = get_rotated_batch(ROTATION_LIMIT_2)

    # تابع ذخیره‌سازی فایل خروجی (با اعمال تغییر نام لحظه‌ای)
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

    # بروزرسانی دیتابیس و پوینتر
    with open('data.temp', 'w', encoding='utf-8') as f:
        for item in valid_db: f.write("|".join(item) + "\n")
    with open('pointer.txt', 'w', encoding='utf-8') as f:
        f.write(str((current_index + ROTATION_LIMIT) % len(valid_db) if valid_db else 0))

if __name__ == "__main__":
    run()
