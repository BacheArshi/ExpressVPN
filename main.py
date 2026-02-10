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

# تنظیمات نام‌گذاری
MY_CHANNEL_ID = "@express_alaki"
SOURCE_ICON = "📁" 
CUSTOM_SEPARATOR = "|"
NOT_FOUND_FLAG = "🌐"

SUPPORTED_PROTOCOLS = ['vless://', 'vmess://', 'trojan://', 'hysteria2://', 'hy2://']

EXPIRY_HOURS = 12       
SEARCH_LIMIT_HOURS = 1  
ROTATION_LIMIT = 65      
ROTATION_LIMIT_2 = 1000   
ROTATION_LIMIT_3 = 3000   # ظرفیت فایل ۳ و ۴
# =============================================================

def get_only_flag(text):
    if not text: return NOT_FOUND_FLAG
    try:
        text = urllib.parse.unquote(urllib.parse.unquote(str(text)))
    except: pass
    flag_pattern = re.compile(r'[\U0001F1E6-\U0001F1FF]{2}')
    flags = flag_pattern.findall(text)
    return flags[0] if flags else NOT_FOUND_FLAG

def parse_vmess_uri(config):
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

def analyze_and_rename(config, channel_name, use_my_branding=False):
    """
    use_my_branding=True  -> قالب: Flag Trans-Sec | @express_alaki
    use_my_branding=False -> قالب: Flag Trans-Sec 📁 @SourceChannel
    """
    try:
        config = config.strip()
        
        # تعیین نام و جداکننده بر اساس حالت درخواستی
        if use_my_branding:
            final_label = MY_CHANNEL_ID
            separator = CUSTOM_SEPARATOR
        else:
            clean_channel = channel_name.replace("https://t.me/", "@").replace("t.me/", "@")
            if not clean_channel.startswith("@"): clean_channel = f"@{clean_channel}"
            final_label = clean_channel
            separator = SOURCE_ICON

        transport, security, flag = "TCP", "None", NOT_FOUND_FLAG
        
        # --- استراتژی ۱: VMess ---
        if config.startswith("vmess://"):
            data, raw_name, v_trans, v_sec, is_json = parse_vmess_uri(config)
            if is_json:
                flag = get_only_flag(raw_name)
                t_map = {'tcp': 'TCP', 'ws': 'WS', 'grpc': 'GRPC', 'kcp': 'KCP', 'h2': 'H2', 'quic': 'QUIC', 'httpupgrade': 'HTTPUpgrade', 'xhttp': 'XHTTP'}
                transport = t_map.get(v_trans.lower(), 'TCP')
                security = v_sec
                
                new_ps = f"{flag} {transport}-{security} {separator} {final_label}"
                data['ps'] = new_ps
                return "vmess://" + base64.b64encode(json.dumps(data).encode('utf-8')).decode('utf-8')

        # --- استراتژی ۲: سایر پروتکل‌ها ---
        if '#' in config:
            base_url, raw_fragment = config.split('#', 1)
        else:
            base_url, raw_fragment = config, ""

        flag = get_only_flag(raw_fragment)
        params = {k.lower(): v.lower() for k, v in urllib.parse.parse_qsl(urllib.parse.urlparse(base_url).query)}
        
        if 'security' in params:
            if params['security'] in ['tls', 'xtls', 'ssl']: security = 'TLS'
            elif params['security'] == 'reality': security = 'Reality'
        elif 'sni' in params or 'pbk' in params: security = 'Reality' if 'pbk' in params else 'TLS'

        t_val = params.get('type', params.get('net', 'tcp'))
        t_map = {'tcp': 'TCP', 'ws': 'WS', 'grpc': 'GRPC', 'kcp': 'KCP', 'httpupgrade': 'HTTPUpgrade', 'xhttp': 'XHTTP'}
        transport = t_map.get(t_val, 'TCP')

        if config.startswith(('hysteria2://', 'hy2://')): transport, security = "Hysteria", "TLS"

        final_name = f"{flag} {transport}-{security} {separator} {final_label}"
        return f"{base_url}#{urllib.parse.quote(final_name)}"

    except:
        return config

def extract_configs_logic(msg_div):
    for img in msg_div.find_all("img"):
        if 'emoji' in img.get('class', []) and img.get('alt'): img.replace_with(img['alt'])
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
            if len(candidate.strip()) > 15: extracted.append(candidate.strip())
    return extracted

def run():
    if not os.path.exists('channels.txt'): return
    with open('channels.txt', 'r') as f:
        channels = [line.strip() for line in f if line.strip()]

    db_data = []
    if os.path.exists('data.temp'):
        with open('data.temp', 'r', encoding='utf-8') as f:
            for line in f:
                parts = line.strip().split('|')
                if len(parts) == 3: db_data.append(parts)

    all_raw_configs = [d[2] for d in db_data]
    now = datetime.now().timestamp()

    for ch in channels:
        try:
            resp = requests.get(f"https://t.me/s/{ch}", timeout=15)
            if resp.status_code != 200: continue
            soup = BeautifulSoup(resp.text, 'html.parser')
            for wrap in soup.find_all('div', class_='tgme_widget_message_wrap'):
                time_tag = wrap.find('time')
                if not time_tag: continue
                msg_time = datetime.fromisoformat(time_tag['datetime'])
                if (datetime.now(timezone.utc) - msg_time).total_seconds() > (SEARCH_LIMIT_HOURS * 3600): continue
                msg_text = wrap.find('div', class_='tgme_widget_message_text')
                if not msg_text: continue
                for c in extract_configs_logic(msg_text):
                    if c not in all_raw_configs and c not in PINNED_CONFIGS:
                        db_data.append([str(now), ch, c])
                        all_raw_configs.append(c)
        except: continue

    valid_db = [item for item in db_data if now - float(item[0]) < (EXPIRY_HOURS * 3600)]

    # --- منطق چرخش برای فایل ۱ و ۲ ---
    current_index = 0
    if os.path.exists('pointer.txt'):
        try:
            with open('pointer.txt', 'r') as f: current_index = int(f.read().strip())
        except: current_index = 0
    if current_index >= len(valid_db): current_index = 0

    def get_rotated(size):
        if not valid_db: return []
        if current_index + size <= len(valid_db): return valid_db[current_index : current_index + size]
        return valid_db[current_index:] + valid_db[:size - (len(valid_db) - current_index)]

    batch1 = get_rotated(ROTATION_LIMIT)
    batch2 = get_rotated(ROTATION_LIMIT_2)
    
    # --- منطق ثابت (زمانی) برای فایل ۳ و ۴ ---
    batch_chronological = valid_db[-ROTATION_LIMIT_3:]

    # تابع ذخیره‌سازی
    def save_output(filename, batch, use_custom_branding=False):
        seen = set(PINNED_CONFIGS)
        with open(filename, 'w', encoding='utf-8') as f:
            for pin in PINNED_CONFIGS: f.write(pin + "\n\n")
            for ts, source_ch, raw_cfg in batch:
                renamed = analyze_and_rename(raw_cfg, source_ch, use_my_branding=use_custom_branding)
                if renamed not in seen:
                    f.write(renamed + "\n\n")
                    seen.add(renamed)

    # 1. فایل چرخشی کوچک (با نام منبع)
    save_output('configs.txt', batch1, use_custom_branding=False)
    
    # 2. فایل چرخشی بزرگ (با نام منبع)
    save_output('configs2.txt', batch2, use_custom_branding=False)
    
    # 3. فایل زمانی ثابت (با نام شما @express_alaki)
    save_output('configs3.txt', batch_chronological, use_custom_branding=True)
    
    # 4. فایل زمانی ثابت (با نام منبع - کپی محتوای 3)
    save_output('configs4.txt', batch_chronological, use_custom_branding=False)

    with open('data.temp', 'w', encoding='utf-8') as f:
        for item in valid_db: f.write("|".join(item) + "\n")
    with open('pointer.txt', 'w', encoding='utf-8') as f:
        f.write(str((current_index + ROTATION_LIMIT) % len(valid_db) if valid_db else 0))

if __name__ == "__main__":
    run()
