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
    "ss://bm9uZTpmOGY3YUN6Y1BLYnNGOHAz@lil:360#%F0%9F%91%91%20%40Express_alaki",
]

MY_CHANNEL_ID = "@Express_alaki"
SOURCE_ICON = "📁" 
CUSTOM_SEPARATOR = "|"
NOT_FOUND_FLAG = "🌐"

SUPPORTED_PROTOCOLS = ['vless://', 'vmess://', 'trojan://', 'hysteria2://', 'hy2://']

CHANNELS = [
    'HajmVPN_Config', 'DailyV2RY', 'V2ray_Extractor', 'v2nodes', 'V2ray20261', 'Hope_Net'
]

EXPIRY_HOURS = 12       
SEARCH_LIMIT_HOURS = 1  
ROTATION_LIMIT = 65      
ROTATION_LIMIT_2 = 1000   
ROTATION_LIMIT_3 = 3000   
# =============================================================

def get_only_flag(text):
    if not text: return NOT_FOUND_FLAG
    try:
        text = urllib.parse.unquote(urllib.parse.unquote(str(text)))
    except: pass
    flag_pattern = re.compile(r'[\U0001F1E6-\U0001F1FF]{2}')
    match = flag_pattern.search(text)
    return match.group(0) if match else NOT_FOUND_FLAG

def analyze_and_rename(raw_config, source_ch, use_my_branding=False):
    try:
        if raw_config.startswith('vmess://'):
            v_json = base64.b64decode(raw_config[8:]).decode('utf-8')
            v_data = json.loads(v_json)
            flag = get_only_flag(v_data.get('ps', ''))
            new_name = f"{flag} | {MY_CHANNEL_ID} | src @{source_ch}" if use_my_branding else f"{flag} | @{source_ch}"
            v_data['ps'] = new_name
            return "vmess://" + base64.b64encode(json.dumps(v_data).encode('utf-8')).decode('utf-8')
        else:
            base_part, old_name = raw_config.split('#', 1) if '#' in raw_config else (raw_config, "")
            flag = get_only_flag(old_name)
            new_name = f"{flag} | {MY_CHANNEL_ID} | src @{source_ch}" if use_my_branding else f"{flag} | @{source_ch}"
            return f"{base_part}#{urllib.parse.quote(new_name)}"
    except:
        return raw_config

def run():
    unique_pool = []
    if os.path.exists('data.temp'):
        try:
            with open('data.temp', 'r', encoding='utf-8') as f:
                for line in f:
                    parts = line.strip().split(',', 2)
                    if len(parts) == 3: unique_pool.append(tuple(parts))
        except: pass

    # --- بخش اصلی جمع‌آوری کانفیگ‌ها ---
    for ch in CHANNELS:
        try:
            url = f"https://t.me/s/{ch}"
            r = requests.get(url, timeout=15)
            soup = BeautifulSoup(r.text, 'html.parser')
            messages = soup.find_all('div', class_='tgme_widget_message_wrap')
            for msg in messages:
                text_elem = msg.find('div', class_='tgme_widget_message_text')
                if not text_elem: continue
                text = text_elem.get_text('\n')
                for line in text.split('\n'):
                    line = line.strip()
                    if any(line.startswith(p) for p in SUPPORTED_PROTOCOLS):
                        if not any(item[2] == line for item in unique_pool):
                            unique_pool.append((str(datetime.now().timestamp()), ch, line))
        except: continue

    # فیلتر انقضا
    now_ts = datetime.now().timestamp()
    unique_pool = [item for item in unique_pool if now_ts - float(item[0]) < (EXPIRY_HOURS * 3600)]
    if not unique_pool: return

    # منطق چرخشی و ذخیره‌سازی
    pointer = 0
    if os.path.exists('pointer.txt'):
        try:
            with open('pointer.txt', 'r') as f: pointer = int(f.read().strip())
        except: pass

    def get_batch(size):
        idx = pointer % len(unique_pool)
        return (unique_pool[idx:] + unique_pool[:idx])[:size]

    def save_output(filename, batch, use_branding=False):
        with open(filename, 'w', encoding='utf-8') as f:
            for pin in PINNED_CONFIGS: f.write(pin + "\n\n")
            for ts, ch, cfg in batch:
                f.write(analyze_and_rename(cfg, ch, use_branding) + "\n\n")

    # ساخت فایل‌ها
    save_output('configs3.txt', unique_pool[-ROTATION_LIMIT_3:], True)
    
    # --- فایل configs5 مخصوص بات (فقط ۲ ساعت اخیر) ---
    batch_5 = [i for i in unique_pool if now_ts - float(i[0]) < (2 * 3600)]
    save_output('configs5.txt', batch_5[-1000:], True)

    # آپدیت فایل‌های سیستمی
    with open('pointer.txt', 'w') as f: f.write(str(pointer + 1))
    with open('data.temp', 'w', encoding='utf-8') as f:
        for item in unique_pool: f.write(f"{item[0]},{item[1]},{item[2]}\n")

if __name__ == "__main__":
    run()
