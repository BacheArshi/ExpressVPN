import requests
from bs4 import BeautifulSoup
import re
import os
import json
import base64
import urllib.parse
from datetime import datetime

# =============================================================
#  تنظیمات
# =============================================================
PINNED_CONFIGS = ["ss://bm9uZTpmOGY3YUN6Y1BLYnNGOHAz@lil:360#%F0%9F%91%91%20%40Express_alaki"]
MY_CHANNEL_ID = "@Express_alaki"
CHANNELS = ['HajmVPN_Config', 'DailyV2RY', 'V2ray_Extractor', 'v2nodes', 'V2ray20261', 'Hope_Net', 'SafeNet_Server', 'L_I_N_E_V_P_N', 'v2rayNG_VPNN']
SUPPORTED_PROTOCOLS = ['vless://', 'vmess://', 'trojan://', 'hysteria2://', 'hy2://']
EXPIRY_HOURS = 12
STRICT_LIMIT_HOURS = 1
ROTATION_LIMIT, ROTATION_LIMIT_2, ROTATION_LIMIT_3 = 65, 1000, 3000

def get_only_flag(text):
    try:
        text = urllib.parse.unquote(str(text))
        match = re.search(r'[\U0001F1E6-\U0001F1FF]{2}', text)
        return match.group(0) if match else "🌐"
    except: return "🌐"

def analyze_and_rename(raw_config, source_ch, use_branding=False):
    try:
        clean_source = source_ch.replace("https://t.me/", "@").replace("t.me/", "@")
        if not clean_source.startswith("@"): clean_source = f"@{clean_source}"
        suffix = f" | {MY_CHANNEL_ID} | src {clean_source}" if use_branding else f" | {clean_source}"
        
        if raw_config.startswith('vmess://'):
            b64 = raw_config[8:]
            b64 += "=" * (-len(b64) % 4)
            v_data = json.loads(base64.b64decode(b64).decode('utf-8'))
            v_data['ps'] = f"{get_only_flag(v_data.get('ps', ''))}{suffix}"
            return "vmess://" + base64.b64encode(json.dumps(v_data).encode('utf-8')).decode('utf-8')
        else:
            base, name = raw_config.split('#', 1) if '#' in raw_config else (raw_config, "")
            return f"{base}#{urllib.parse.quote(f'{get_only_flag(name)}{suffix}')}"
    except: return raw_config

def run():
    print("--- STARTING SCRIPT ---")
    db_data = []
    # لود دیتابیس با مدیریت خطای پیشرفته برای جلوگیری از ValueError
    if os.path.exists('data.temp'):
        with open('data.temp', 'r', encoding='utf-8') as f:
            for line in f:
                # استفاده از جداکننده مخصوص برای جلوگیری از تداخل با متن کانفیگ
                parts = line.strip().split(':::') 
                if len(parts) == 3:
                    try:
                        float(parts[0]) # تست سلامت زمان
                        db_data.append(tuple(parts))
                    except: continue

    for ch in CHANNELS:
        try:
            r = requests.get(f"https://t.me/s/{ch}", timeout=10)
            soup = BeautifulSoup(r.text, 'html.parser')
            for msg in soup.find_all('div', class_='tgme_widget_message_text'):
                for line in msg.get_text('\n').split('\n'):
                    line = line.strip()
                    if any(line.startswith(p) for p in SUPPORTED_PROTOCOLS):
                        if not any(x[2] == line for x in db_data):
                            db_data.append((str(datetime.now().timestamp()), ch, line))
        except: continue

    now_ts = datetime.now().timestamp()
    # فیلتر ۱۲ ساعته
    valid_db = [i for i in db_data if now_ts - float(i[0]) < (EXPIRY_HOURS * 3600)]
    
    # فیلتر ۲ ساعته برای فایل ۵ (دقیقاً طبق خواسته شما)
    batch_5 = [i for i in valid_db if now_ts - float(i[0]) < (STRICT_LIMIT_HOURS * 3600)]
    
    def save(fn, batch, brand=False):
        with open(fn, 'w', encoding='utf-8') as f:
            for p in PINNED_CONFIGS: f.write(p + "\n\n")
            for _, ch, cfg in batch: f.write(analyze_and_rename(cfg, ch, brand) + "\n\n")
        print(f"Saved {fn} with {len(batch)} configs.")

    save('configs3.txt', valid_db[-ROTATION_LIMIT_3:], True)
    save('configs5.txt', batch_5, True) # فایل ۵ با همان فرمت ۳

    # ذخیره دیتابیس با جداکننده امن :::
    with open('data.temp', 'w', encoding='utf-8') as f:
        for item in valid_db:
            f.write(f"{item[0]}:::{item[1]}:::{item[2]}\n")
    print("--- FINISHED ---")

if __name__ == "__main__":
    run()
