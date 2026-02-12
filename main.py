import requests
from bs4 import BeautifulSoup
import re
import os
import json
import base64
import urllib.parse
from datetime import datetime, timezone

# =============================================================
# تنظیمات
# =============================================================
PINNED_CONFIGS = ["ss://bm9uZTpmOGY3YUN6Y1BLYnNGOHAz@lil:360#%F0%9F%91%91%20%40Express_alaki"]
MY_CHANNEL_ID = "@Express_alaki"
CHANNELS = ['HajmVPN_Config', 'DailyV2RY', 'V2ray_Extractor', 'v2nodes', 'V2ray20261', 'Hope_Net', 'SafeNet_Server', 'L_I_N_E_V_P_N', 'v2rayNG_VPNN']
SUPPORTED_PROTOCOLS = ['vless://', 'vmess://', 'trojan://', 'hysteria2://', 'hy2://']
EXPIRY_HOURS = 12
STRICT_LIMIT_HOURS = 2
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
    print("--- STARTING ACCURATE SCRIPT ---")
    db_data = []
    now_ts = datetime.now().timestamp()

    # ۱. خواندن دیتابیس با دقت بالا
    if os.path.exists('data.temp'):
        with open('data.temp', 'r', encoding='utf-8') as f:
            for line in f:
                # استفاده از جداکننده کاملاً خاص برای جلوگیری از خطا در پایتون
                parts = line.strip().split('::SPLIT::') 
                if len(parts) == 3:
                    try:
                        t = float(parts[0])
                        # فقط اگر زمان ذخیره شده معتبر و زیر ۱۲ ساعت باشد به دیتابیس زنده اضافه کن
                        if now_ts - t < (EXPIRY_HOURS * 3600):
                            db_data.append((parts[0], parts[1], parts[2]))
                    except: continue
    
    print(f"Loaded {len(db_data)} valid configs from DB.")

    # ۲. اسکرپ کردن (فقط کانفیگ‌های واقعاً جدید اضافه می‌شوند)
    new_found = 0
    for ch in CHANNELS:
        try:
            r = requests.get(f"https://t.me/s/{ch}", timeout=10)
            soup = BeautifulSoup(r.text, 'html.parser')
            for msg in soup.find_all('div', class_='tgme_widget_message_text'):
                for line in msg.get_text('\n').split('\n'):
                    line = line.strip()
                    if any(line.startswith(p) for p in SUPPORTED_PROTOCOLS):
                        # چک کردن اینکه آیا این متن کانفیگ دقیقاً در دیتابیس فعلی هست؟
                        if not any(x[2] == line for x in db_data):
                            db_data.append((str(datetime.now().timestamp()), ch, line))
                            new_found += 1
        except: continue
    
    print(f"Scraping done. Found {new_found} brand new configs.")

    # ۳. فیلتر ۲ ساعت برای فایل ۵ (دقیق و سخت‌گیرانه)
    # این بخش فقط مواردی را برمی‌دارد که زمان ثبت‌شان کمتر از ۷۲۰۰ ثانیه با الان فاصله دارد
    batch_5 = [i for i in db_data if now_ts - float(i[0]) < (STRICT_LIMIT_HOURS * 3600)]
    
    print(f"DEBUG: Configs under 2 hours old: {len(batch_5)}")

    def save(fn, batch, brand=False):
        with open(fn, 'w', encoding='utf-8') as f:
            for p in PINNED_CONFIGS: f.write(p + "\n\n")
            if batch:
                for _, ch, cfg in batch: 
                    f.write(analyze_and_rename(cfg, ch, brand) + "\n\n")
        print(f"Saved {fn}")

    # ذخیره‌سازی فایل‌ها
    save('configs3.txt', db_data[-ROTATION_LIMIT_3:], True)
    save('configs5.txt', batch_5, True)

    # ۴. ذخیره دیتابیس با فرمت جدید و امن
    with open('data.temp', 'w', encoding='utf-8') as f:
        for item in db_data:
            f.write(f"{item[0]}::SPLIT::{item[1]}::SPLIT::{item[2]}\n")
            
    print("--- SCRIPT FINISHED ---")

if __name__ == "__main__":
    run()
