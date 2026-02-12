import requests
from bs4 import BeautifulSoup
import re
import os
import json
import base64
import urllib.parse
from datetime import datetime, timezone

# =============================================================
#  بخش تنظیمات
# =============================================================
PINNED_CONFIGS = [
    "ss://bm9uZTpmOGY3YUN6Y1BLYnNGOHAz@lil:360#%F0%9F%91%91%20%40Express_alaki",
]

MY_CHANNEL_ID = "@Express_alaki"
# لیست کانال‌ها
CHANNELS = [
    'HajmVPN_Config', 'DailyV2RY', 'V2ray_Extractor', 'v2nodes', 'V2ray20261', 'Hope_Net',
    'SafeNet_Server', 'L_I_N_E_V_P_N', 'v2rayNG_VPNN'
]

SUPPORTED_PROTOCOLS = ['vless://', 'vmess://', 'trojan://', 'hysteria2://', 'hy2://']

# تنظیمات زمانی
EXPIRY_HOURS = 12       # انقضای کلی دیتابیس
STRICT_LIMIT_HOURS = 2  # انقضای فایل ۵

ROTATION_LIMIT = 65      
ROTATION_LIMIT_2 = 1000   
ROTATION_LIMIT_3 = 3000   
# =============================================================

def get_only_flag(text):
    if not text: return "🌐"
    try:
        text = urllib.parse.unquote(urllib.parse.unquote(str(text)))
        flag_pattern = re.compile(r'[\U0001F1E6-\U0001F1FF]{2}')
        match = flag_pattern.search(text)
        return match.group(0) if match else "🌐"
    except: return "🌐"

def analyze_and_rename(raw_config, source_ch, use_my_branding=False):
    try:
        clean_source = source_ch.replace("https://t.me/", "@").replace("t.me/", "@")
        if not clean_source.startswith("@"): clean_source = f"@{clean_source}"

        if use_my_branding:
            suffix = f" | {MY_CHANNEL_ID} | src {clean_source}"
        else:
            suffix = f" | {clean_source}"

        if raw_config.startswith('vmess://'):
            b64 = raw_config[8:]
            b64 += "=" * (-len(b64) % 4)
            v_data = json.loads(base64.b64decode(b64).decode('utf-8'))
            flag = get_only_flag(v_data.get('ps', ''))
            v_data['ps'] = f"{flag}{suffix}"
            return "vmess://" + base64.b64encode(json.dumps(v_data).encode('utf-8')).decode('utf-8')
        else:
            base_part, old_name = raw_config.split('#', 1) if '#' in raw_config else (raw_config, "")
            flag = get_only_flag(old_name)
            final_name = f"{flag}{suffix}"
            return f"{base_part}#{urllib.parse.quote(final_name)}"
    except:
        return raw_config

def run():
    print("--- STARTING SCRIPT ---")
    
    # 1. لود دیتابیس
    db_data = []
    if os.path.exists('data.temp'):
        try:
            with open('data.temp', 'r', encoding='utf-8') as f:
                for line in f:
                    parts = line.strip().split(',', 2)
                    if len(parts) == 3:
                        db_data.append(tuple(parts))
            print(f"Loaded {len(db_data)} configs from database.")
        except Exception as e:
            print(f"Error loading DB: {e}")

    # 2. اسکرپ کانال‌ها
    new_found_count = 0
    for ch in CHANNELS:
        try:
            url = f"https://t.me/s/{ch}"
            resp = requests.get(url, timeout=10)
            if resp.status_code != 200: continue
            
            soup = BeautifulSoup(resp.text, 'html.parser')
            msgs = soup.find_all('div', class_='tgme_widget_message_text')
            
            for msg in msgs:
                raw_text = msg.get_text('\n')
                for line in raw_text.split('\n'):
                    line = line.strip()
                    if any(line.startswith(p) for p in SUPPORTED_PROTOCOLS):
                        # اگر تکراری نبود اضافه کن
                        if not any(x[2] == line for x in db_data):
                            db_data.append((str(datetime.now().timestamp()), ch, line))
                            new_found_count += 1
        except Exception as e:
            print(f"Error scraping {ch}: {e}")
            continue
            
    print(f"Scraping finished. Found {new_found_count} NEW configs.")

    # 3. حذف منقضی‌های کلی (۱۲ ساعت)
    now_ts = datetime.now().timestamp()
    valid_db = [item for item in db_data if now_ts - float(item[0]) < (EXPIRY_HOURS * 3600)]
    print(f"Total valid configs (last 12h): {len(valid_db)}")

    # 4. آماده‌سازی دسته‌ها
    
    # --- منطق فایل ۵ (فقط ۲ ساعت اخیر) ---
    # شرط: زمان فعلی - زمان ثبت < ۷۲۰۰ ثانیه
    batch_5 = [item for item in valid_db if now_ts - float(item[0]) < (STRICT_LIMIT_HOURS * 3600)]
    print(f"Configs for configs5.txt (Last 2 hours): {len(batch_5)}")

    batch_3 = valid_db[-ROTATION_LIMIT_3:]

    # منطق چرخشی
    pointer = 0
    if os.path.exists('pointer.txt'):
        try: pointer = int(open('pointer.txt', 'r').read().strip())
        except: pointer = 0
    
    pool_size = len(valid_db)
    if pointer >= pool_size: pointer = 0
    
    def get_rotated(size):
        if not valid_db: return []
        if pool_size <= size: return valid_db
        if pointer + size <= pool_size:
            return valid_db[pointer : pointer + size]
        else:
            return valid_db[pointer:] + valid_db[:size - (pool_size - pointer)]

    batch_1 = get_rotated(ROTATION_LIMIT)
    batch_2 = get_rotated(ROTATION_LIMIT_2)

    # 5. تابع ذخیره‌سازی تضمینی
    def save(filename, batch, branded=False):
        try:
            with open(filename, 'w', encoding='utf-8') as f:
                # اول پین شده‌ها را بنویس
                for pin in PINNED_CONFIGS: f.write(pin + "\n\n")
                
                # اگر لیستی وجود دارد بنویس
                if batch:
                    for _, ch, cfg in batch:
                        renamed = analyze_and_rename(cfg, ch, use_my_branding=branded)
                        f.write(renamed + "\n\n")
            print(f"Successfully saved {filename}")
        except Exception as e:
            print(f"Error saving {filename}: {e}")

    # ذخیره تمام فایل‌ها
    save('configs.txt', batch_1, branded=False)
    save('configs2.txt', batch_2, branded=False)
    save('configs3.txt', batch_3, branded=True)
    save('configs4.txt', batch_3, branded=False)
    
    # فایل ۵ حتما ساخته می‌شود حتی اگر batch_5 خالی باشد
    save('configs5.txt', batch_5, branded=True)

    # 6. آپدیت سیستم
    with open('pointer.txt', 'w') as f:
        new_ptr = (pointer + ROTATION_LIMIT) % pool_size if pool_size > 0 else 0
        f.write(str(new_ptr))
    
    with open('data.temp', 'w', encoding='utf-8') as f:
        for item in valid_db:
            f.write(f"{item[0]},{item[1]},{item[2]}\n")
            
    print("--- SCRIPT FINISHED ---")

if __name__ == "__main__":
    run()
