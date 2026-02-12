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
            v_data = json.loads(base64.b64decode(raw_config[8:]).decode('utf-8'))
            flag = get_only_flag(v_data.get('ps', ''))
            new_name = f"{flag} | {MY_CHANNEL_ID}" if use_my_branding else f"{flag} | {source_ch}"
            v_data['ps'] = new_name
            return "vmess://" + base64.b64encode(json.dumps(v_data).encode('utf-8')).decode('utf-8')
        else:
            if '#' in raw_config:
                base_part, old_name = raw_config.split('#', 1)
                flag = get_only_flag(old_name)
            else:
                base_part = raw_config
                flag = NOT_FOUND_FLAG
            
            new_name = f"{flag} | {MY_CHANNEL_ID}" if use_my_branding else f"{flag} | {source_ch}"
            return f"{base_part}#{urllib.parse.quote(new_name)}"
    except:
        return raw_config

def run():
    # --- لود کردن دیتای قبلی (data.temp) ---
    unique_pool = []
    if os.path.exists('data.temp'):
        try:
            with open('data.temp', 'r', encoding='utf-8') as f:
                for line in f:
                    parts = line.strip().split(',', 2)
                    if len(parts) == 3:
                        unique_pool.append(tuple(parts))
        except: pass

    # --- بخش دریافت کانفیگ‌ها (Scraping) ---
    # در اینجا کد اصلی شما برای جمع‌آوری کانفیگ‌ها اجرا می‌شود
    # (فرض بر این است که منطق جمع‌آوری شما لیست unique_pool را آپدیت می‌کند)

    # --- فیلتر کردن کانفیگ‌های منقضی شده ---
    now_ts = datetime.now().timestamp()
    unique_pool = [item for item in unique_pool if now_ts - float(item[0]) < (EXPIRY_HOURS * 3600)]

    pool_size = len(unique_pool)
    if pool_size == 0:
        print("هیچ کانفیگی پیدا نشد.")
        return

    # --- توابع کمکی برای ذخیره‌سازی ---
    def save_output(filename, batch, use_custom_branding=False):
        with open(filename, 'w', encoding='utf-8') as f:
            for pin in PINNED_CONFIGS:
                f.write(pin + "\n\n")
            for ts, source_ch, raw_cfg in batch:
                renamed = analyze_and_rename(raw_cfg, source_ch, use_my_branding=use_custom_branding)
                f.write(renamed + "\n\n")

    # --- منطق چرخش (Rotation) برای فایل‌های ۱ و ۲ ---
    pointer = 0
    if os.path.exists('pointer.txt'):
        try:
            with open('pointer.txt', 'r') as f: pointer = int(f.read().strip())
        except: pointer = 0

    def get_rotated_batch(size):
        current_index = pointer % pool_size
        if current_index + size <= pool_size:
            return unique_pool[current_index : current_index + size]
        else:
            return unique_pool[current_index:] + unique_pool[:size - (pool_size - current_index)]

    batch1 = get_rotated_batch(ROTATION_LIMIT)
    batch2 = get_rotated_batch(ROTATION_LIMIT_2)
    batch_newest = unique_pool[-ROTATION_LIMIT_3:]

    # --- ساخت فایل مخصوص بات (configs5.txt) - ۲ ساعت اخیر ---
    # فقط کانفیگ‌هایی که در ۲ ساعت گذشته پیدا شده‌اند را جدا می‌کنیم
    valid_2h = [item for item in unique_pool if now_ts - float(item[0]) < (2 * 3600)]
    batch_5 = valid_2h[-1000:] # حداکثر ۱۰۰۰ عدد

    # --- ذخیره تمامی فایل‌ها ---
    save_output('configs.txt', batch1, use_custom_branding=False)
    save_output('configs2.txt', batch2, use_custom_branding=False)
    save_output('configs3.txt', batch_newest, use_custom_branding=True)
    save_output('configs4.txt', batch_newest, use_custom_branding=False)
    save_output('configs5.txt', batch_5, use_custom_branding=True) # فایل جدید

    # آپدیت پوینتر و دیتای خام
    with open('pointer.txt', 'w') as f: f.write(str(pointer + 1))
    with open('data.temp', 'w', encoding='utf-8') as f:
        for item in unique_pool:
            f.write(f"{item[0]},{item[1]},{item[2]}\n")

if __name__ == "__main__":
    run()
