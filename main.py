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
    # اینجا فرض بر این است که منطق جمع‌آوری شما در unique_pool ذخیره شده است
    # برای کوتاه شدن پاسخ، من فقط بخش نهایی ذخیره‌سازی را اصلاح می‌کنیم:
    
    # [بخش جمع‌آوری کد اصلی شما اینجا قرار دارد...]
    # فرض کنید لیست نهایی شما unique_pool است شامل (timestamp, channel, config)
    
    unique_pool = [] # این لیست در کد اصلی شما پر می‌شود
    
    # ... (کد اصلی جمع‌آوری کانفیگ‌ها را اینجا نگه دارید) ...

    # --- بخش نهایی ذخیره‌سازی فایل‌ها ---
    pool_size = len(unique_pool)
    if pool_size == 0: return

    def save_output(filename, batch, use_custom_branding=False):
        with open(filename, 'w', encoding='utf-8') as f:
            for pin in PINNED_CONFIGS:
                f.write(pin + "\n\n")
            for ts, source_ch, raw_cfg in batch:
                renamed = analyze_and_rename(raw_cfg, source_ch, use_my_branding=use_custom_branding)
                f.write(renamed + "\n\n")

    # فایل‌های قبلی
    # (محاسبات batch1 و batch2 و batch_newest مشابه کد خودتان)
    
    # --- ساخت فایل جدید configs5.txt (مخصوص بات) ---
    now_ts = datetime.now().timestamp()
    # فقط کانفیگ‌هایی که حداکثر ۲ ساعت پیش اضافه شده‌اند
    valid_2h = [item for item in unique_pool if now_ts - float(item[0]) < (2 * 3600)]
    batch_5 = valid_2h[-1000:] # حداکثر ۱۰۰۰ تای آخر

    # ذخیره فایل‌ها
    # save_output('configs.txt', batch1) ... و غیره
    save_output('configs3.txt', unique_pool[-ROTATION_LIMIT_3:], use_custom_branding=True)
    save_output('configs5.txt', batch_5, use_custom_branding=True)

if __name__ == "__main__":
    run()
