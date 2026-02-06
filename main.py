import requests
from bs4 import BeautifulSoup
import re
import os
import html
from datetime import datetime, timezone

# =============================================================
#  بخش تنظیمات (Settings)
# =============================================================
# 1. کانفیگ‌هایی که همیشه باید اول باشند (هر چندتا خواستی اضافه کن)
PINNED_CONFIGS = [
    "ss://bm9uZTpmOGY3YUN6Y1BLYnNGOHAz@bache:138#%F0%9F%91%91",
    #"ss://bm9uZTpmOGY3YUN6Y1BLYnNGOHAz@bache:138#%F0%9F%91%92"
]

EXPIRY_HOURS = 24      # زمان حذف کانفیگ‌های قدیمی
SEARCH_LIMIT_HOURS = 1 # بررسی پیام‌های 1 ساعت اخیر کانال‌ها
# =============================================================

def extract_configs_logic(msg_div):
    """
    استخراج با منطق ۴ شرط توقف:
    1. 3 اسپیس / 2. خط بعد / 3. شروع پروتکل جدید / 4. پایان پیام
    """
    # تبدیل تگ‌های ایموجی تلگرام به متن واقعی برای جلوگیری از قطع شدن لینک
    for img in msg_div.find_all("img"):
        if 'emoji' in img.get('class', []) and img.get('alt'):
            img.replace_with(img['alt'])
    
    # تبدیل <br> به خط جدید برای اعمال قانون توقف در خط بعد
    for br in msg_div.find_all("br"):
        br.replace_with("\n")
    
    # دریافت متن تمیز شده
    full_text = html.unescape(msg_div.get_text())
    
    protocols = ['vless://', 'vmess://', 'trojan://']
    extracted = []
    
    # تقسیم بر اساس خط (قانون توقف در خط بعد)
    lines = full_text.split('\n')
    
    for line in lines:
        starts = []
        for proto in protocols:
            for m in re.finditer(re.escape(proto), line):
                starts.append(m.start())
        starts.sort()
        
        for i in range(len(starts)):
            start_pos = starts[i]
            
            # قانون توقف در صورت شروع پروتکل جدید در همان خط
            if i + 1 < len(starts):
                end_pos = starts[i+1]
                candidate = line[start_pos:end_pos]
            else:
                # قانون توقف در انتهای خط یا پیام
                candidate = line[start_pos:]
            
            # قانون توقف در صورت مشاهده 3 فاصله (اسپیس) پشت سر هم
            if '   ' in candidate:
                candidate = candidate.split('   ')[0]
            
            final_cfg = candidate.strip()
            # فیلتر طول (حداقل 8 کاراکتر)
            if len(final_cfg) > 7:
                extracted.append(final_cfg)
                
    return extracted

def get_messages_within_limit(channel_username):
    url = f"https://t.me/s/{channel_username}"
    try:
        response = requests.get(url, timeout=15)
        if response.status_code != 200: return []
        
        soup = BeautifulSoup(response.text, 'html.parser')
        message_wraps = soup.find_all('div', class_='tgme_widget_message_wrap')
        
        valid_configs = []
        now_utc = datetime.now(timezone.utc)
        
        for wrap in message_wraps:
            try:
                time_tag = wrap.find('time')
                if not time_tag: continue
                msg_time = datetime.fromisoformat(time_tag['datetime'])
                if (now_utc - msg_time).total_seconds() > (SEARCH_LIMIT_HOURS * 3600):
                    continue

                msg_text_div = wrap.find('div', class_='tgme_widget_message_text')
                if not msg_text_div: continue

                configs = extract_configs_logic(msg_text_div)
                for c in configs:
                    if c not in valid_configs:
                        valid_configs.append(c)
            except: continue
        return valid_configs
    except: return []

def run():
    if not os.path.exists('channels.txt'): return
    with open('channels.txt', 'r') as f:
        channels = [line.strip() for line in f if line.strip()]

    existing_data = []
    if os.path.exists('data.temp'):
        with open('data.temp', 'r') as f:
            for line in f:
                parts = line.strip().split('|')
                if len(parts) == 2: existing_data.append(parts)

    all_known_configs = [d[1] for d in existing_data]
    new_entries = []
    now = datetime.now().timestamp()

    for ch in channels:
        found = get_messages_within_limit(ch)
        for c in found:
            # اگر کانفیگ پیدا شده، جزو لیست PINNED نباشد، آن را ذخیره کن
            if c not in all_known_configs and c not in PINNED_CONFIGS:
                new_entries.insert(0, [str(now), c])
                all_known_configs.append(c)

    # فیلتر کردن موارد قدیمی دیتابیس (غیر از PINNED ها که اصلاً در دیتابیس نیستند)
    combined = new_entries + existing_data
    final_data = [item for item in combined if now - float(item[0]) < (EXPIRY_HOURS * 3600)]

    # نوشتن در فایل خروجی
    with open('configs.txt', 'w', encoding='utf-8') as f:
        # اول: کانفیگ‌های سنجاق شده (همیشه در صدر)
        for pin in PINNED_CONFIGS:
            f.write(pin + "\n\n")
            
        # دوم: کانفیگ‌های استخراج شده از کانال‌ها
        for _, cfg in final_data:
            # جلوگیری از تکرار احتمالی کانفیگ سنجاق شده در لیست استخراجی
            if cfg not in PINNED_CONFIGS:
                f.write(cfg + "\n\n")

    # آپدیت دیتابیس (فقط برای موارد استخراجی)
    with open('data.temp', 'w', encoding='utf-8') as f:
        for ts, cfg in final_data:
            if cfg not in PINNED_CONFIGS:
                f.write(f"{ts}|{cfg}\n")

if __name__ == "__main__":
    run()
