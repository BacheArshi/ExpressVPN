import requests
from bs4 import BeautifulSoup
import re
import os
from datetime import datetime, timezone, timedelta

# =============================================================
#  تنظیمات اصلی
# =============================================================
EXPIRY_HOURS = 0.083   # حذف کانفیگ‌ها بعد از 24 ساعت
SEARCH_LIMIT_HOURS = 1 # بررسی پیام‌های 1 ساعت اخیر
# =============================================================

def get_messages_within_limit(channel_username):
    url = f"https://t.me/s/{channel_username}"
    try:
        response = requests.get(url, timeout=15)
        if response.status_code != 200: return []
        
        soup = BeautifulSoup(response.text, 'html.parser')
        message_wraps = soup.find_all('div', class_='tgme_widget_message_wrap')
        
        valid_configs = []
        
        # اصلاح مهم Regex:
        # اضافه کردن / برای مسیرها (path)
        # اضافه کردن [] برای آدرس‌های IPv6
        pattern = r"(?:vless|vmess|trojan|ss|shadowsocks)://[a-zA-Z0-9\-_@.:?#%&=+/\[\]]+"
        
        now_utc = datetime.now(timezone.utc)
        
        for wrap in message_wraps:
            try:
                # 1. بررسی زمان پیام
                time_tag = wrap.find('time')
                if not time_tag: continue
                
                msg_time_str = time_tag['datetime']
                msg_time = datetime.fromisoformat(msg_time_str)
                
                # اگر پیام قدیمی‌تر از حد مجاز است، بررسی نکن
                if (now_utc - msg_time).total_seconds() > (SEARCH_LIMIT_HOURS * 3600):
                    continue

                # 2. استخراج و تمیزسازی متن
                msg_text_div = wrap.find('div', class_='tgme_widget_message_text')
                if not msg_text_div: continue

                # تبدیل <br> به فاصله برای جدا شدن خطوط چسبیده
                for br in msg_text_div.find_all('br'):
                    br.replace_with(' ')
                
                text = msg_text_div.get_text()
                
                # 3. پیدا کردن کانفیگ‌ها
                found = re.findall(pattern, text)
                for item in found:
                    clean_config = item.strip()
                    
                    # اصلاح مهم: کاهش محدودیت طول به 7 کاراکتر
                    # ss://a (حداقل طول منطقی)
                    if len(clean_config) > 7 and clean_config not in valid_configs:
                        valid_configs.append(clean_config)
                        
            except Exception as e:
                continue
                
        return valid_configs

    except Exception as e:
        print(f"Error scraping {channel_username}: {e}")
        return []

def run():
    if not os.path.exists('channels.txt'):
        return

    with open('channels.txt', 'r') as f:
        channels = [line.strip() for line in f if line.strip()]

    existing_data = []
    if os.path.exists('data.temp'):
        with open('data.temp', 'r') as f:
            for line in f:
                parts = line.strip().split('|')
                if len(parts) == 2:
                    existing_data.append(parts)

    all_known_configs = [d[1] for d in existing_data]
    new_entries = []
    now = datetime.now().timestamp()

    # استخراج موارد جدید
    for ch in channels:
        found = get_messages_within_limit(ch)
        for c in found:
            if c not in all_known_configs:
                new_entries.insert(0, [str(now), c])
                all_known_configs.append(c)

    # حذف موارد قدیمی (24 ساعت)
    combined = new_entries + existing_data
    final_data = []
    
    for ts, cfg in combined:
        if now - float(ts) < (EXPIRY_HOURS * 3600):
            final_data.append([ts, cfg])

    # ذخیره فایل کانفیگ
    with open('configs.txt', 'w', encoding='utf-8') as f:
        for _, cfg in final_data:
            f.write(cfg)
            f.write("\n\n")

    # ذخیره دیتابیس
    with open('data.temp', 'w', encoding='utf-8') as f:
        for ts, cfg in final_data:
            f.write(f"{ts}|{cfg}\n")

if __name__ == "__main__":
    run()
