import requests
from bs4 import BeautifulSoup
import re
import os
from datetime import datetime, timedelta

# تنظیمات: 24 ساعت انقضا
EXPIRY_HOURS = 24 

def extract_configs_from_url(channel_username):
    url = f"https://t.me/s/{channel_username}"
    try:
        response = requests.get(url, timeout=10)
        if response.status_code != 200: return []
        soup = BeautifulSoup(response.text, 'html.parser')
        messages = soup.find_all('div', class_='tgme_widget_message_text')
        
        configs = []
        # الگو برای تشخیص پروتکل‌های مختلف
        pattern = r"(vless|vmess|trojan|ss|shadowsocks)://[^\s<]+"
        for msg in messages:
            found = re.findall(pattern, msg.get_text())
            configs.extend(found)
        return configs
    except:
        return []

def run():
    # 1. خواندن کانال‌ها
    with open('channels.txt', 'r') as f:
        channels = [line.strip() for line in f if line.strip()]

    # 2. خواندن دیتای قبلی (زمان|کانفیگ)
    existing_data = []
    if os.path.exists('data.temp'):
        with open('data.temp', 'r') as f:
            existing_data = [line.strip().split('|') for line in f if '|' in line]

    all_known_configs = [d[1] for d in existing_data]
    new_entries = []
    now = datetime.now()

    # 3. بررسی کانال‌ها
    for ch in channels:
        found = extract_configs_from_url(ch)
        for c in found:
            if c not in all_known_configs:
                # اضافه کردن به اول لیست (جدیدترین‌ها)
                new_entries.insert(0, [str(now.timestamp()), c])
                all_known_configs.append(c)

    # 4. ترکیب و حذف قدیمی‌ها (بیش از 24 ساعت)
    combined = new_entries + existing_data
    final_data = []
    for ts, cfg in combined:
        if now.timestamp() - float(ts) < (EXPIRY_HOURS * 3600):
            final_data.append([ts, cfg])

    # 5. خروجی نهایی برای نمایش کاربر
    with open('configs.txt', 'w') as f:
        for _, cfg in final_data:
            f.write(cfg + "\n\n") # دو اینتر برای فاصله کامل

    # 6. ذخیره فایل سیستمی
    with open('data.temp', 'w') as f:
        for ts, cfg in final_data:
            f.write(f"{ts}|{cfg}\n")

if __name__ == "__main__":
    run()
