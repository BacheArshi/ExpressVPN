import requests
from bs4 import BeautifulSoup
import re
import os
from datetime import datetime, timedelta

# =============================================================
#  بخش تنظیمات (اینجا را می‌توانید تغییر دهید)
# =============================================================
EXPIRY_HOURS = 24  # هر کانفیگی که بیشتر از این ساعت در لیست باشد، حذف می‌شود
# =============================================================

def extract_configs_from_url(channel_username):
    url = f"https://t.me/s/{channel_username}"
    try:
        response = requests.get(url, timeout=10)
        if response.status_code != 200: return []
        soup = BeautifulSoup(response.text, 'html.parser')
        messages = soup.find_all('div', class_='tgme_widget_message_text')
        
        configs = []
        # این الگو تمام لینک‌های موجود در یک پیام را پیدا می‌کند
        pattern = r"(?:vless|vmess|trojan|ss|shadowsocks)://[^\s<]+"
        
        for msg in messages:
            full_text = msg.get_text() # کل متن پیام را می‌گیرد
            found = re.findall(pattern, full_text) # تمام کانفیگ‌های داخل پیام را پیدا می‌کند
            for item in found:
                configs.append(item.strip()) # هر کانفیگ را جداگانه به لیست اضافه می‌کند
        return configs
    except:
        return []

def run():
    # 1. خواندن لیست کانال‌ها
    if not os.path.exists('channels.txt'):
        return

    with open('channels.txt', 'r') as f:
        channels = [line.strip() for line in f if line.strip()]

    # 2. خواندن اطلاعات قبلی (زمان ذخیره شده و خود کانفیگ)
    existing_data = []
    if os.path.exists('data.temp'):
        with open('data.temp', 'r') as f:
            for line in f:
                parts = line.strip().split('|')
                if len(parts) == 2:
                    existing_data.append(parts)

    all_known_configs = [d[1] for d in existing_data]
    new_entries = []
    now = datetime.now()

    # 3. بررسی کانال‌ها برای یافتن موارد جدید
    for ch in channels:
        found = extract_configs_from_url(ch)
        for c in found:
            if c not in all_known_configs:
                # جدیدترین‌ها در ابتدای لیست قرار می‌گیرند
                new_entries.insert(0, [str(now.timestamp()), c])
                all_known_configs.append(c)

    # 4. ترکیب لیست جدید با قدیمی و حذف موارد منقضی شده
    combined = new_entries + existing_data
    final_data = []
    for ts, cfg in combined:
        time_diff = now.timestamp() - float(ts)
        # اگر زمان سپری شده کمتر از مقدار تنظیم شده (مثلاً 24 ساعت) باشد، نگهش دار
        if time_diff < (EXPIRY_HOURS * 3600):
            final_data.append([ts, cfg])

    # 5. نوشتن در فایل configs.txt با رعایت فاصله کامل (یک خط خالی بین هر کانفیگ)
    with open('configs.txt', 'w') as f:
        for _, cfg in final_data:
            # اضافه کردن دو عدد \n باعث می‌شود یک خط کاملاً خالی ایجاد شود
            f.write(cfg + "\n\n")

    # 6. آپدیت فایل دیتابیس کمکی
    with open('data.temp', 'w') as f:
        for ts, cfg in final_data:
            f.write(f"{ts}|{cfg}\n")

if __name__ == "__main__":
    run()
