import requests
from bs4 import BeautifulSoup
import re
import os
import html
from datetime import datetime, timezone

# =============================================================
#  بخش تنظیمات (Settings)
# =============================================================
PINNED_CONFIGS = [
    "ss://bm9uZTpmOGY3YUN6Y1BLYnNGOHAz@bache:138#%F0%9F%91%91",
    #"ss://bm9uZTpmOGY3YUN6Y1BLYnNGOHAz@bache:138#%F0%9F%91%92"
]

EXPIRY_HOURS = 24       # حذف کانفیگ‌های قدیمی‌تر از 24 ساعت
SEARCH_LIMIT_HOURS = 1  # بررسی 1 ساعت اخیر کانال
ROTATION_LIMIT = 65     # تعداد کانفیگ در هر دور نمایش
# =============================================================

def extract_configs_logic(msg_div):
    # تبدیل ایموجی به متن
    for img in msg_div.find_all("img"):
        if 'emoji' in img.get('class', []) and img.get('alt'):
            img.replace_with(img['alt'])
    
    # تبدیل br به اینتر
    for br in msg_div.find_all("br"):
        br.replace_with("\n")
    
    full_text = html.unescape(msg_div.get_text())
    
    protocols = ['vless://', 'vmess://', 'trojan://', 'hysteria2://', 'hy2://', 'ss://', 'shadowsocks://']
    extracted = []
    
    lines = full_text.split('\n')
    
    for line in lines:
        starts = []
        for proto in protocols:
            for m in re.finditer(re.escape(proto), line):
                starts.append(m.start())
        starts.sort()
        
        for i in range(len(starts)):
            start_pos = starts[i]
            if i + 1 < len(starts):
                end_pos = starts[i+1]
                candidate = line[start_pos:end_pos]
            else:
                candidate = line[start_pos:]
            
            if '   ' in candidate:
                candidate = candidate.split('   ')[0]
            
            final_cfg = candidate.strip()
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
    # 1. خواندن لیست کانال‌ها
    if not os.path.exists('channels.txt'): return
    with open('channels.txt', 'r') as f:
        channels = [line.strip() for line in f if line.strip()]

    # 2. خواندن دیتابیس فعلی
    existing_data = []
    if os.path.exists('data.temp'):
        with open('data.temp', 'r') as f:
            for line in f:
                parts = line.strip().split('|')
                if len(parts) == 2: existing_data.append(parts)

    # استخراج لیست کانفیگ‌های موجود برای جلوگیری از تکرار
    all_known_configs = [d[1] for d in existing_data]
    new_entries = []
    now = datetime.now().timestamp()

    # 3. دریافت کانفیگ‌های جدید
    # نکته: ما لیست را معکوس نمی‌کنیم تا ترتیب زمانی حفظ شود
    for ch in channels:
        found = get_messages_within_limit(ch)
        for c in found:
            if c not in all_known_configs and c not in PINNED_CONFIGS:
                # افزودن به لیست جدیدها
                new_entries.append([str(now), c])
                all_known_configs.append(c)

    # 4. ترکیب: کانفیگ‌های قدیمی + کانفیگ‌های جدید (ته لیست)
    # این تغییر باعث می‌شود کانفیگ‌های جدید بروند ته صف
    combined = existing_data + new_entries
    
    # حذف منقضی شده‌ها
    valid_db_data = [item for item in combined if now - float(item[0]) < (EXPIRY_HOURS * 3600)]

    # 5. مدیریت چرخش (Rotation)
    current_index = 0
    if os.path.exists('pointer.txt'):
        try:
            with open('pointer.txt', 'r') as f:
                current_index = int(f.read().strip())
        except:
            current_index = 0

    total_configs = len(valid_db_data)
    selected_configs = []
    next_index = 0

    if total_configs > 0:
        # اگر اشاره‌گر از کل تعداد بیشتر شده، برگرد اول خط
        if current_index >= total_configs:
            current_index = 0
        
        end_index = current_index + ROTATION_LIMIT
        
        # برش زدن لیست
        if end_index <= total_configs:
            # حالت عادی: برداشتن یک تکه از وسط
            batch = valid_db_data[current_index : end_index]
            selected_configs = [item[1] for item in batch]
            next_index = end_index
        else:
            # حالت لوپ: رسیدن به ته لیست و برداشتن بقیه از اول لیست
            batch1 = valid_db_data[current_index : total_configs]
            remaining_needed = ROTATION_LIMIT - len(batch1)
            batch2 = valid_db_data[0 : remaining_needed]
            
            selected_configs = [item[1] for item in batch1 + batch2]
            next_index = remaining_needed
    else:
        next_index = 0

    # 6. نوشتن فایل خروجی (اشتراک کاربر)
    with open('configs.txt', 'w', encoding='utf-8') as f:
        # اول پین شده‌ها
        for pin in PINNED_CONFIGS:
            f.write(pin + "\n\n")
        
        # بعد ۶۵ تای انتخابی
        for cfg in selected_configs:
            if cfg not in PINNED_CONFIGS:
                f.write(cfg + "\n\n")

    # 7. ذخیره دیتابیس کامل
    with open('data.temp', 'w', encoding='utf-8') as f:
        for ts, cfg in valid_db_data:
            if cfg not in PINNED_CONFIGS:
                f.write(f"{ts}|{cfg}\n")

    # 8. ذخیره موقعیت جدید اشاره‌گر
    with open('pointer.txt', 'w', encoding='utf-8') as f:
        f.write(str(next_index))

if __name__ == "__main__":
    run()
