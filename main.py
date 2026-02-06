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
]

EXPIRY_HOURS = 24       
SEARCH_LIMIT_HOURS = 1  
ROTATION_LIMIT = 150     # هر عددی خواستی اینجا بذار
# =============================================================

def extract_configs_logic(msg_div):
    for img in msg_div.find_all("img"):
        if 'emoji' in img.get('class', []) and img.get('alt'):
            img.replace_with(img['alt'])
    
    for br in msg_div.find_all("br"):
        br.replace_with("\n")
    
    full_text = html.unescape(msg_div.get_text())
    # ترتیب پروتکل‌ها مهم است: اول بلندترها را چک می‌کنیم
    protocols = ['vless://', 'vmess://', 'trojan://', 'hysteria2://', 'hy2://']
    extracted = []
    
    lines = full_text.split('\n')
    for line in lines:
        # پیدا کردن موقعیت تمام پروتکل‌ها
        starts = []
        for proto in protocols:
            for m in re.finditer(re.escape(proto), line):
                starts.append((m.start(), proto))
        
        # مرتب‌سازی بر اساس مکان شروع در خط
        starts.sort(key=lambda x: x[0])
        
        for i in range(len(starts)):
            start_pos, current_proto = starts[i]
            
            if i + 1 < len(starts):
                end_pos = starts[i+1][0]
                candidate = line[start_pos:end_pos]
            else:
                candidate = line[start_pos:]
            
            if '   ' in candidate:
                candidate = candidate.split('   ')[0]
            
            final_cfg = candidate.strip()
            # چک کردن اینکه آیا واقعاً با یکی از پروتکل‌ها شروع می‌شود
            if any(final_cfg.startswith(p) for p in protocols) and len(final_cfg) > 10:
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
            # جلوگیری از اضافه کردن تکراری به دیتابیس
            if c not in all_known_configs and c not in PINNED_CONFIGS:
                new_entries.append([str(now), c])
                all_known_configs.append(c)

    combined = existing_data + new_entries
    valid_db_data = [item for item in combined if now - float(item[0]) < (EXPIRY_HOURS * 3600)]

    # منطق چرخش
    current_index = 0
    if os.path.exists('pointer.txt'):
        try:
            with open('pointer.txt', 'r') as f:
                current_index = int(f.read().strip())
        except: current_index = 0

    total_configs = len(valid_db_data)
    selected_configs = []
    next_index = 0

    if total_configs > 0:
        if current_index >= total_configs:
            current_index = 0
        
        end_index = current_index + ROTATION_LIMIT
        if end_index <= total_configs:
            batch = valid_db_data[current_index : end_index]
            selected_configs = [item[1] for item in batch]
            next_index = end_index
        else:
            batch1 = valid_db_data[current_index : total_configs]
            remaining = ROTATION_LIMIT - len(batch1)
            batch2 = valid_db_data[0 : remaining]
            selected_configs = [item[1] for item in batch1 + batch2]
            next_index = remaining
    
    # حذف تکراری‌های احتمالی در لیست نهایی برای محکم‌کاری
    final_output_list = []
    seen = set()
    
    # اضافه کردن پین شده‌ها به لیست "دیده شده"
    for p in PINNED_CONFIGS:
        seen.add(p)

    for cfg in selected_configs:
        if cfg not in seen:
            final_output_list.append(cfg)
            seen.add(cfg)

    # نوشتن فایل خروجی
    with open('configs.txt', 'w', encoding='utf-8') as f:
        for pin in PINNED_CONFIGS:
            f.write(pin + "\n\n")
        for cfg in final_output_list:
            f.write(cfg + "\n\n")

    # ذخیره دیتابیس
    with open('data.temp', 'w', encoding='utf-8') as f:
        for ts, cfg in valid_db_data:
            if cfg not in PINNED_CONFIGS:
                f.write(f"{ts}|{cfg}\n")

    with open('pointer.txt', 'w', encoding='utf-8') as f:
        f.write(str(next_index))

if __name__ == "__main__":
    run()
