import requests
from bs4 import BeautifulSoup
import re
import os
import html
from datetime import datetime, timezone

# =============================================================
#  بخش تنظیمات
# =============================================
EXPIRY_HOURS = 24      # زمان حذف کانفیگ‌های قدیمی
SEARCH_LIMIT_HOURS = 1 # بررسی پیام‌های 1 ساعت اخیر
# =============================================================

def extract_configs_final_boss(msg_div):
    """
    استخراج با منطق: 3 اسپیس، خط بعد، شروع بعدی، یا پایان پیام
    """
    # 1. تبدیل تگ‌های <br> به اینتر واقعی
    for br in msg_div.find_all("br"):
        br.replace_with("\n")
    
    # 2. تبدیل تگ‌های ایموجی به متن واقعی (🇩🇪)
    for img in msg_div.find_all("img"):
        if 'emoji' in img.get('class', []) and img.get('alt'):
            img.replace_with(img['alt'])
    
    # 3. گرفتن متن خام و تبدیل کاراکترهای HTML (مثل &amp; به &)
    full_text = html.unescape(msg_div.get_text())
    
    protocols = ['vless://', 'vmess://', 'ss://', 'trojan://', 'shadowsocks://']
    extracted = []
    
    # جدا کردن بر اساس خط (قانون: توقف در خط بعد)
    lines = full_text.split('\n')
    
    for line in lines:
        # پیدا کردن تمام نقاط شروع در این خط
        starts = []
        for proto in protocols:
            for m in re.finditer(re.escape(proto), line):
                starts.append(m.start())
        starts.sort()
        
        for i in range(len(starts)):
            start_pos = starts[i]
            
            # قانون: توقف در صورت شروع کانفیگ بعدی در همان خط
            if i + 1 < len(starts):
                end_pos = starts[i+1]
                candidate = line[start_pos:end_pos]
            else:
                # قانون: توقف در اتمام پیام یا سطر
                candidate = line[start_pos:]
            
            # قانون: توقف در صورت مشاهده 3 فاصله پشت سر هم
            if '   ' in candidate:
                candidate = candidate.split('   ')[0]
            
            final_cfg = candidate.strip()
            # فیلتر طول (حداقل 8 کاراکتر برای ss://a...)
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

                configs = extract_configs_final_boss(msg_text_div)
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
            if c not in all_known_configs:
                new_entries.insert(0, [str(now), c])
                all_known_configs.append(c)

    combined = new_entries + existing_data
    final_data = [item for item in combined if now - float(item[0]) < (EXPIRY_HOURS * 3600)]

    with open('configs.txt', 'w', encoding='utf-8') as f:
        for _, cfg in final_data:
            f.write(cfg + "\n\n")

    with open('data.temp', 'w', encoding='utf-8') as f:
        for ts, cfg in final_data:
            f.write(f"{ts}|{cfg}\n")

if __name__ == "__main__":
    run()
