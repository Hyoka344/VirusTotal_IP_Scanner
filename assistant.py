import tkinter as tk
from tkinter import filedialog, ttk
import pandas as pd
import os
import requests
import time
import re
import threading
from datetime import datetime
from PIL import Image, ImageTk
from dotenv import load_dotenv
import csv

# Load environment
load_dotenv()
API_KEYS = [{"key": key.strip(), "exhausted": False} for key in os.getenv('VT_API_KEYS', '').split(',') if key.strip()]

if not API_KEYS:
    exit("API Key tidak ditemukan. Harap set VT_API_KEYS di file .env.")

CACHE_FILE = "scanned_domains.csv"

# Status API key
api_key_status = {
    "current_key": None,
    "remaining_keys": len(API_KEYS),
    "exhausted": False
}

highlighted_results = []

# GUI setup
root = tk.Tk()
root.title("Chill-guy Assistant")
root.geometry("500x520")
root.configure(bg="#1A1B26")

main_frame = tk.Frame(root, bg="#24283B", padx=20, pady=20)
main_frame.pack(fill="both", expand=True)

try:
    image = Image.open("Image/chillguy.jpg").resize((100, 100))
    photo = ImageTk.PhotoImage(image)
    img_label = tk.Label(main_frame, image=photo, bg="#24283B")
    img_label.pack(pady=10)
except:
    pass

title_label = tk.Label(main_frame, text="Chill-guy Assistant", font=("Arial", 16, "bold"), fg="#FFFFFF", bg="#24283B")
title_label.pack(pady=5)

upload_button = tk.Button(main_frame, text="Upload CSV/TSV", font=("Arial", 12), bg="#7AA2F7", fg="#FFFFFF")
upload_button.pack(pady=10)

reset_button = tk.Button(main_frame, text="Reset API Keys", font=("Arial", 10), bg="#9ECE6A", fg="#000000")
reset_button.pack(pady=2)

api_status_label = tk.Label(main_frame, text="✅ Ready to scan.", font=("Arial", 10), fg="#A9B1D6", bg="#24283B")
api_status_label.pack(pady=5)

progress_bar = ttk.Progressbar(main_frame, orient="horizontal", length=400, mode="determinate")
progress_label = tk.Label(main_frame, text="", font=("Arial", 12), fg="#FFFFFF", bg="#24283B")
progress_label.pack()

highlight_frame = tk.Frame(main_frame, bg="#24283B")
highlight_frame.pack(pady=5)
highlight_label = tk.Label(highlight_frame, text="", font=("Arial", 10), fg="#F7768E", bg="#24283B")
highlight_label.pack()

footer_label = tk.Label(root, text="developed by Hyoka344", font=("Arial", 10), fg="#FFFFFF", bg="#1A1B26")
footer_label.pack(side="bottom", pady=5)

# Validasi domain
def is_valid_domain(domain):
    pattern = r"^(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$"
    return bool(re.match(pattern, domain))

# Load cache
def load_cached_domains():
    if not os.path.exists(CACHE_FILE):
        return set()
    try:
        df = pd.read_csv(CACHE_FILE)
        return set(df["Address"].astype(str).tolist())
    except:
        return set()

# Update cache
def update_cache(address, data):
    try:
        file_exists = os.path.isfile(CACHE_FILE)
        with open(CACHE_FILE, 'a', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=["Address", "Country", "Owner", "Malicious", "Suspicious", "Total", "Scan Time", "Status"])
            if not file_exists:
                writer.writeheader()
            writer.writerow({"Address": address, **data})
        print(f"[DEBUG] Cached: {address}")
    except Exception as e:
        print(f"[ERROR] Failed to update cache: {e}")

def update_results_file(filename, alert_id, host_ip, address, data):
    try:
        file_exists = os.path.isfile(filename)
        with open(filename, 'a', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=["Alert Id", "Host IP", "Address", "Type", "Country", "Owner", "Malicious", "Suspicious", "Total", "Scan Time"])
            if not file_exists:
                writer.writeheader()
            writer.writerow({
                "Alert Id": alert_id,
                "Host IP": host_ip,
                "Address": address,
                "Type": "URL",
                **{k: data.get(k, '') for k in ["Country", "Owner", "Malicious", "Suspicious", "Total", "Scan Time"]}
            })
        if data["Status"] != "Safe":
            highlighted_results.append(f"⚠️ {address} - {data['Status']}")
        print(f"[DEBUG] Saved result: {address}")
    except Exception as e:
        print(f"[ERROR] Failed to write result: {e}")

# Cek reputasi domain
def check_virustotal(address):
    time.sleep(2)
    url = f'https://www.virustotal.com/api/v3/domains/{address}'

    for api_obj in API_KEYS:
        if api_obj["exhausted"]:
            continue

        api_key = api_obj["key"]
        headers = {'x-apikey': api_key}
        api_key_status["current_key"] = f"{api_key[:8]}..."
        api_status_label.config(text=f"Using API Key: {api_key_status['current_key']} ({api_key_status['remaining_keys']} keys remaining)")
        root.update_idletasks()

        try:
            response = requests.get(url, headers=headers)
            print(f"[DEBUG] Scanning {address} with key {api_key[:8]}... Status {response.status_code}")

            if response.status_code == 200:
                data = response.json()
                attributes = data.get('data', {}).get('attributes', {})
                stats = attributes.get('last_analysis_stats', {})

                malicious = stats.get('malicious', 0)
                suspicious = stats.get('suspicious', 0)
                return {
                    'Country': attributes.get('country', 'Unknown'),
                    'Owner': attributes.get('as_owner', 'Unknown'),
                    'Malicious': malicious,
                    'Suspicious': suspicious,
                    'Total': sum(stats.values()),
                    'Scan Time': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    'Status': "Safe" if malicious == 0 and suspicious == 0 else "Potentially Harmful"
                }
            elif response.status_code in [403, 429]:
                api_obj["exhausted"] = True
                api_key_status["remaining_keys"] -= 1
                if api_key_status["remaining_keys"] <= 0:
                    api_key_status["exhausted"] = True
                continue
        except Exception as e:
            print(f"[ERROR] Exception: {e}")
            api_obj["exhausted"] = True
            api_key_status["remaining_keys"] -= 1
            if api_key_status["remaining_keys"] <= 0:
                api_key_status["exhausted"] = True
            continue

    api_key_status["exhausted"] = True
    api_status_label.config(text="❌ All API keys exhausted! Please wait or replace keys.")
    upload_button.config(state="disabled")
    root.update_idletasks()
    return None

def read_file(filepath):
    try:
        if not os.path.exists(filepath):
            return None
        if filepath.endswith(".csv"):
            df = pd.read_csv(filepath, on_bad_lines='skip', engine='python')
        elif filepath.endswith(".tsv"):
            df = pd.read_csv(filepath, on_bad_lines='skip', sep='\t', engine='python')
        else:
            return None
        return df if not df.empty else None
    except:
        return None

def upload_file():
    filepath = filedialog.askopenfilename(filetypes=[("CSV & TSV Files", "*.csv;*.tsv")])
    if not filepath:
        return
    df = read_file(filepath)
    if df is not None:
        threading.Thread(target=process_data, args=(df,), daemon=True).start()

def reset_api_keys():
    load_dotenv()
    global API_KEYS
    API_KEYS = [{"key": key.strip(), "exhausted": False} for key in os.getenv('VT_API_KEYS', '').split(',') if key.strip()]
    api_key_status["remaining_keys"] = len(API_KEYS)
    api_key_status["exhausted"] = False
    upload_button.config(state="normal")
    api_status_label.config(text="✅ API Key status reset. Ready to scan.")
    print(f"[INFO] API key reset. {len(API_KEYS)} keys loaded.")

upload_button.config(command=upload_file)
reset_button.config(command=reset_api_keys)

def process_data(df):
    valid_columns = [col for col in ["Address", "Remote Host"] if col in df.columns]
    if not valid_columns or "Alert Id" not in df.columns or "Host IP" not in df.columns:
        progress_label.config(text="Kolom wajib (Alert Id, Host IP, Address/Remote Host) tidak ditemukan.")
        return

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    result_file = f"scan_results_{timestamp}.csv"

    entries = []
    for _, row in df.iterrows():
        address = None
        for col in valid_columns:
            if pd.notna(row[col]) and is_valid_domain(str(row[col])):
                address = str(row[col])
                break
        if address:
            entries.append((row["Alert Id"], row["Host IP"], address))

    cached = load_cached_domains()
    new_entries = [entry for entry in entries if entry[2] not in cached]

    total = len(new_entries)
    if total == 0:
        progress_label.config(text="Tidak ada domain baru untuk dipindai.")
        return

    progress_bar['maximum'] = total
    progress_bar['value'] = 0
    progress_label.config(text="Scanning started...")
    progress_bar.pack()

    for index, (alert_id, host_ip, address) in enumerate(new_entries, start=1):
        if api_key_status["exhausted"]:
            progress_label.config(text="Semua API key telah habis. Scan dihentikan.")
            break

        vt_data = check_virustotal(address)
        if vt_data:
            update_results_file(result_file, alert_id, host_ip, address, vt_data)
            update_cache(address, vt_data)

        progress_bar['value'] = index
        progress_label.config(text=f"Scanning: {index}/{total} ({(index/total)*100:.1f}%)")
        root.update_idletasks()

    if not api_key_status["exhausted"]:
        if highlighted_results:
            progress_label.config(text=f"Scan Completed! ⚠️ Waspada: {len(highlighted_results)} mencurigakan")
        else:
            progress_label.config(text=f"Scan Completed! Results saved in {result_file}")

root.mainloop()
