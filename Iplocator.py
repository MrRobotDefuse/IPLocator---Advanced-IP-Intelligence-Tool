#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import os
import socket
import time
import json
import re
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
import requests
from pytz import timezone
import pytz

class UltraPreciseIPHunter:
    def __init__(self):
        self.ip_data = {}
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': 'text/html,application/xhtml+xml',
            'Accept-Language': 'en-US,en;q=0.9'
        })

    def run(self):
        while True:
            self._clear_screen()
            target = self._get_input("\n[?] Enter target IP (q to quit): ")
            
            if target.lower() == 'q':
                break
                
            if not self._validate_ip(target):
                print("[!] Invalid IP address")
                time.sleep(1)
                continue
                
            self._investigate(target)
            self._show_results()
            input("\n[+] Press Enter to continue...")

    def _clear_screen(self):
        os.system('cls' if os.name == 'nt' else 'clear')

    def _get_input(self, prompt):
        try:
            return input(prompt).strip()
        except (EOFError, KeyboardInterrupt):
            return 'q'

    def _validate_ip(self, ip):
        try:
            socket.inet_aton(ip)
            return True
        except socket.error:
            return False

    def _investigate(self, target):
        self.ip_data = {'target': target}
        
        with ThreadPoolExecutor(max_workers=6) as executor:
            futures = [
                executor.submit(self._get_maxmind_data, target),
                executor.submit(self._get_ip_api_data, target),
                executor.submit(self._get_ipinfo_data, target),
                executor.submit(self._get_abstract_data, target),
                executor.submit(self._get_threat_data, target),
                executor.submit(self._port_scan, target)
            ]
            
            for future in as_completed(futures):
                try:
                    result = future.result()
                    if result:
                        self.ip_data.update(result)
                except Exception as e:
                    continue

    def _get_maxmind_data(self, target):
        try:
            resp = self.session.get(f'https://www.maxmind.com/en/locate-my-ip-address/{target}', timeout=10)
            if resp.status_code == 200:
                html = resp.text
                
                # Извлекаем данные из HTML
                street = re.search(r'"street":"([^"]+)"', html)
                city = re.search(r'"city":"([^"]+)"', html)
                postal = re.search(r'"postal":"([^"]+)"', html)
                
                return {
                    'precise_location': {
                        'street_address': street.group(1) if street else None,
                        'city': city.group(1) if city else None,
                        'postal_code': postal.group(1) if postal else None,
                        'source': 'MaxMind'
                    }
                }
        except:
            return {}

    def _get_ip_api_data(self, target):
        try:
            resp = self.session.get(f'http://ip-api.com/json/{target}?fields=66842623', timeout=10)
            if resp.status_code == 200:
                data = resp.json()
                if data.get('status') == 'success':
                    # Получаем местное время
                    tz = data.get('timezone')
                    local_time = None
                    if tz:
                        try:
                            tz_obj = timezone(tz)
                            local_time = datetime.now(tz_obj).strftime('%Y-%m-%d %H:%M:%S')
                        except:
                            pass
                    
                    return {
                        'geo': {
                            'continent': data.get('continent'),
                            'country': data.get('country'),
                            'region': data.get('regionName'),
                            'city': data.get('city'),
                            'district': data.get('district'),
                            'zip': data.get('zip'),
                            'lat': data.get('lat'),
                            'lon': data.get('lon'),
                            'timezone': tz,
                            'local_time': local_time,
                            'isp': data.get('isp'),
                            'org': data.get('org'),
                            'as': data.get('as'),
                            'asname': data.get('asname'),
                            'mobile': data.get('mobile'),
                            'proxy': data.get('proxy'),
                            'hosting': data.get('hosting'),
                            'maps': f"https://www.google.com/maps/place/{data.get('lat')},{data.get('lon')}",
                            'street_view': f"https://www.google.com/maps?q=&layer=c&cbll={data.get('lat')},{data.get('lon')}"
                        }
                    }
        except:
            return {}

    def _get_ipinfo_data(self, target):
        try:
            resp = self.session.get(f'https://ipinfo.io/{target}/json', timeout=10)
            if resp.status_code == 200:
                data = resp.json()
                loc = data.get('loc', '').split(',')
                return {
                    'network': {
                        'ip': data.get('ip'),
                        'hostname': data.get('hostname'),
                        'city': data.get('city'),
                        'region': data.get('region'),
                        'country': data.get('country'),
                        'loc': data.get('loc'),
                        'org': data.get('org'),
                        'postal': data.get('postal'),
                        'timezone': data.get('timezone'),
                        'asn': data.get('asn'),
                        'company': data.get('company'),
                        'privacy': {
                            'vpn': data.get('vpn'),
                            'proxy': data.get('proxy'),
                            'tor': data.get('tor'),
                            'relay': data.get('relay'),
                            'hosting': data.get('hosting')
                        },
                        'street': data.get('street'),
                        'street_view': f"https://www.google.com/maps?q=&layer=c&cbll={loc[0] if len(loc)>0 else ''},{loc[1] if len(loc)>1 else ''}"
                    }
                }
        except:
            return {}

    def _get_abstract_data(self, target):
        try:
            # Эмуляция запроса к Google Maps через веб-интерфейс
            resp = self.session.get(f'https://www.google.com/maps/search/?api=1&query={target}', timeout=10)
            if resp.status_code == 200:
                html = resp.text
                
                # Парсим данные из HTML Google Maps
                address = re.search(r'"address":"([^"]+)"', html)
                coords = re.search(r'"center":\[([^\]]+)\]', html)
                
                if address and coords:
                    lat, lon = coords.group(1).split(',')
                    return {
                        'google_maps': {
                            'address': address.group(1),
                            'coordinates': f"{lat},{lon}",
                            'street_view': f"https://www.google.com/maps?q=&layer=c&cbll={lat},{lon}",
                            'map_link': f"https://www.google.com/maps/place/{lat},{lon}"
                        }
                    }
        except:
            return {}

    def _get_threat_data(self, target):
        threat_data = {}
        
        try:
            resp = self.session.get(f'https://www.abuseipdb.com/check/{target}', timeout=10)
            if resp.status_code == 200:
                html = resp.text
                score = re.search(r'Abuse Confidence Score:\s*(\d+)%', html)
                reports = re.search(r'Reported (\d+) times', html)
                
                if score:
                    threat_data['abuse_score'] = f"{score.group(1)}%"
                if reports:
                    threat_data['reports'] = reports.group(1)
        except:
            pass
            
        return {'threat': threat_data}

    def _port_scan(self, target, ports=None):
        if ports is None:
            ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995, 3389]
            
        open_ports = []
        
        def check_port(port):
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(1.5)
                    if s.connect_ex((target, port)) == 0:
                        return port
            except:
                return None
                
        with ThreadPoolExecutor(max_workers=100) as executor:
            futures = [executor.submit(check_port, port) for port in ports]
            for future in as_completed(futures):
                result = future.result()
                if result:
                    open_ports.append(result)
                    
        return {'ports': sorted(open_ports)}

    def _show_results(self):
        print(f"\n[+] Ultra Precise IP Intelligence Report for {self.ip_data.get('target')}")
        print("="*90)
        
        # Основные геоданные
        geo = self.ip_data.get('geo', {})
        if geo:
            print("\n[GEOGRAPHIC LOCATION]")
            for key, val in geo.items():
                if key == 'maps':
                    print(f"  {'GOOGLE MAPS LINK':<25}: {val}")
                elif key == 'street_view':
                    print(f"  {'STREET VIEW LINK':<25}: {val}")
                elif val and val != 'None':
                    print(f"  {key.upper().replace('_', ' '):<25}: {val}")
        
        # Точное местоположение
        precise = self.ip_data.get('precise_location', {})
        if precise:
            print("\n[PRECISE LOCATION DETAILS]")
            for key, val in precise.items():
                if val and val != 'None':
                    print(f"  {key.upper().replace('_', ' '):<25}: {val}")
        
        # Данные Google Maps
        gmaps = self.ip_data.get('google_maps', {})
        if gmaps:
            print("\n[GOOGLE MAPS DATA]")
            for key, val in gmaps.items():
                if val and val != 'None':
                    print(f"  {key.upper().replace('_', ' '):<25}: {val}")
        
        # Сетевые данные
        network = self.ip_data.get('network', {})
        if network:
            print("\n[NETWORK INFORMATION]")
            for key, val in network.items():
                if isinstance(val, dict):
                    print(f"  {key.upper().replace('_', ' '):<25}:")
                    for k, v in val.items():
                        if v and v != 'None':
                            print(f"    {k.upper().replace('_', ' '):<23}: {v}")
                elif val and val != 'None':
                    print(f"  {key.upper().replace('_', ' '):<25}: {val}")
        
        # Угрозы
        threat = self.ip_data.get('threat', {})
        if threat:
            print("\n[THREAT INTELLIGENCE]")
            for key, val in threat.items():
                if val and val != 'None':
                    print(f"  {key.upper().replace('_', ' '):<25}: {val}")
        
        # Порты
        ports = self.ip_data.get('ports', [])
        if ports:
            print("\n[PORT SCAN RESULTS]")
            print("  " + ", ".join(map(str, ports)))
        else:
            print("\n[PORT SCAN RESULTS]")
            print("  No open ports found")
        
        print("\n" + "="*90)
        print("GitHub: https://github.com/MrRobotDefuse")

if __name__ == '__main__':
    try:
        hunter = UltraPreciseIPHunter()
        hunter.run()
    except KeyboardInterrupt:
        print("\n[!] Investigation stopped")
        sys.exit(0)
