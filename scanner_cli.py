# -*- coding: utf-8 -*-
import socket
import threading
import time
import random
import json
import os
import sys
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Optional, List, Dict
from datetime import datetime

# ============================================================
# ЦВЕТА ДЛЯ КРАСИВОГО ВЫВОДА
# ============================================================
class Colors:
    RESET = '\033[0m'
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'

def print_banner():
    print(f"""{Colors.CYAN}
    ╔══════════════════════════════════════════════╗
    ║         PORT SCANNER v2.0                    ║
    ║         TCP/UDP Scanner with Banner Grab     ║
    ╚══════════════════════════════════════════════╝
    {Colors.RESET}""")

# ============================================================
# СТРУКТУРЫ ДАННЫХ
# ============================================================
@dataclass
class PortResult:
    port: int
    protocol: str
    state: str
    service: str = 'unknown'
    banner: str = ''
    version: str = ''
    response_time: float = 0.0

@dataclass
class ScanConfig:
    target: str
    ports: List[int] = field(default_factory=list)
    tcp_scan: bool = True
    udp_scan: bool = False
    banner_grab: bool = True
    os_detect: bool = True
    threads: int = 200
    timeout: float = 1.5

# ============================================================
# ПРЕДУСТАНОВЛЕННЫЕ НАБОРЫ ПОРТОВ
# ============================================================
PORT_SETS = {
    'quick': [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995, 1433, 1521, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 27017],
    'web': [80, 443, 8080, 8443, 3000, 5000, 8000, 8888, 9090],
    'database': [1433, 1521, 3306, 5432, 6379, 9200, 11211, 27017, 27018],
    'mail': [25, 110, 143, 465, 587, 993, 995, 2525],
    'windows': [135, 139, 445, 3389, 5985, 5986],
    'linux': [22, 111, 2049, 3306, 5432, 6379, 8080],
    'all_well_known': list(range(1, 1025)),
    'top100': [
        7, 9, 13, 21, 22, 23, 25, 26, 37, 53, 79, 80, 81, 82, 83, 84, 85, 88, 89, 90,
        99, 106, 109, 110, 111, 113, 119, 135, 139, 143, 144, 179, 199, 389, 427, 443,
        444, 445, 465, 513, 514, 515, 543, 544, 548, 554, 587, 631, 646, 873, 990, 993,
        995, 1025, 1026, 1027, 1028, 1029, 1110, 1433, 1521, 1720, 1723, 1755, 1900,
        2000, 2001, 2049, 2121, 2717, 3000, 3128, 3306, 3389, 3986, 4899, 5000, 5009,
        5051, 5060, 5101, 5190, 5357, 5432, 5631, 5666, 5800, 5900, 6000, 6001, 6379,
        6646, 7070, 8000, 8008, 8080, 8081, 8443, 8888, 9100, 9200, 9999, 10000, 27017,
        32768, 49152, 49153, 49154, 49155, 49156, 49157
    ]
}

# ============================================================
# БАЗА СИГНАТУР СЕРВИСОВ (встроенная, чтобы не нужен был файл)
# ============================================================
SERVICE_SIGNATURES = {
    'tcp': {
        '21': {'service': 'FTP', 'banner_regex': ['220[ -].*FTP', '220[ -].*FileZilla', '220[ -].*vsftpd', '220[ -].*ProFTPD']},
        '22': {'service': 'SSH', 'banner_regex': ['SSH-2\\.0-OpenSSH', 'SSH-2\\.0-dropbear', 'SSH-2\\.0-Go', 'SSH-2\\.0-libssh']},
        '25': {'service': 'SMTP', 'banner_regex': ['220[ -].*ESMTP', '220[ -].*Sendmail', '220[ -].*Postfix', '220[ -].*Exim']},
        '53': {'service': 'DNS', 'banner_regex': []},
        '80': {'service': 'HTTP', 'banner_regex': [], 'probe': 'GET / HTTP/1.0\r\nHost: {target}\r\nUser-Agent: Mozilla/5.0\r\n\r\n'},
        '110': {'service': 'POP3', 'banner_regex': ['\\+OK.*POP3', '\\+OK.*Dovecot']},
        '135': {'service': 'RPC', 'banner_regex': []},
        '139': {'service': 'NetBIOS', 'banner_regex': []},
        '143': {'service': 'IMAP', 'banner_regex': ['\\* OK.*IMAP', '\\* OK.*Dovecot']},
        '443': {'service': 'HTTPS', 'banner_regex': [], 'probe': 'GET / HTTP/1.0\r\nHost: {target}\r\n\r\n'},
        '445': {'service': 'SMB', 'banner_regex': []},
        '993': {'service': 'IMAPS', 'banner_regex': []},
        '995': {'service': 'POP3S', 'banner_regex': []},
        '1433': {'service': 'MSSQL', 'banner_regex': []},
        '1521': {'service': 'OracleDB', 'banner_regex': []},
        '3306': {'service': 'MySQL', 'banner_regex': ['.*mysql_native_password', '.*caching_sha2_password', '.*MariaDB']},
        '3389': {'service': 'RDP', 'banner_regex': []},
        '5432': {'service': 'PostgreSQL', 'banner_regex': []},
        '5900': {'service': 'VNC', 'banner_regex': ['RFB [0-9]{3}\\.[0-9]{3}']},
        '6379': {'service': 'Redis', 'banner_regex': [], 'probe': 'PING\r\n'},
        '8080': {'service': 'HTTP-Alt', 'banner_regex': [], 'probe': 'GET / HTTP/1.0\r\nHost: {target}\r\n\r\n'},
        '8443': {'service': 'HTTPS-Alt', 'banner_regex': []},
        '9090': {'service': 'HTTP-Alt2', 'banner_regex': [], 'probe': 'GET / HTTP/1.0\r\nHost: {target}\r\n\r\n'},
        '9200': {'service': 'Elasticsearch', 'banner_regex': [], 'probe': 'GET / HTTP/1.0\r\n\r\n'},
        '11211': {'service': 'Memcached', 'banner_regex': [], 'probe': 'stats\r\n'},
        '27017': {'service': 'MongoDB', 'banner_regex': []},
    },
    'udp': {
        '53': {'service': 'DNS', 'probe_data': '000001000000000000000000076578616d706c6503636f6d0000010001'},
        '67': {'service': 'DHCP'},
        '123': {'service': 'NTP'},
        '161': {'service': 'SNMP', 'probe_data': '302902010004067075626c6963a01c0204511b2302020100020100300e300c06082b060102010101000500'},
        '500': {'service': 'IKE'},
        '1900': {'service': 'UPnP'},
        '5353': {'service': 'mDNS'},
    }
}

# ============================================================
# СКАНЕР ПОРТОВ
# ============================================================
class PortScanner:
    
    def __init__(self, config: ScanConfig):
        self.config = config
        self.results: List[PortResult] = []
        self.lock = threading.Lock()
        self.start_time = None
        self.scanning = True
        
        try:
            self.target_ip = socket.gethostbyname(config.target)
        except socket.gaierror:
            raise ValueError(f"Не удалось разрешить имя: {config.target}")
    
    def _identify_service(self, port: int, protocol: str, banner: str) -> dict:
        port_str = str(port)
        sig_info = SERVICE_SIGNATURES.get(protocol, {}).get(port_str, {})
        
        result = {'service': sig_info.get('service', 'unknown'), 'version': ''}
        
        import re
        
        for regex in sig_info.get('banner_regex', []):
            match = re.search(regex, banner, re.IGNORECASE)
            if match:
                result['version'] = match.group(0)[:80]
                break
        
        version_patterns = {
            'OpenSSH': r'SSH-\d+\.\d+-OpenSSH[_ ](\d+\.\d+[^\s]*)',
            'Apache': r'Apache/(\d+\.\d+\.\d+)',
            'nginx': r'nginx/(\d+\.\d+\.\d+)',
            'MySQL': r'(\d+\.\d+\.\d+).*MySQL',
            'MariaDB': r'(\d+\.\d+\.\d+).*MariaDB',
            'vsftpd': r'vsftpd (\d+\.\d+\.\d+)',
            'ProFTPD': r'ProFTPD (\d+\.\d+\.\d+)',
            'FileZilla': r'FileZilla Server (\d+\.\d+\.\d+)',
            'PHP': r'PHP/(\d+\.\d+\.\d+)',
            'Django': r'Django/(\d+\.\d+\.\d+)',
            'WordPress': r'WordPress/(\d+\.\d+\.\d+)',
        }
        
        for service_name, pattern in version_patterns.items():
            match = re.search(pattern, banner, re.IGNORECASE)
            if match:
                if not result['version']:
                    result['version'] = f"{service_name}/{match.group(1)}"
                if result['service'] == 'unknown':
                    result['service'] = service_name
                break
        
        return result
    
    def _tcp_scan_port(self, port: int) -> PortResult:
        start_time = time.time()
        result = PortResult(port=port, protocol='tcp', state='closed')
        
        if not self.scanning:
            return result
        
        sock = None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.config.timeout)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            
            connect_result = sock.connect_ex((self.target_ip, port))
            
            if connect_result == 0:
                result.state = 'open'
                result.response_time = time.time() - start_time
                
                if self.config.banner_grab:
                    try:
                        sock.settimeout(min(2.0, self.config.timeout * 1.5))
                        port_str = str(port)
                        sig_info = SERVICE_SIGNATURES.get('tcp', {}).get(port_str, {})
                        probe = sig_info.get('probe')
                        
                        if probe:
                            probe_data = probe.format(target=self.target_ip)
                            sock.send(probe_data.encode('utf-8', errors='ignore'))
                        
                        data = b''
                        try:
                            while True:
                                chunk = sock.recv(4096)
                                if not chunk:
                                    break
                                data += chunk
                                if len(data) > 8192:
                                    break
                        except socket.timeout:
                            pass
                        except:
                            pass
                        
                        if data:
                            try:
                                banner = data.decode('utf-8', errors='ignore').strip()
                            except:
                                try:
                                    banner = data.decode('latin-1', errors='ignore').strip()
                                except:
                                    banner = repr(data)
                            
                            result.banner = banner[:300]
                            service_info = self._identify_service(port, 'tcp', banner)
                            result.service = service_info.get('service', 'unknown')
                            result.version = service_info.get('version', '')
                        else:
                            if port_str in SERVICE_SIGNATURES.get('tcp', {}):
                                result.service = SERVICE_SIGNATURES['tcp'][port_str].get('service', 'unknown')
                    except:
                        pass
                
        except socket.timeout:
            result.state = 'filtered'
        except ConnectionRefusedError:
            result.state = 'closed'
        except:
            result.state = 'closed'
        finally:
            if sock:
                try:
                    sock.close()
                except:
                    pass
        
        return result
    
    def _udp_scan_port(self, port: int) -> PortResult:
        result = PortResult(port=port, protocol='udp', state='closed')
        
        if not self.scanning:
            return result
        
        sock = None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(self.config.timeout)
            
            probe_data = b'\x00' * 8
            port_str = str(port)
            sig_info = SERVICE_SIGNATURES.get('udp', {}).get(port_str, {})
            probe_hex = sig_info.get('probe_data', '')
            if probe_hex:
                try:
                    probe_data = bytes.fromhex(probe_hex)
                except:
                    pass
            
            sock.sendto(probe_data, (self.target_ip, port))
            
            try:
                data, _ = sock.recvfrom(4096)
                result.state = 'open'
                try:
                    result.banner = data.decode('utf-8', errors='ignore')[:200]
                except:
                    result.banner = data.hex()[:200]
                result.service = sig_info.get('service', 'unknown')
            except socket.timeout:
                result.state = 'open|filtered'
            except:
                result.state = 'closed'
                
        except:
            result.state = 'closed'
        finally:
            if sock:
                try:
                    sock.close()
                except:
                    pass
        
        return result
    
    def _detect_os(self, results: List[PortResult]) -> str:
        os_score = defaultdict(int)
        os_details = []
        
        for result in results:
            if result.state != 'open':
                continue
            
            banner_lower = result.banner.lower()
            
            if 'ubuntu' in banner_lower:
                os_score['Ubuntu Linux'] += 30
                os_details.append(f"Ubuntu (found in {result.service} banner)")
            elif 'debian' in banner_lower:
                os_score['Debian Linux'] += 30
            elif 'centos' in banner_lower:
                os_score['CentOS Linux'] += 30
            elif 'red hat' in banner_lower or 'rhel' in banner_lower:
                os_score['Red Hat Enterprise Linux'] += 30
            elif 'windows' in banner_lower or 'microsoft' in banner_lower:
                os_score['Microsoft Windows'] += 30
            elif 'freebsd' in banner_lower:
                os_score['FreeBSD'] += 30
            
            if 'openssh' in banner_lower:
                if 'ubuntu' in banner_lower:
                    os_score['Ubuntu Linux'] += 10
                elif 'debian' in banner_lower:
                    os_score['Debian Linux'] += 10
                elif 'centos' in banner_lower:
                    os_score['CentOS Linux'] += 10
                else:
                    os_score['Linux Generic'] += 5
            
            if 'iis' in banner_lower or 'microsoft-iis' in banner_lower:
                os_score['Microsoft Windows'] += 25
            
            if 'apache' in banner_lower and 'ubuntu' in banner_lower:
                os_score['Ubuntu Linux'] += 15
        
        if os_score:
            best = max(os_score.items(), key=lambda x: x[1])
            if best[1] >= 15:
                return f"{best[0]} (confidence: {best[1]}%)"
        
        return 'Unknown'
    
    def scan(self):
        self.start_time = time.time()
        self.scanning = True
        
        print(f"\n{Colors.BOLD}┌─── Информация о цели ───{Colors.RESET}")
        print(f"│ Цель        : {Colors.GREEN}{self.config.target}{Colors.RESET} ({self.target_ip})")
        print(f"│ Портов      : {len(self.config.ports)}")
        print(f"│ TCP         : {'Да' if self.config.tcp_scan else 'Нет'}")
        print(f"│ UDP         : {'Да' if self.config.udp_scan else 'Нет'}")
        print(f"│ Баннеры     : {'Да' if self.config.banner_grab else 'Нет'}")
        print(f"│ Потоков     : {self.config.threads}")
        print(f"│ Таймаут     : {self.config.timeout}с")
        print(f"{'─' * 50}")
        
        tasks = []
        
        if self.config.tcp_scan:
            for port in self.config.ports:
                tasks.append(('tcp', port))
        
        if self.config.udp_scan:
            for port in self.config.ports:
                tasks.append(('udp', port))
        
        results = []
        completed = 0
        total = len(tasks)
        
        open_count = 0
        
        with ThreadPoolExecutor(max_workers=self.config.threads) as executor:
            future_to_port = {}
            
            for protocol, port in tasks:
                if protocol == 'tcp':
                    future = executor.submit(self._tcp_scan_port, port)
                else:
                    future = executor.submit(self._udp_scan_port, port)
                future_to_port[future] = (protocol, port)
            
            for future in as_completed(future_to_port):
                if not self.scanning:
                    break
                
                protocol, port = future_to_port[future]
                completed += 1
                
                try:
                    result = future.result()
                    if result.state == 'open':
                        results.append(result)
                        open_count += 1
                        self._print_result(result)
                except:
                    pass
                
                # Прогресс
                if completed % 50 == 0 or completed == total:
                    elapsed = time.time() - self.start_time
                    percent = 100 * completed // total
                    bar_len = 20
                    filled = bar_len * completed // total
                    bar = '█' * filled + '░' * (bar_len - filled)
                    print(f"\r{Colors.CYAN}[{bar}] {percent}% | {completed}/{total} | Открыто: {open_count} | {elapsed:.1f}с{Colors.RESET}", end='')
        
        print()
        
        # Определение ОС
        if self.config.os_detect and results:
            os_guess = self._detect_os(results)
            if 'Unknown' not in os_guess:
                print(f"\n{Colors.MAGENTA}[+] Предполагаемая ОС: {os_guess}{Colors.RESET}")
        
        elapsed = time.time() - self.start_time
        self.results = results
        
        return results, elapsed
    
    def _print_result(self, result: PortResult):
        with self.lock:
            service_color = Colors.GREEN if result.service != 'unknown' else Colors.YELLOW
            
            print(f"\n  {Colors.GREEN}●{Colors.RESET} {Colors.BOLD}{result.port}{Colors.RESET}/{result.protocol}", end='')
            
            if result.service != 'unknown':
                print(f" {Colors.RESET}─{Colors.RESET} {service_color}{result.service}{Colors.RESET}", end='')
            
            if result.version:
                print(f" {Colors.WHITE}({result.version}){Colors.RESET}", end='')
            
            if result.response_time > 0:
                print(f" {Colors.CYAN}[{result.response_time:.3f}с]{Colors.RESET}", end='')
            
            if result.banner:
                banner_short = result.banner.replace('\n', ' ').replace('\r', '')[:100]
                print(f"\n    └─ {Colors.BLUE}{banner_short}{Colors.RESET}", end='')
    
    def stop(self):
        self.scanning = False

# ============================================================
# ФУНКЦИИ ДЛЯ РАБОТЫ С РЕЗУЛЬТАТАМИ
# ============================================================
def save_results(results, target, elapsed, filename=None):
    if not filename:
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"scan_{target.replace('.', '_')}_{timestamp}"
    
    # Сохраняем в TXT
    txt_file = f"{filename}.txt"
    with open(txt_file, 'w', encoding='utf-8') as f:
        f.write("=" * 60 + "\n")
        f.write(f"Отчет о сканировании портов\n")
        f.write(f"Цель: {target}\n")
        f.write(f"Время: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"Длительность: {elapsed:.1f}с\n")
        f.write("=" * 60 + "\n\n")
        
        # Группируем по сервисам
        by_service = defaultdict(list)
        for r in results:
            by_service[r.service].append(r)
        
        for service, ports in sorted(by_service.items()):
            f.write(f"\n{'─' * 40}\n")
            f.write(f"Сервис: {service}\n")
            f.write(f"{'─' * 40}\n")
            for r in ports:
                f.write(f"Порт: {r.port}/{r.protocol}\n")
                if r.version:
                    f.write(f"Версия: {r.version}\n")
                if r.banner:
                    f.write(f"Баннер: {r.banner[:200]}\n")
                f.write(f"Время отклика: {r.response_time:.3f}с\n")
                f.write("\n")
    
    # Сохраняем в JSON
    json_file = f"{filename}.json"
    with open(json_file, 'w', encoding='utf-8') as f:
        json.dump([{
            'port': r.port,
            'protocol': r.protocol,
            'state': r.state,
            'service': r.service,
            'version': r.version,
            'banner': r.banner,
            'response_time': r.response_time
        } for r in results], f, indent=2, ensure_ascii=False)
    
    return txt_file, json_file

def show_menu():
    print(f"\n{Colors.BOLD}Выберите действие:{Colors.RESET}")
    print(f"  {Colors.GREEN}1{Colors.RESET}. Сканировать конкретный хост")
    print(f"  {Colors.GREEN}2{Colors.RESET}. Быстрое сканирование (топ-25 портов)")
    print(f"  {Colors.GREEN}3{Colors.RESET}. Полное сканирование (1-1024)")
    print(f"  {Colors.GREEN}4{Colors.RESET}. Сканирование веб-портов")
    print(f"  {Colors.GREEN}5{Colors.RESET}. Сканирование портов баз данных")
    print(f"  {Colors.GREEN}6{Colors.RESET}. Сканирование Windows портов")
    print(f"  {Colors.GREEN}7{Colors.RESET}. Свои порты (ввести вручную)")
    print(f"  {Colors.GREEN}8{Colors.RESET}. TCP + UDP сканирование")
    print(f"  {Colors.GREEN}0{Colors.RESET}. Выход")

def get_target():
    print(f"\n{Colors.BOLD}Введите цель для сканирования:{Colors.RESET}")
    print(f"  Примеры: 192.168.1.1, example.com, scanme.nmap.org")
    target = input(f"  {Colors.CYAN}→{Colors.RESET} ").strip()
    if not target:
        print(f"{Colors.RED}[!] Цель не введена{Colors.RESET}")
        return None
    return target

def get_custom_ports():
    print(f"\n{Colors.BOLD}Введите порты через запятую или диапазон:{Colors.RESET}")
    print(f"  Примеры: 80,443,8080  или  1-1024  или  22,80-100,443")
    ports_str = input(f"  {Colors.CYAN}→{Colors.RESET} ").strip()
    
    ports = []
    try:
        for part in ports_str.split(','):
            part = part.strip()
            if '-' in part:
                start, end = part.split('-')
                ports.extend(range(int(start), int(end) + 1))
            else:
                ports.append(int(part))
        return sorted(set(ports))
    except:
        print(f"{Colors.RED}[!] Неверный формат портов{Colors.RESET}")
        return None

def confirm_scan(target, ports_count):
    print(f"\n{Colors.YELLOW}╔═══ Подтверждение сканирования ═══╗{Colors.RESET}")
    print(f"{Colors.YELLOW}║ Цель: {target}{Colors.RESET}")
    print(f"{Colors.YELLOW}║ Портов: {ports_count}{Colors.RESET}")
    print(f"{Colors.YELLOW}╚══════════════════════════════════╝{Colors.RESET}")
    confirm = input(f"  Начать сканирование? (y/n): ").strip().lower()
    return confirm == 'y' or confirm == 'yes' or confirm == 'д' or confirm == 'да'

# ============================================================
# ГЛАВНАЯ ПРОГРАММА
# ============================================================
def main():
    os.system('cls' if os.name == 'nt' else 'clear')
    print_banner()
    
    while True:
        show_menu()
        choice = input(f"\n  {Colors.CYAN}Ваш выбор →{Colors.RESET} ").strip()
        
        if choice == '0':
            print(f"\n{Colors.YELLOW}[*] Выход...{Colors.RESET}")
            break
        
        target = get_target()
        if not target:
            continue
        
        ports = None
        tcp = True
        udp = False
        banner = True
        threads = 200
        timeout = 1.5
        
        if choice == '1':
            ports = PORT_SETS['quick']
        elif choice == '2':
            ports = PORT_SETS['top100']
        elif choice == '3':
            ports = PORT_SETS['all_well_known']
            threads = 300
            timeout = 1.0
        elif choice == '4':
            ports = PORT_SETS['web']
        elif choice == '5':
            ports = PORT_SETS['database']
        elif choice == '6':
            ports = PORT_SETS['windows']
        elif choice == '7':
            ports = get_custom_ports()
            if not ports:
                continue
        elif choice == '8':
            ports = PORT_SETS['quick']
            udp = True
            timeout = 2.0
        else:
            print(f"{Colors.RED}[!] Неверный выбор{Colors.RESET}")
            continue
        
        if not confirm_scan(target, len(ports)):
            print(f"{Colors.YELLOW}[*] Сканирование отменено{Colors.RESET}")
            continue
        
        # Создаем конфиг и сканируем
        config = ScanConfig(
            target=target,
            ports=ports,
            tcp_scan=tcp,
            udp_scan=udp,
            banner_grab=banner,
            os_detect=True,
            threads=threads,
            timeout=timeout
        )
        
        try:
            scanner = PortScanner(config)
            print(f"\n{Colors.BOLD}{Colors.GREEN}[*] Сканирование запущено...{Colors.RESET}")
            results, elapsed = scanner.scan()
            
            # Итоги
            print(f"\n{Colors.BOLD}{'═' * 50}{Colors.RESET}")
            print(f"{Colors.GREEN}[+] Сканирование завершено!{Colors.RESET}")
            print(f"[+] Найдено открытых портов: {Colors.GREEN}{len(results)}{Colors.RESET}")
            print(f"[+] Время сканирования: {elapsed:.1f} секунд")
            
            if results:
                # Группируем по сервисам
                by_service = defaultdict(list)
                for r in results:
                    by_service[r.service].append(r.port)
                
                print(f"\n{Colors.BOLD}Обнаруженные сервисы:{Colors.RESET}")
                for service, ports_list in sorted(by_service.items()):
                    ports_str = ', '.join(map(str, sorted(ports_list)))
                    print(f"  {Colors.GREEN}{service}{Colors.RESET}: {ports_str}")
                
                # Предложить сохранить
                save = input(f"\n{Colors.CYAN}Сохранить результаты? (y/n): {Colors.RESET}").strip().lower()
                if save in ['y', 'yes', 'д', 'да']:
                    txt_file, json_file = save_results(results, target, elapsed)
                    print(f"{Colors.GREEN}[+] Сохранено:{Colors.RESET}")
                    print(f"    TXT: {txt_file}")
                    print(f"    JSON: {json_file}")
            
        except KeyboardInterrupt:
            print(f"\n{Colors.YELLOW}[!] Сканирование прервано пользователем{Colors.RESET}")
            if scanner:
                scanner.stop()
        except Exception as e:
            print(f"\n{Colors.RED}[!] Ошибка: {e}{Colors.RESET}")
        
        input(f"\n{Colors.CYAN}Нажмите Enter чтобы продолжить...{Colors.RESET}")
        os.system('cls' if os.name == 'nt' else 'clear')
        print_banner()

if __name__ == '__main__':
    main()
