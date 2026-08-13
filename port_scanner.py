# -*- coding: utf-8 -*-
import socket
import threading
import time
import random
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Optional, List, Dict
import json
import os

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
    max_retries: int = 2
    random_order: bool = True

class PortScanner:
    
    def __init__(self, config: ScanConfig, signatures: dict):
        self.config = config
        self.signatures = signatures
        self.results: List[PortResult] = []
        self.lock = threading.Lock()
        
        try:
            self.target_ip = socket.gethostbyname(config.target)
        except socket.gaierror:
            raise ValueError(f"Не удалось разрешить имя: {config.target}")
        
        if not config.ports:
            self.config.ports = list(range(1, 1025))
        
        if config.random_order:
            random.shuffle(self.config.ports)
    
    def _identify_service(self, port: int, protocol: str, banner: str) -> dict:
        port_str = str(port)
        sig_info = self.signatures.get(protocol, {}).get(port_str, {})
        
        result = {
            'service': sig_info.get('service', 'unknown'),
            'version': ''
        }
        
        import re
        
        for regex in sig_info.get('banner_regex', []):
            match = re.search(regex, banner, re.IGNORECASE)
            if match:
                result['version'] = match.group(0)[:100]
                break
        
        version_patterns = {
            'OpenSSH': r'SSH-\d+\.\d+-OpenSSH[_ ](\d+\.\d+)',
            'Apache': r'Apache/(\d+\.\d+\.\d+)',
            'nginx': r'nginx/(\d+\.\d+\.\d+)',
            'MySQL': r'(\d+\.\d+\.\d+).*MySQL',
            'MariaDB': r'(\d+\.\d+\.\d+).*MariaDB',
            'PostgreSQL': r'PostgreSQL (\d+\.\d+)',
            'Redis': r'redis_version:(\d+\.\d+\.\d+)',
            'vsftpd': r'vsftpd (\d+\.\d+\.\d+)',
            'ProFTPD': r'ProFTPD (\d+\.\d+\.\d+)',
            'FileZilla': r'FileZilla Server (\d+\.\d+\.\d+)',
            'VNC': r'RFB (\d{3}\.\d{3})',
            'PHP': r'PHP/(\d+\.\d+\.\d+)',
            'IIS': r'Microsoft-IIS/(\d+\.\d+)',
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
                        sig_info = self.signatures.get('tcp', {}).get(port_str, {})
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
                                if len(data) > 4096:
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
                            if port_str in self.signatures.get('tcp', {}):
                                result.service = self.signatures['tcp'][port_str].get('service', 'unknown')
                    except:
                        pass
            else:
                result.state = 'closed'
                result.response_time = time.time() - start_time
                
        except socket.timeout:
            result.state = 'filtered'
        except ConnectionRefusedError:
            result.state = 'closed'
        except Exception:
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
        
        sock = None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(self.config.timeout)
            
            probe_data = b'\x00' * 8
            port_str = str(port)
            sig_info = self.signatures.get('udp', {}).get(port_str, {})
            probe_hex = sig_info.get('probe_data', '')
            if probe_hex:
                try:
                    probe_data = bytes.fromhex(probe_hex)
                except:
                    pass
            
            sock.sendto(probe_data, (self.target_ip, port))
            
            try:
                data, _ = sock.recvfrom(1024)
                result.state = 'open'
                try:
                    result.banner = data.decode('utf-8', errors='ignore')[:200]
                except:
                    result.banner = data.hex()[:200]
            except socket.timeout:
                result.state = 'open|filtered'
            except:
                result.state = 'closed'
                
        except Exception:
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
        
        for result in results:
            if result.state != 'open':
                continue
            
            banner_lower = result.banner.lower()
            
            if 'ubuntu' in banner_lower:
                os_score['Ubuntu Linux'] += 30
            elif 'debian' in banner_lower:
                os_score['Debian Linux'] += 30
            elif 'centos' in banner_lower:
                os_score['CentOS Linux'] += 30
            elif 'windows' in banner_lower or 'microsoft' in banner_lower:
                os_score['Microsoft Windows'] += 30
            elif 'freebsd' in banner_lower:
                os_score['FreeBSD'] += 30
            
            if 'openssh' in banner_lower:
                if 'ubuntu' in banner_lower:
                    os_score['Ubuntu Linux'] += 10
                elif 'debian' in banner_lower:
                    os_score['Debian Linux'] += 10
                else:
                    os_score['Linux Generic'] += 5
            
            if 'iis' in banner_lower:
                os_score['Microsoft Windows'] += 20
        
        if os_score:
            return max(os_score.items(), key=lambda x: x[1])[0]
        return 'Unknown'
    
    def scan(self):
        print(f"[*] Цель: {self.config.target} ({self.target_ip})")
        print(f"[*] Портов для сканирования: {len(self.config.ports)}")
        print(f"[*] Потоков: {self.config.threads}")
        print(f"[*] Таймаут: {self.config.timeout}с")
        print(f"[*] Сбор баннеров: {'Да' if self.config.banner_grab else 'Нет'}")
        print(f"[*] Определение ОС: {'Да' if self.config.os_detect else 'Нет'}")
        print("-" * 60)
        
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
        
        with ThreadPoolExecutor(max_workers=self.config.threads) as executor:
            future_to_port = {}
            
            for protocol, port in tasks:
                if protocol == 'tcp':
                    future = executor.submit(self._tcp_scan_port, port)
                else:
                    future = executor.submit(self._udp_scan_port, port)
                future_to_port[future] = (protocol, port)
            
            for future in as_completed(future_to_port):
                protocol, port = future_to_port[future]
                completed += 1
                
                try:
                    result = future.result()
                    if result.state == 'open':
                        results.append(result)
                        self._print_result(result)
                except Exception:
                    pass
                
                if completed % 100 == 0 or completed == total:
                    print(f"\r[*] Прогресс: {completed}/{total} "
                          f"({100*completed//total}%)", end='')
        
        print()
        
        if self.config.os_detect and results:
            os_guess = self._detect_os(results)
            if os_guess != 'Unknown':
                print(f"\n[+] Предполагаемая ОС: {os_guess}")
        
        self.results = results
        return results
    
    def _print_result(self, result: PortResult):
        with self.lock:
            output = f"\n[●] {result.port}/{result.protocol}"
            
            if result.service != 'unknown':
                output += f" ({result.service})"
            
            if result.version:
                output += f" - {result.version}"
            
            if result.banner:
                banner_short = result.banner.replace('\n', ' ').replace('\r', '')[:80]
                output += f"\n    └─ {banner_short}"
            
            print(output)


if __name__ == '__main__':
    # Загрузка сигнатур
    script_dir = os.path.dirname(os.path.abspath(__file__))
    signatures_path = os.path.join(script_dir, 'signatures.json')
    
    with open(signatures_path, 'r', encoding='utf-8') as f:
        signatures = json.load(f)
    
    # Конфигурация
    config = ScanConfig(
        target='scanme.nmap.org',
        ports=[21, 22, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995, 1433, 1521, 2082, 2083, 2086, 2087, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 8888, 9090, 9200, 11211, 27017],
        tcp_scan=True,
        banner_grab=True,
        os_detect=True,
        threads=300,
        timeout=2.0
    )
    
    # Запуск
    scanner = PortScanner(config, signatures)
    results = scanner.scan()
    
    # Итоги
    print("\n" + "=" * 60)
    print(f"[+] Сканирование завершено")
    print(f"[+] Открытых портов: {len([r for r in results if 'open' in r.state])}")
    
    services = defaultdict(list)
    for r in results:
        services[r.service].append(r.port)
    
    print("\n[+] Обнаруженные сервисы:")
    for service, ports in sorted(services.items()):
        if len(ports) <= 20:
            ports_str = ', '.join(map(str, sorted(ports)))
        else:
            ports_str = f"{len(ports)} портов"
        print(f"    {service}: {ports_str}")
    
    print("\nДля продолжения нажмите любую клавишу . . .")
    input()