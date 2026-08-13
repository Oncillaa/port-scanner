# -*- coding: utf-8 -*-
import socket
import ssl
import struct
import re
from typing import Optional, Dict, Tuple

class BannerGrabber:
    """Продвинутый сбор баннеров с определением версий"""
    
    # Пробы для сервисов которые требуют специального запроса
    PROBES = {
        'HTTP': {
            'ports': [80, 8080, 8000, 8888, 9090],
            'probe': b'GET / HTTP/1.0\r\nHost: {target}\r\nUser-Agent: Mozilla/5.0\r\nAccept: */*\r\n\r\n',
            'regex': [
                (r'Server: (.+)', 'HTTP Server'),
                (r'X-Powered-By: (.+)', 'Platform'),
                (r'Set-Cookie: (.+)', 'Cookie'),
            ]
        },
        'HTTPS': {
            'ports': [443, 8443, 9443],
            'probe': b'GET / HTTP/1.0\r\nHost: {target}\r\n\r\n',
            'ssl': True
        },
        'SMTP': {
            'ports': [25, 587, 2525],
            'probe': b'EHLO scanner.local\r\n',
            'regex': [
                (r'250[ -]([^\r\n]+)', 'SMTP Banner'),
            ]
        },
        'FTP': {
            'ports': [21, 2121],
            'probe': None,  # Ответ приходит сразу после подключения
            'regex': [
                (r'220[ -]([^\r\n]+)', 'FTP Banner'),
            ]
        },
        'SSH': {
            'ports': [22, 2222],
            'probe': None,  # Баннер приходит при подключении
            'regex': [
                (r'SSH-\d+\.\d+-([^\r\n]+)', 'SSH Version'),
            ]
        },
        'MySQL': {
            'ports': [3306],
            'probe': None,
            'parse': 'mysql'
        },
        'PostgreSQL': {
            'ports': [5432],
            'probe': b'\x00\x00\x00\x08\x04\xd2\x16\x2f',
            'parse': 'postgresql'
        },
        'Redis': {
            'ports': [6379],
            'probe': b'PING\r\nINFO\r\n',
            'parse': 'redis'
        },
        'MongoDB': {
            'ports': [27017, 27018],
            'probe': b'\x3a\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xd4\x07\x00\x00\x00\x00\x00\x00admin.$cmd\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff\xff\xff\x13\x00\x00\x00\x10isMaster\x00\x01\x00\x00\x00\x00',
            'parse': 'mongodb'
        },
        'RDP': {
            'ports': [3389],
            'probe': None,
            'parse': 'rdp'
        },
        'SMB': {
            'ports': [445, 139],
            'probe': None,
            'parse': 'smb'
        },
        'DNS': {
            'ports': [53],
            'probe': b'\x00\x00\x10\x00\x00\x00\x00\x00\x00\x00\x00\x00',
            'parse': 'dns'
        },
        'VNC': {
            'ports': [5900, 5901],
            'probe': None,
            'parse': 'vnc'
        },
    }
    
    def __init__(self, target: str, timeout: float = 3.0):
        self.target = target
        self.timeout = timeout
    
    def grab_banner(self, port: int, protocol: str = 'tcp') -> Dict[str, str]:
        """Захватывает баннер с определением сервиса"""
        result = {
            'service': 'unknown',
            'banner': '',
            'version': '',
            'details': {}
        }
        
        if protocol != 'tcp':
            return result
        
        # Определяем тип сервиса по порту
        probe_info = self._get_probe_for_port(port)
        if not probe_info:
            return result
        
        sock = None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            
            # SSL если нужно
            if probe_info.get('ssl'):
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                sock = context.wrap_socket(sock, server_hostname=self.target)
            
            sock.connect((self.target, port))
            
            # Получаем начальный баннер
            initial_data = b''
            
            if probe_info.get('probe'):
                # Отправляем пробу
                probe = probe_info['probe']
                if b'{target}' in probe:
                    probe = probe.replace(b'{target}', self.target.encode())
                sock.send(probe)
            
            # Читаем ответ
            try:
                while True:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    initial_data += chunk
                    if len(initial_data) > 65536:
                        break
            except socket.timeout:
                pass
            
            if initial_data:
                # Парсим ответ
                parsed = self._parse_response(
                    probe_info.get('name', 'unknown'),
                    initial_data
                )
                result.update(parsed)
            
            sock.close()
            
        except Exception as e:
            pass
        finally:
            if sock:
                try:
                    sock.close()
                except:
                    pass
        
        return result
    
    def _get_probe_for_port(self, port: int) -> Optional[Dict]:
        """Находит подходящую пробу для порта"""
        for name, info in self.PROBES.items():
            if port in info['ports']:
                result = info.copy()
                result['name'] = name
                return result
        return None
    
    def _parse_response(self, service_type: str, data: bytes) -> Dict:
        """Разбирает ответ сервиса"""
        result = {'service': service_type, 'banner': '', 'version': ''}
        
        try:
            banner = data.decode('utf-8', errors='ignore')
        except:
            try:
                banner = data.decode('latin-1', errors='ignore')
            except:
                banner = repr(data)
        
        result['banner'] = banner.strip()[:500]
        
        # Специфичные парсеры
        parser_method = getattr(self, f'_parse_{service_type.lower()}', None)
        if parser_method:
            parsed = parser_method(data)
            result.update(parsed)
        
        return result
    
    def _parse_http(self, data: bytes) -> Dict:
        """Парсит HTTP ответ"""
        result = {}
        try:
            text = data.decode('utf-8', errors='ignore')
            
            # Server header
            match = re.search(r'^Server: (.+)$', text, re.MULTILINE | re.IGNORECASE)
            if match:
                result['version'] = match.group(1).strip()
            
            # X-Powered-By
            match = re.search(r'^X-Powered-By: (.+)$', text, re.MULTILINE | re.IGNORECASE)
            if match:
                result['details']['platform'] = match.group(1).strip()
            
            # Set-Cookie
            cookies = re.findall(r'^Set-Cookie: (.+)$', text, re.MULTILINE | re.IGNORECASE)
            if cookies:
                result['details']['cookies'] = len(cookies)
            
            # HTTP статус
            match = re.search(r'^HTTP/\d\.\d (\d+) (.+)$', text, re.MULTILINE)
            if match:
                result['details']['status'] = f"{match.group(1)} {match.group(2)}"
        
        except:
            pass
        
        return result
    
    def _parse_mysql(self, data: bytes) -> Dict:
        """Парсит MySQL приветственный пакет"""
        result = {}
        try:
            if len(data) > 4:
                # Пропускаем длину пакета и номер
                protocol_version = data[4]
                
                # Ищем конец строки с версией
                version_end = data.find(b'\x00', 5)
                if version_end > 5:
                    version = data[5:version_end].decode('utf-8', errors='ignore')
                    result['version'] = version
                    result['banner'] = f"MySQL {version}"
        except:
            pass
        
        return result
    
    def _parse_postgresql(self, data: bytes) -> Dict:
        """Парсит PostgreSQL ответ"""
        result = {}
        try:
            if data and data[0] == 0x52:  # 'R' - Authentication request
                result['version'] = "PostgreSQL (authenticated)"
            elif data and data[0] == 0x45:  # 'E' - Error
                error_msg = data[1:].decode('utf-8', errors='ignore')
                result['version'] = f"PostgreSQL ({error_msg[:50]})"
        except:
            pass
        
        return result
    
    def _parse_redis(self, data: bytes) -> Dict:
        """Парсит Redis ответ"""
        result = {}
        try:
            text = data.decode('utf-8', errors='ignore')
            
            # Ищем версию в INFO выводе
            match = re.search(r'redis_version:(\d+\.\d+\.\d+)', text)
            if match:
                result['version'] = f"Redis {match.group(1)}"
            
            # Дополнительная информация
            for field in ['redis_mode', 'os', 'arch_bits', 'process_id']:
                match = re.search(rf'{field}:(.+)', text)
                if match:
                    result['details'][field] = match.group(1).strip()
        
        except:
            pass
        
        return result
    
    def _parse_rdp(self, data: bytes) -> Dict:
        """Парсит RDP Negotiation Response"""
        result = {}
        try:
            if len(data) >= 8:
                if data[0:4] == b'\x03\x00\x00\x13':
                    result['version'] = "RDP (TLS supported)"
                elif data[0:4] == b'\x03\x00\x00\x0b':
                    result['version'] = "RDP (Standard RDP Security)"
                else:
                    result['version'] = "RDP (Unknown)"
        except:
            pass
        
        return result
    
    def _parse_smb(self, data: bytes) -> Dict:
        """Парсит SMB Negotiate Response"""
        result = {}
        try:
            if len(data) > 8:
                # Заголовок SMB
                if data[0:4] == b'\x00\x00\x00\x90':
                    result['version'] = "SMBv1"
                elif data[0:4] == b'\xfeSMB':
                    result['version'] = "SMBv2"
        except:
            pass
        
        return result
    
    def _parse_dns(self, data: bytes) -> Dict:
        """Парсит DNS ответ"""
        result = {}
        try:
            if len(data) >= 12:
                flags = struct.unpack('>H', data[2:4])[0]
                qr = (flags >> 15) & 1
                if qr:
                    result['version'] = "DNS (responding)"
                else:
                    result['version'] = "DNS (query only)"
        except:
            pass
        
        return result
    
    def _parse_vnc(self, data: bytes) -> Dict:
        """Парсит VNC RFB протокол"""
        result = {}
        try:
            if len(data) >= 12:
                version = data[:12].decode('utf-8', errors='ignore')
                match = re.search(r'RFB (\d{3}\.\d{3})', version)
                if match:
                    result['version'] = f"VNC RFB {match.group(1)}"
        except:
            pass
        
        return result


if __name__ == '__main__':
    grabber = BannerGrabber('127.0.0.1')
    
    for port in [80, 443, 22, 3306, 5432, 6379, 27017]:
        result = grabber.grab_banner(port)
        if result['banner']:
            print(f"\nПорт {port}: {result['service']}")
            print(f"  Версия: {result['version']}")
            print(f"  Баннер: {result['banner'][:100]}")
