"""Quick Nmap test"""
import sys, os
sys.path.insert(0, os.path.abspath(os.path.dirname(os.path.dirname(__file__))))
from app import create_app
from app.services.nmap_service import NmapScanner

app = create_app()
with app.app_context():
    scanner = NmapScanner()
    print(f'Nmap available: {scanner.is_available()}')
    print(f'Path: {scanner.nmap_path}')
    print()
    print('Scanning 127.0.0.1 (ports 80,135,445,8080)...')
    results, error = scanner.scan('127.0.0.1', '80,135,445,8080')
    if error:
        print(f'Error: {error}')
    else:
        print(f'Found {len(results)} ports:')
        for r in results:
            print(f'  {r["port"]}/{r["protocol"]} {r["state"]} {r["service"]} {r["version"]}')
