#!/usr/bin/env python3
import os
import sys
import http.server
import socketserver
import threading
import websockets
import asyncio
import socket
from pathlib import Path
from http import HTTPStatus
from termcolor import colored
import webbrowser
import json

from .utils.loadProjectFiles import load_project_files
from .scanners.codeScanner import run_code_scan
# -----------------------------
# HTTP handler
# -----------------------------
class DashboardHandler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        self.templates_dir = Path(__file__).parent / 'templates'
        super().__init__(*args, directory=str(self.templates_dir), **kwargs)

    def do_GET(self):
        if self.path in ['/', '/dashboard']:
            self.path = '/dashboard.html'
        elif self.path.endswith('.css'):
            self.path = '/styles.css'

        file_path = self.templates_dir / self.path.lstrip('/')
        if file_path.exists():
            if self.path.endswith('.css'):
                self.send_response(HTTPStatus.OK)
                self.send_header('Content-type', 'text/css')
                self.end_headers()
                with open(file_path, 'rb') as f:
                    self.wfile.write(f.read())
            else:
                return super().do_GET()
        else:
            self.send_error(HTTPStatus.NOT_FOUND, "Not Found")

    def log_message(self, format, *args):
            pass  # disable logging
    
    def log_error(self, format, *args):
        pass

# -----------------------------
# WebSocket + scan
# -----------------------------
async def websocket_handler(websocket):
    await send_scan_results(websocket)

async def send_scan_results(websocket=None):
    cwd = os.getcwd()
    print(colored(f"🔍 Scanning: {cwd}", 'green'))

    # Async load files
    source_files = await load_project_files(cwd)

    # Run scan
    scan_results = run_code_scan(source_files)

    results = {
        'reflective': scan_results.get('reflectiveXSS', []),
        'stored': scan_results.get('storedXSS', []),
        'dom': scan_results.get('domXSS', [])
    }

    if websocket is not None:  # 👈 only send if websocket given
        await websocket.send(json.dumps(
            {'type': 'update', 'results': results},
            default=str  # convert Enums/objects safely
        ))

    return results



# async def run_code_scan(source_files):
#     """Dummy scan implementation"""
#     return {
#         'reflectiveXSS': [],
#         'storedXSS': [],
#         'domXSS': []
#     }

# -----------------------------
# Utilities
# -----------------------------
def find_available_port(start_port):
    port = start_port
    while True:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.bind(('', port))
                return port
        except OSError:
            port += 1

# -----------------------------
# Start dashboard
# -----------------------------
async def start_dashboard(port=None):
    actual_port = port or find_available_port(5713)

    # HTTP server
    handler = DashboardHandler
    httpd = socketserver.TCPServer(("", actual_port), handler)
    http_thread = threading.Thread(target=httpd.serve_forever)
    http_thread.daemon = True
    http_thread.start()

    # WebSocket server
    ws_port = actual_port + 1
    start_server = websockets.serve(websocket_handler, "localhost", ws_port)
    ws_server = await start_server

    # Run one-time scan immediately
    await send_scan_results()

    url = f"http://localhost:{actual_port}"
    print(colored(f"Dashboard available at: {url}", 'cyan'))
    print(colored(f"WebSocket available at: ws://localhost:{ws_port}", "yellow"))

    
    webbrowser.open(url)

    try:
        while True:
            await asyncio.sleep(1)
    except KeyboardInterrupt:
        httpd.shutdown()
        await ws_server.close()

# -----------------------------
# Entry point
# -----------------------------
if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "scan":
        try:
            asyncio.get_event_loop().run_until_complete(start_dashboard())
        except KeyboardInterrupt:
            print("\nServer stopped")
    else:
        print("Usage: python dashboard.py scan")
