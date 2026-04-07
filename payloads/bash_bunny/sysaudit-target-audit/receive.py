#!/usr/bin/env python3
"""
receive.py — Bash Bunny HTTP server for the SysAudit payload.

Serves staged payload files (GET) and receives the audit ZIP (POST /upload).
Designed to run on the Bash Bunny itself; binds 0.0.0.0 so the RNDIS
target (and any other interface) can reach it.

Usage:
    python3 receive.py --serve-dir /tmp/bb_serve --loot-dir /loot/sysaudit-target-audit [--port 80]
"""

import argparse
import http.server
import os
import sys

SERVE_DIR: str = ''
LOOT_DIR:  str = ''


class AuditHandler(http.server.BaseHTTPRequestHandler):
    """Handle GET (file serving) and POST (loot intake) requests."""

    # Suppress per-request log lines — Bunny stdout/stderr space is limited.
    def log_message(self, fmt, *args):  # noqa: N802
        pass

    def do_GET(self):  # noqa: N802
        # Strip leading slash; prevent directory traversal
        rel  = self.path.lstrip('/').replace('..', '').lstrip('/')
        path = os.path.join(SERVE_DIR, rel)

        if rel and os.path.isfile(path):
            with open(path, 'rb') as fh:
                data = fh.read()
            self.send_response(200)
            self.send_header('Content-Type', 'application/octet-stream')
            self.send_header('Content-Length', str(len(data)))
            self.end_headers()
            self.wfile.write(data)
        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self):  # noqa: N802
        length = int(self.headers.get('Content-Length', 0))
        body   = self.rfile.read(length)

        # Derive filename from URL path or default to audit_results.zip
        rel  = self.path.strip('/') or 'upload'
        name = 'audit_results.zip' if rel == 'upload' else os.path.basename(rel)

        out = os.path.join(LOOT_DIR, name)
        with open(out, 'wb') as fh:
            fh.write(body)

        self.send_response(200)
        self.end_headers()


def main() -> None:
    global SERVE_DIR, LOOT_DIR

    parser = argparse.ArgumentParser(description='Bash Bunny SysAudit HTTP server/receiver')
    parser.add_argument('--serve-dir', required=True,
                        help='Directory containing files to serve (runner.ps1, SysAudit.ps1)')
    parser.add_argument('--loot-dir',  required=True,
                        help='Directory where received loot (audit ZIP) will be saved')
    parser.add_argument('--port', type=int, default=80,
                        help='TCP port to listen on (default: 80)')
    args = parser.parse_args()

    SERVE_DIR = os.path.abspath(args.serve_dir)
    LOOT_DIR  = os.path.abspath(args.loot_dir)

    os.makedirs(LOOT_DIR, exist_ok=True)

    server = http.server.HTTPServer(('0.0.0.0', args.port), AuditHandler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == '__main__':
    main()
