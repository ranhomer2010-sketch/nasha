#!/usr/bin/env python3
"""Regenerate the inline CSP hashes after changes to the standalone HTML."""
import base64
import hashlib
from html.parser import HTMLParser
from pathlib import Path
import re

root = Path(__file__).resolve().parent.parent
path = root / 'index.html'
html = path.read_text(encoding='utf-8')

def digest(text):
    value = base64.b64encode(hashlib.sha256(text.encode('utf-8')).digest()).decode()
    return "'sha256-" + value + "'"

scripts = re.findall(r'<script\b[^>]*>([\s\S]*?)</script>', html)
styles = re.findall(r'<style\b[^>]*>([\s\S]*?)</style>', html)
policy = "; ".join([
    "default-src 'none'",
    "script-src 'self' " + ' '.join(digest(x) for x in scripts),
    "style-src 'self' " + ' '.join(digest(x) for x in styles),
    "img-src 'self' data:",
    "font-src 'self'",
    "media-src 'self'",
    "connect-src 'none'",
    "frame-src 'none'",
    "object-src 'none'",
    "base-uri 'none'",
    "form-action 'none'",
])
meta = '<meta http-equiv="Content-Security-Policy" content="' + policy + '">'
if '<!-- CSP_HASHES -->' in html:
    html = html.replace('<!-- CSP_HASHES -->', meta)
else:
    html, count = re.subn(r'<meta http-equiv="Content-Security-Policy" content="[^"]*">', meta, html)
    if count != 1:
        raise SystemExit('Expected exactly one CSP placeholder or meta tag')
path.write_text(html, encoding='utf-8')
(root / 'security-headers.txt').write_text(
    '# Apply as HTTP response headers at the Russian host.\n'
    '# CSP below is generated for this exact index.html.\n'
    'Content-Security-Policy: ' + policy + "; frame-ancestors 'none'\n"
    'Referrer-Policy: no-referrer\n'
    'X-Content-Type-Options: nosniff\n'
    'X-Frame-Options: DENY\n'
    'Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=(), usb=()\n'
    '# Enable HSTS only after HTTPS works on the final domain.\n'
    '# Strict-Transport-Security: max-age=31536000\n', encoding='utf-8')

class Audit(HTMLParser):
    def __init__(self):
        super().__init__(); self.ids=set(); self.duplicates=[]; self.h1=0; self.chapters=0; self.externals=[]
    def handle_starttag(self, tag, attrs):
        attrs=dict(attrs)
        if 'id' in attrs:
            if attrs['id'] in self.ids: self.duplicates.append(attrs['id'])
            self.ids.add(attrs['id'])
        if tag == 'h1': self.h1 += 1
        if tag == 'section' and 'data-chapter' in attrs: self.chapters += 1
        for key in ('src', 'href', 'action', 'poster'):
            value=attrs.get(key, '')
            if value.startswith(('http:', 'https:', '//')): self.externals.append((tag,key,value))

audit=Audit(); audit.feed(html)
assert audit.h1 == 1, audit.h1
assert audit.chapters == 4, audit.chapters
assert not audit.duplicates, audit.duplicates
assert not audit.externals, audit.externals
assert 'checked' not in re.search(r'<input[^>]+id="consent"[^>]+>', html).group(0)
assert not re.search(r'\b(?:fetch|XMLHttpRequest|sendBeacon|WebSocket)\s*\(', html)
(root / 'tools' / 'app-check.js').write_text(scripts[-1], encoding='utf-8')
print('OK: 4 chapters; 1 H1; unique IDs; no external resource URLs; no form transport; consent unchecked; CSP regenerated.')
