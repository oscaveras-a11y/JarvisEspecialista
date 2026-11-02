"""Explicit, bounded retrieval of one authorized technical reference (item 11).

Scope rule: consult sources only with connectivity AND authorized access, never
execute downloaded content. This is an opt-in operator action, not a crawler or
search engine: the operator names the exact host(s) allowed for this call; only
https is used; redirects are refused; size/time are capped; the body is treated
as inert text (hash + sanitized excerpt) and is never parsed as code. Hosts that
resolve to private/loopback/link-local space are refused (SSRF guard).
"""
import hashlib
import html
import ipaddress
import re
import socket
import ssl
import urllib.error
import urllib.request
from datetime import datetime, timezone
from urllib.parse import urlsplit

from cyber_core.errors import CoreError
from cyber_core.research import classify_source

MAX_BYTES = 2 * 1024 * 1024
MAX_TIMEOUT = 60
TEXT_TYPES = ('text/html', 'text/plain', 'text/markdown', 'application/json',
              'application/xml', 'text/xml', 'application/xhtml+xml')


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def _public_host(host, resolver):
    try:
        addresses = {ipaddress.ip_address(a) for a in resolver(host)}
    except (OSError, ValueError) as exc:
        raise CoreError('Reference host could not be resolved') from exc
    if not addresses or any(not a.is_global for a in addresses):
        raise CoreError('Reference host resolves to a non-public address')


def _resolve(host):
    return [info[4][0] for info in socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)]


def _excerpt(body, content_type):
    decoded = body.decode('utf-8', 'replace')
    title = ''
    if 'html' in content_type:
        match = re.search(r'<title[^>]*>(.*?)</title>', decoded, re.I | re.S)
        if match:
            title = html.unescape(re.sub(r'\s+', ' ', match.group(1))).strip()[:300]
        decoded = re.sub(r'(?is)<(script|style)\b.*?</\1\s*>', ' ', decoded)
        decoded = html.unescape(re.sub(r'<[^>]+>', ' ', decoded))
    clean = ''.join(ch if ch.isprintable() or ch in '\n\t' else ' ' for ch in decoded)
    return title, re.sub(r'\s+', ' ', clean).strip()[:1000]


def fetch_reference(url, *, allow_hosts, max_bytes=MAX_BYTES, timeout=20, resolver=_resolve, opener=None):
    """Retrieve one reference. `opener` and `resolver` are injectable for offline tests."""
    if not isinstance(url, str) or not url.strip():
        raise CoreError('A reference URL is required')
    parts = urlsplit(url.strip())
    if parts.scheme != 'https' or not parts.hostname or parts.username or parts.password:
        raise CoreError('Reference URL must be https without credentials')
    host = parts.hostname.lower()
    allowed = {h.strip().lower() for h in (allow_hosts or ()) if isinstance(h, str) and h.strip()}
    if not allowed:
        raise CoreError('Retrieval requires an explicit --allow-host')
    if host not in allowed:
        raise CoreError('Reference host is not in the allowed host list')
    if not isinstance(max_bytes, int) or not 1 <= max_bytes <= MAX_BYTES:
        raise CoreError('Invalid maximum size')
    if not isinstance(timeout, (int, float)) or not 0 < timeout <= MAX_TIMEOUT:
        raise CoreError('Invalid timeout')
    if opener is None:
        _public_host(host, resolver)
        opener = urllib.request.build_opener(_NoRedirect, urllib.request.HTTPSHandler(context=ssl.create_default_context())).open
    request = urllib.request.Request(url.strip(), headers={'User-Agent': 'cyber-core-reference/1', 'Accept': 'text/*, application/json, application/xml'})
    try:
        with opener(request, timeout=timeout) as response:
            status = getattr(response, 'status', 200)
            content_type = (response.headers.get('Content-Type') or '').split(';')[0].strip().lower()
            if status != 200:
                raise CoreError('Reference server returned status %s' % status)
            if content_type not in TEXT_TYPES:
                raise CoreError('Reference content type is not accepted: %s' % (content_type or 'unknown'))
            body = response.read(max_bytes + 1)
    except urllib.error.HTTPError as exc:
        raise CoreError('Reference server returned status %s (redirects are refused)' % exc.code) from exc
    except (urllib.error.URLError, OSError, TimeoutError) as exc:
        raise CoreError('Reference could not be retrieved') from exc
    if len(body) > max_bytes:
        raise CoreError('Reference exceeds the maximum size')
    title, excerpt = _excerpt(body, content_type)
    return {'url': url.strip(), 'host': host, 'category': classify_source(url)['category'],
            'sha256': hashlib.sha256(body).hexdigest(), 'bytes': len(body), 'content_type': content_type,
            'page_title': title, 'excerpt': excerpt,
            'retrieved_at': datetime.now(timezone.utc).isoformat(timespec='seconds'),
            'limitation': 'Conteúdo tratado como texto inerte (hash + trecho); nunca executado. Categoria é heurística por domínio; confirme autoridade e versão.'}
