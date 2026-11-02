"""Isolated bounded HTTPS fetch of one explicit URL. Invoked only under run_bounded.

Item 11 (technical research engine): fetches EXACTLY the URL the caller
named — never crawls, never follows a search, never decides on its own what
to fetch. The response is hashed and a bounded text excerpt is extracted for
the investigation record; nothing fetched here is ever executed, imported,
evaluated or passed to another tool. TLS certificate verification is always
on (the system trust store, via ssl.create_default_context()) and is never
disabled, regardless of what the response or any redirect claims.
"""
import hashlib
import json
import ssl
import sys
import urllib.error
import urllib.request

MAX_BYTES = 4 * 1024 * 1024
MAX_EXCERPT_BYTES = 8192
MAX_REDIRECTS = 5
TEXT_CONTENT_TYPES = ("text/plain", "text/html", "text/markdown", "text/xml",
                      "application/json", "application/xml", "application/rss+xml")


class _HttpsOnlyRedirectHandler(urllib.request.HTTPRedirectHandler):
    def __init__(self):
        self.hops = 0

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        self.hops += 1
        if self.hops > MAX_REDIRECTS:
            raise urllib.error.URLError("Too many redirects")
        if not newurl.lower().startswith("https://"):
            raise urllib.error.URLError("Redirect left https")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def fetch(url, *, max_bytes, timeout):
    if not isinstance(url, str) or not url.lower().startswith("https://"):
        raise ValueError("Only an explicit https URL is fetched")
    if type(max_bytes) is not int or not 1 <= max_bytes <= MAX_BYTES:
        raise ValueError("Invalid fetch byte limit")
    if type(timeout) not in (int, float) or not 0 < timeout <= 120:
        raise ValueError("Invalid fetch timeout")
    context = ssl.create_default_context()
    redirects = _HttpsOnlyRedirectHandler()
    opener = urllib.request.build_opener(redirects, urllib.request.HTTPSHandler(context=context))
    # No cookies, no credentials, no referrer — a plain, identifying GET of
    # exactly the one URL named.
    request = urllib.request.Request(url, headers={"User-Agent": "cyber-core-research/1 (+authorized investigation)"})
    with opener.open(request, timeout=timeout) as response:
        final_url = response.geturl()
        if not final_url.lower().startswith("https://"):
            raise ValueError("Final URL left https")
        status = response.status
        content_type = response.headers.get("Content-Type", "")
        last_modified = response.headers.get("Last-Modified", "")
        etag = response.headers.get("ETag", "")
        body = bytearray()
        while True:
            block = response.read(65536)
            if not block:
                break
            body += block
            if len(body) > max_bytes:
                raise ValueError("Fetched content exceeds byte limit")
    digest = hashlib.sha256(bytes(body)).hexdigest()
    excerpt = ""
    if content_type.split(";")[0].strip().lower() in TEXT_CONTENT_TYPES:
        excerpt = bytes(body[:MAX_EXCERPT_BYTES]).decode("utf-8", "replace")
    return {"status": status, "final_url": final_url, "content_type": content_type[:200],
            "last_modified": last_modified[:128], "etag": etag[:256],
            "bytes": len(body), "sha256": digest, "excerpt": excerpt,
            "excerpt_truncated": len(body) > MAX_EXCERPT_BYTES}


def main():
    try:
        data = json.loads(sys.stdin.buffer.read(16385))
        result = fetch(data["url"], max_bytes=data.get("max_bytes", MAX_BYTES), timeout=data.get("timeout", 30))
        print(json.dumps(result, ensure_ascii=True))
        return 0
    except BaseException:
        print('{"error":"fetch_failed"}')
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
