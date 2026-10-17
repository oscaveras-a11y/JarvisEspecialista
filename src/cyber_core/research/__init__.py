"""Offline source-authority classification. No implicit web retrieval.

Part of item 11 (technical research engine). The source registry already records
title/url/version/provenance/author; this adds the scope's required
differentiation of source authority (official vs academic vs community) by a
domain heuristic. It is offline and advisory: a heuristic label to verify, never
an implicit fetch and never a claim of correctness.
"""
from urllib.parse import urlsplit
from cyber_core.errors import CoreError

OFFICIAL = ('.gov', 'nist.gov', 'ietf.org', 'iso.org', 'iana.org', 'owasp.org',
            'learn.microsoft.com', 'developer.mozilla.org', 'docs.python.org', 'kernel.org')
ACADEMIC = ('arxiv.org', 'doi.org', '.edu', 'ieee.org', 'acm.org', 'usenix.org',
            'springer.com', 'sciencedirect.com')
COMMUNITY = ('github.com', 'gitlab.com', 'stackoverflow.com', 'stackexchange.com',
             'reddit.com', 'medium.com')


def _matches(host, markers):
    return any(host == marker.lstrip('.') or host.endswith(marker) for marker in markers)


def classify_source(url):
    if not isinstance(url, str) or not url.strip():
        raise CoreError('A source URL is required')
    parts = urlsplit(url.strip())
    if parts.scheme not in ('http', 'https') or not parts.hostname:
        raise CoreError('Source URL must be http(s) with a host')
    host = parts.hostname.lower()
    if _matches(host, OFFICIAL):
        category = 'official'
    elif _matches(host, ACADEMIC):
        category = 'academic'
    elif _matches(host, COMMUNITY):
        category = 'community'
    else:
        category = 'unknown'
    return {'host': host, 'category': category,
            'rationale': 'Heuristic classification by domain',
            'limitation': 'Heurística por domínio; confirme a autoridade e a versão da fonte. Nenhuma busca na web foi feita.'}
