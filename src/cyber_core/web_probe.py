"""Scoped HTTPS protocol observations. No exploitation, writes, credentials or crawling."""
from datetime import datetime, timezone
import hashlib
import http.client
import ipaddress
import json
import math
from pathlib import Path
import platform
import re
import socket
import ssl
import sys
import tempfile
import time
from urllib.parse import urlsplit

VERSION = 'https-probe-1'
SECURITY_HEADERS = ('strict-transport-security', 'content-security-policy',
                    'x-content-type-options', 'x-frame-options', 'referrer-policy',
                    'permissions-policy')


def public_address(value):
    address = ipaddress.ip_address(value)
    if (not address.is_global or address.is_multicast or address.is_reserved
            or address.is_loopback or address.is_link_local or address.is_unspecified):
        raise ValueError('Nonpublic destination rejected')
    if address.version == 6:
        if address not in ipaddress.ip_network('2000::/3') or address.sixtofour or address.teredo:
            raise ValueError('Transition destination rejected')
    return str(address)


def _origin(value):
    if not isinstance(value, str) or not 1 <= len(value) <= 512 or any(ord(c) <= 32 or ord(c) >= 127 for c in value):
        raise ValueError('Invalid HTTPS origin')
    target = urlsplit(value)
    if (target.scheme != 'https' or target.username is not None or target.password is not None
            or target.path not in ('', '/') or target.query or target.fragment
            or '?' in value or '#' in value or '\\' in value):
        raise ValueError('Explicit HTTPS origin required')
    host = target.hostname
    if not host or host.endswith('.') or len(host) > 253:
        raise ValueError('Invalid host')
    try:
        ipaddress.ip_address(host)
    except ValueError:
        if not all(re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', label) for label in host.split('.')):
            raise ValueError('Invalid ASCII hostname')
    else:
        public_address(host)
    port = 443 if target.port is None else target.port
    if port != 443 and not 1024 <= port <= 65535:
        raise ValueError('Invalid HTTPS port')
    authority = ('['+host+']') if ':' in host else host
    if port != 443:
        authority += ':'+str(port)
    return 'https://'+authority, host, port


def validate_grant(grant):
    fields = {'version','origin','paths','allow_read','authorization','expires_at'}
    if (not isinstance(grant, dict) or set(grant) != fields
            or type(grant['version']) is not int or grant['version'] != 1
            or grant['allow_read'] is not True):
        raise ValueError('Explicit versioned read grant required')
    origin, _, _ = _origin(grant['origin'])
    declaration = grant['authorization']
    if (not isinstance(declaration, str) or not 1 <= len(declaration.strip()) <= 256
            or any(ord(c) < 32 or 0xD800 <= ord(c) <= 0xDFFF for c in declaration)):
        raise ValueError('Authorization declaration required')
    paths = grant['paths']
    if not isinstance(paths, list) or not 1 <= len(paths) <= 8 or len(set(p for p in paths if isinstance(p,str))) != len(paths):
        raise ValueError('One to eight unique explicit paths required')
    for path in paths:
        if (not isinstance(path,str) or not 1 <= len(path) <= 256
                or not re.fullmatch(r"/[A-Za-z0-9/_~.!$&'()*+,;=:@-]*",path)
                or '//' in path or any(part in ('.','..') for part in path.split('/'))):
            raise ValueError('Invalid explicit path')
    expires = grant['expires_at']
    if not isinstance(expires, str) or len(expires) > 64:
        raise ValueError('Invalid grant expiry')
    stamp = datetime.fromisoformat(expires)
    if stamp.tzinfo is None or stamp.utcoffset() is None or stamp <= datetime.now(timezone.utc):
        raise ValueError('Expired or timezone-free grant')
    return {**grant, 'origin':origin}


def _unique(pairs):
    result = {}
    for key,value in pairs:
        if key in result:
            raise ValueError('Duplicate manifest key')
        result[key] = value
    return result


def parse_grant(raw):
    if not isinstance(raw, bytes) or len(raw) > 8192:
        raise ValueError('Manifest byte limit exceeded')
    try:
        return validate_grant(json.loads(raw.decode('utf-8'),object_pairs_hook=_unique))
    except (UnicodeError, RecursionError, TypeError, OverflowError):
        raise ValueError('Invalid grant encoding or fields') from None


def validate_options(*, body_bytes=65536, seconds=30):
    if type(body_bytes) is not int or not 1 <= body_bytes <= 1048576:
        raise ValueError('Invalid response body budget')
    if type(seconds) not in (int,float) or not math.isfinite(seconds) or not 0 < seconds <= 300:
        raise ValueError('Invalid probe time budget')
    return {'body_bytes':body_bytes,'seconds':seconds}


def resolve_public(host, port):
    answers = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    if not answers or len(answers) > 32:
        raise ValueError('DNS answer count rejected')
    # Reject the entire answer set if any destination is outside policy.
    addresses = list(dict.fromkeys(public_address(item[4][0]) for item in answers))
    if len(addresses) > 16:
        raise ValueError('DNS address count rejected')
    return addresses


class _PinnedHTTPS(http.client.HTTPSConnection):
    def __init__(self,host,port,address,*,context,timeout):
        super().__init__(host,port,context=context,timeout=timeout)
        self.address = address

    def connect(self):
        address = public_address(self.address)
        family = socket.AF_INET6 if ':' in address else socket.AF_INET
        raw = socket.socket(family,socket.SOCK_STREAM)
        try:
            raw.settimeout(self.timeout)
            raw.connect((address,self.port))
            if public_address(raw.getpeername()[0]) != address:
                raise ValueError('Unexpected peer address')
            self.sock = self._context.wrap_socket(raw,server_hostname=self.host)
        except BaseException:
            raw.close()
            raise


def probe(grant, *, body_bytes=65536, seconds=30, ca_pem=None):
    options = validate_options(body_bytes=body_bytes,seconds=seconds)
    grant = validate_grant(grant)
    origin,host,port = _origin(grant['origin'])
    context = ssl.create_default_context()
    if ca_pem is not None:
        if not isinstance(ca_pem,str) or len(ca_pem.encode()) > 4096 or 'PRIVATE KEY' in ca_pem:
            raise ValueError('Invalid supplied public CA')
        context.load_verify_locations(cadata=ca_pem)
    deadline = time.monotonic()+seconds
    responses = []
    for path in grant['paths']:
        validate_grant(grant)
        if responses:
            time.sleep(.25)
        if time.monotonic() >= deadline:
            break
        connection = None
        try:
            addresses = resolve_public(host,port)
            remaining = deadline-time.monotonic()
            if remaining <= 0:
                break
            address = addresses[0]
            connection = _PinnedHTTPS(host,port,address,context=context,timeout=min(5,remaining))
            connection.connect()
            tls = {'version':connection.sock.version(),
                   'certificate_sha256':hashlib.sha256(connection.sock.getpeercert(binary_form=True)).hexdigest(),
                   'trust_source':'supplied_ca_plus_system' if ca_pem else 'system'}
            connection.request('GET',path,headers={'User-Agent':'JarvisProtocolProbe/1',
                               'Accept-Encoding':'identity','Connection':'close','Accept':'*/*'})
            response = connection.getresponse()
            headers = response.getheaders()
            if sum(len(k)+len(v)+4 for k,v in headers) > 65536:
                raise ValueError('Header byte budget exceeded')
            names = {key.lower() for key,_ in headers}
            digest = hashlib.sha256()
            read = 0
            complete = False
            incomplete_reason = None
            while read < body_bytes:
                if time.monotonic() >= deadline:
                    raise TimeoutError()
                chunk = response.read1(min(8192,body_bytes-read))
                if not chunk:
                    if response.length not in (None,0):
                        incomplete_reason = 'premature_eof'
                    else:
                        complete = True
                    break
                digest.update(chunk)
                read += len(chunk)
            if not complete and incomplete_reason is None:
                if time.monotonic() >= deadline:
                    raise TimeoutError()
                extra = response.read1(1)  # At most one extra byte, never hashed.
                if extra:
                    incomplete_reason = 'body_byte_limit'
                elif response.length not in (None,0):
                    incomplete_reason = 'premature_eof'
                else:
                    complete = True
            responses.append({'path':path,'status':response.status,'peer_ip':address,
                              'resolved_public_addresses':addresses,'tls':tls,
                              'security_headers':{name:name in names for name in SECURITY_HEADERS},
                              'body_sha256':digest.hexdigest(),'body_bytes_hashed':read,
                              'body_complete':complete,'incomplete_reason':incomplete_reason,
                              'hash_scope':'complete_response_body' if complete else 'response_body_prefix',
                              'redirect_followed':False})
        except ssl.SSLCertVerificationError:
            responses.append({'path':path,'error':'tls_validation_failed'})
        except (socket.timeout,TimeoutError):
            responses.append({'path':path,'error':'network_timeout'})
        except ValueError:
            responses.append({'path':path,'error':'destination_or_response_policy_rejected'})
        except (OSError,http.client.HTTPException):
            responses.append({'path':path,'error':'connection_or_protocol_failed'})
        finally:
            if connection is not None:
                connection.close()
    partial = (len(responses) != len(grant['paths'])
               or any('error' in r or not r.get('body_complete',False) or 300 <= r.get('status',0) < 400
                      for r in responses))
    return {'version':VERSION,'origin':origin,'parameters':options,'status':'partial' if partial else 'completed',
            'responses':responses,'paths_not_attempted':len(grant['paths'])-len(responses),
            'runtime':{'python':platform.python_version(),'openssl':ssl.OPENSSL_VERSION},
            'interpretation':'Read-only protocol observations; header presence is not a vulnerability verdict',
            'limitations':['No exploitation, authentication tests, writes, JavaScript execution or crawling',
                           'Certificate validation authenticates the TLS endpoint under the selected trust roots, not site ownership',
                           'Absent findings do not establish site security; no firmware or electoral evidence is collected']}


def run_probe(core,case,manifest,*,ca_file=None,body_bytes=65536,seconds=30,receipt=None,control_check=None):
    from cyber_core.agents.runner import run_bounded
    from cyber_core.errors import CoreError
    from cyber_core.memory import audit
    from cyber_core.operations import _acquire, save_operation
    if receipt is not None and (not isinstance(receipt,str) or not re.fullmatch(r'[0-9a-f]{32}',receipt)):
        raise CoreError('Invalid campaign receipt')
    if control_check is not None and not callable(control_check):
        raise CoreError('Invalid campaign control callback')
    try:
        options = validate_options(body_bytes=body_bytes,seconds=seconds)
    except ValueError:
        raise CoreError('Invalid HTTPS probe budgets') from None
    options['seconds'] = min(options['seconds'],core.timeout)
    raw,evidence = _acquire(core,case,manifest,8192)
    try:
        grant = parse_grant(raw)
    except ValueError:
        raise CoreError('Invalid or expired HTTPS read grant') from None
    inputs = [(manifest,evidence['sha256'],8192)]
    ca_pem = None
    ca_evidence = None
    if ca_file is not None:
        ca_raw,ca_evidence = _acquire(core,case,ca_file,4096)
        try:
            ca_pem = ca_raw.decode('ascii')
            if 'PRIVATE KEY' in ca_pem or '-----BEGIN CERTIFICATE-----' not in ca_pem:
                raise ValueError()
            ssl.create_default_context().load_verify_locations(cadata=ca_pem)
        except (ValueError,UnicodeError,ssl.SSLError):
            raise CoreError('Invalid public CA certificate') from None
        inputs.append((ca_file,ca_evidence['sha256'],4096))
    def stopped():
        if control_check is not None:
            control_check()
        row = core.authorize(case)
        if row['paused']:
            raise CoreError('Investigation is paused')
        for path,digest,limit in inputs:
            source = core.authorize(case,path)
            with source.open('rb') as handle:
                current = handle.read(limit+1)
            if len(current) > limit or hashlib.sha256(current).hexdigest() != digest:
                raise CoreError('HTTPS grant or CA input changed')
        try:
            validate_grant(grant)
        except ValueError:
            raise CoreError('HTTPS read grant expired') from None
        return False
    stopped()
    with core.db:
        audit(core.db,case,'web_probe_started',{'manifest_sha256':evidence['sha256'],'origin':grant['origin']})
    try:
        request = dict(grant=grant,ca_pem=ca_pem,**options)
        with tempfile.TemporaryDirectory(prefix='cyber-https-') as folder:
            response = run_bounded([sys.executable,'-I',str(Path(__file__).with_name('web_probe_child.py'))],
                                   json.dumps(request),cwd=folder,timeout=options['seconds'],
                                   max_output=65536,should_stop=stopped,env={})
        result = json.loads(response['stdout'])
        if (not isinstance(result,dict) or result.get('origin') != grant['origin']
                or not isinstance(result.get('responses'),list) or len(result['responses']) > len(grant['paths'])):
            raise CoreError('Invalid HTTPS worker result')
        stopped()
        return save_operation(core,case,'web_probe',{'evidence':evidence,'ca_evidence':ca_evidence,
                              'parameters':options,'analysis':result,
                              **({'campaign_receipt':receipt} if receipt is not None else {})},
                              commit_guard=control_check)
    except BaseException:
        with core.db:
            audit(core.db,case,'web_probe_interrupted',{'manifest_sha256':evidence['sha256'],
                  'result_complete':False,'remote_effects':'GET requests may already have reached the server'})
        raise
