"""Explicit synthetic loopback laboratory protocol, never a real-site scanner."""
import argparse
import http.client
import json
import time
from urllib.parse import urlsplit

def audit(url):
    target=urlsplit(url)
    if (target.scheme!='http' or target.hostname!='127.0.0.1' or target.username
        or target.password or target.path not in ('','/') or target.query or target.fragment
        or not target.port or target.port<1024):
        raise ValueError('Only an explicit 127.0.0.1 laboratory origin on a high port is supported')
    deadline=time.monotonic()+10
    requests=0
    def request(method,payload=None):
        nonlocal requests
        requests+=1
        if requests>5 or time.monotonic()>=deadline:
            raise RuntimeError('Laboratory request/time budget exhausted')
        connection=http.client.HTTPConnection('127.0.0.1',target.port,timeout=max(.01,deadline-time.monotonic()))
        body=None if payload is None else json.dumps(payload).encode()
        try:
            connection.request(method,'/lab/content',body,
                               {'Content-Type':'application/json','Connection':'close'})
            response=connection.getresponse()
            data=response.read(65537)
            if len(data)>65536:
                raise RuntimeError('Laboratory response limit exceeded')
            if 300<=response.status<400:
                raise RuntimeError('Redirects are not followed')
            return response.status,data
        finally:
            connection.close()
    status,data=request('GET')
    original=json.loads(data)
    if status!=200 or not isinstance(original,dict) or not isinstance(original.get('title'),str):
        raise RuntimeError('Unsupported synthetic laboratory response')
    if len(original['title'])>1024:
        raise RuntimeError('Laboratory title limit exceeded')
    changed=False
    restored=False
    try:
        status,_=request('POST',{'title':'jarvis-synthetic-probe'})
        status,data=request('GET')
        changed=status==200 and json.loads(data).get('title')=='jarvis-synthetic-probe'
    finally:
        request('POST',{'title':original['title']})
        status,data=request('GET')
        restored=status==200 and json.loads(data).get('title')==original['title']
    return {'scope':'synthetic_loopback_lab','unauthenticated_write_observed':changed,
            'restored':restored,'requests':requests,
            'limitation':'Demonstrates this laboratory endpoint only; not a general website exploitation engine'}

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('url')
    args=parser.parse_args()
    print(json.dumps(audit(args.url)))

if __name__=='__main__':
    main()
