"""Blocks outbound network access inside the trusted analysis child (item 14:
"politica de acesso a rede"). The child processes untrusted evidence bytes;
this removes the network as an avenue even if analyzed content ever tricked
trusted code into attempting a connection. Must be called before any analysis
code runs. Python-level, not kernel-level: it covers socket and anything
built on it (urllib, http.client, requests, ftplib, smtplib, ...), not raw
file descriptors passed in some other way.
"""
import socket


class NetworkBlocked(OSError):
    pass


def _blocked(*_args, **_kwargs):
    raise NetworkBlocked('Network access is blocked while processing analyzed evidence')


def block_network():
    socket.socket = _blocked
    socket.create_connection = _blocked
    socket.getaddrinfo = _blocked
    socket.gethostbyname = _blocked
