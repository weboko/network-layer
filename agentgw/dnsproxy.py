"""Small forwarding DNS server (UDP + TCP) with a policy callback.

The gateway supplies `handler(src_ip, query_bytes) -> response_bytes | None`.
This module only does transport: listening, forwarding to upstream resolvers
(with TCP fallback on truncation) and building synthetic replies.
"""

import logging
import socket
import socketserver
import struct
import threading
from concurrent.futures import ThreadPoolExecutor

from dnslib import DNSRecord, EDNS0, EDNSOption, RCODE

log = logging.getLogger("agentgw.dns")

EDE_BLOCKED = 15  # RFC 8914 Extended DNS Error "Blocked"


def blocked_reply(req, text):
    """NXDOMAIN with an Extended DNS Error explaining why (shown by dig/kdig)."""
    reply = req.reply()
    reply.header.rcode = RCODE.NXDOMAIN
    if any(r.rtype == 41 for r in req.ar):  # client speaks EDNS
        data = struct.pack("!H", EDE_BLOCKED) + text.encode()[:200]
        reply.add_ar(EDNS0(udp_len=1232, opts=[EDNSOption(15, data)]))
    return reply.pack()


def servfail(req):
    reply = req.reply()
    reply.header.rcode = RCODE.SERVFAIL
    return reply.pack()


class Upstream:
    def __init__(self, servers, timeout=3.0):
        self.servers = servers
        self.timeout = timeout

    @staticmethod
    def _addr(server):
        """'1.1.1.1', '1.1.1.1:5353', '2606:4700::1111' or '[2606:4700::1111]:53'."""
        if server.startswith("["):
            host, _, port = server[1:].partition("]")
            port = port.lstrip(":")
        elif server.count(":") == 1:
            host, port = server.split(":")
        else:
            host, port = server, ""
        return host, int(port or 53)

    def query(self, data):
        last = None
        for server in self.servers:
            host, port = self._addr(server)
            fam = socket.AF_INET6 if ":" in host else socket.AF_INET
            try:
                with socket.socket(fam, socket.SOCK_DGRAM) as s:
                    s.settimeout(self.timeout)
                    s.sendto(data, (host, port))
                    while True:
                        resp, _ = s.recvfrom(65535)
                        if resp[:2] == data[:2]:  # matching transaction id
                            break
                if resp[2] & 0x02:  # TC bit: retry over TCP
                    resp = self._tcp(fam, host, port, data)
                return resp
            except OSError as e:
                last = e
                continue
        raise OSError(f"all upstream resolvers failed: {last}")

    def _tcp(self, fam, host, port, data):
        with socket.socket(fam, socket.SOCK_STREAM) as s:
            s.settimeout(self.timeout)
            s.connect((host, port))
            s.sendall(struct.pack("!H", len(data)) + data)
            n = struct.unpack("!H", _recv_exact(s, 2))[0]
            return _recv_exact(s, n)


def _recv_exact(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise OSError("connection closed")
        buf += chunk
    return buf


class DNSServer:
    def __init__(self, addrs, port, handler, workers=32):
        self.addrs = addrs
        self.port = port
        self.handler = handler
        self.pool = ThreadPoolExecutor(max_workers=workers, thread_name_prefix="dns")
        self.threads = []

    def start(self):
        for addr in self.addrs:
            fam = socket.AF_INET6 if ":" in addr else socket.AF_INET
            u = socket.socket(fam, socket.SOCK_DGRAM)
            u.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            u.bind((addr, self.port))
            t = threading.Thread(target=self._udp_loop, args=(u,), daemon=True, name=f"dns-udp-{addr}")
            t.start()
            self.threads.append(t)

            handler = self.handler

            class TCPHandler(socketserver.BaseRequestHandler):
                def handle(self):
                    self.request.settimeout(10)
                    try:
                        while True:
                            n = struct.unpack("!H", _recv_exact(self.request, 2))[0]
                            data = _recv_exact(self.request, n)
                            resp = handler(self.client_address[0], data)
                            if resp is None:
                                return
                            self.request.sendall(struct.pack("!H", len(resp)) + resp)
                    except (OSError, struct.error):
                        return

            server_cls = type("TCPServer", (socketserver.ThreadingTCPServer,),
                              {"address_family": fam, "allow_reuse_address": True, "daemon_threads": True})
            srv = server_cls((addr, self.port), TCPHandler)
            t = threading.Thread(target=srv.serve_forever, daemon=True, name=f"dns-tcp-{addr}")
            t.start()
            self.threads.append(t)
            log.info("DNS listening on %s:%d (udp+tcp)", addr, self.port)

    def _udp_loop(self, sock):
        while True:
            try:
                data, addr = sock.recvfrom(4096)
            except OSError:
                continue
            self.pool.submit(self._udp_one, sock, data, addr)

    def _udp_one(self, sock, data, addr):
        try:
            resp = self.handler(addr[0], data)
            if resp is not None:
                if len(resp) > 1232:
                    # Too big for one datagram without EDNS: truncate, client retries via TCP.
                    req = DNSRecord.parse(data)
                    r = req.reply()
                    r.header.tc = 1
                    resp = r.pack()
                sock.sendto(resp, addr)
        except Exception:  # never let one bad packet kill the server
            log.exception("DNS handler failed for %s", addr[0])
