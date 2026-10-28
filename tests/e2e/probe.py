"""Network probe run inside an agent container; prints one JSON result.

  probe.py dns NAME
  probe.py http HOST_OR_IP [PORT]
  probe.py tcp HOST_OR_IP PORT
  probe.py udp HOST_OR_IP PORT
  probe.py stream HOST_OR_IP PORT SECONDS   (reads a long-lived stream)
  probe.py dnsdirect NAME SERVER            (raw query to a chosen resolver)
"""

import json
import socket
import struct
import sys
import time


def out(**kw):
    print(json.dumps(kw))
    sys.exit(0)


def err_name(e):
    return type(e).__name__ + (f"[{e.errno}]" if getattr(e, "errno", None) else "") + f": {e}"


def main():
    kind, target = sys.argv[1], sys.argv[2]
    t0 = time.time()
    try:
        if kind == "dns":
            ips = sorted({a[4][0] for a in socket.getaddrinfo(target, 80, socket.AF_INET)})
            out(ok=True, ips=ips)
        if kind == "dnsdirect":
            q = struct.pack("!HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)
            q += b"".join(bytes([len(p)]) + p.encode() for p in target.split(".")) + b"\0" + struct.pack("!HH", 1, 1)
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(3)
            s.sendto(q, (sys.argv[3], 53))
            resp, src = s.recvfrom(512)
            rcode = resp[3] & 0x0F
            an = struct.unpack("!H", resp[6:8])[0]
            ips = []
            if an:
                ips.append(socket.inet_ntoa(resp[-4:]))
            out(ok=rcode == 0, rcode=rcode, ips=ips, answered_from=src[0])
        port = int(sys.argv[3]) if len(sys.argv) > 3 else 80
        if kind == "http":
            s = socket.create_connection((target, port), timeout=4)
            s.sendall(f"GET / HTTP/1.0\r\nHost: {target}\r\n\r\n".encode())
            data = s.recv(4096).decode(errors="replace")
            s.close()
            out(ok=data.startswith("HTTP/1.0 200") or data.startswith("HTTP/1.1 200"),
                body=data.split("\r\n\r\n", 1)[-1].strip(), ms=int((time.time() - t0) * 1000))
        if kind == "tcp":
            s = socket.create_connection((target, port), timeout=4)
            s.close()
            out(ok=True, ms=int((time.time() - t0) * 1000))
        if kind == "udp":
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(3)
            s.connect((target, port))
            s.send(b"ping")
            out(ok=s.recv(64) == b"ping")
        if kind == "stream":
            secs = float(sys.argv[4])
            s = socket.create_connection((target, port), timeout=4)
            s.settimeout(3)
            lines, end = 0, time.time() + secs
            try:
                while time.time() < end:
                    chunk = s.recv(4096)
                    if not chunk:
                        out(ok=False, lines=lines, error="closed by peer", after=round(time.time() - t0, 2))
                    lines += chunk.count(b"\n")
            except OSError as e:
                out(ok=False, lines=lines, error=err_name(e), after=round(time.time() - t0, 2))
            out(ok=True, lines=lines)
    except OSError as e:
        out(ok=False, error=err_name(e), ms=int((time.time() - t0) * 1000))


main()
