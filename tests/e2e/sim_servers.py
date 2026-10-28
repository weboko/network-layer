"""Servers for the simulated internet (stdlib only, runs in the test netns).

DNS (203.0.113.53:53, UDP) answers A records for NAMES, NXDOMAIN otherwise.
HTTP on port 80 of every address returns "hello from <ip>".
203.0.113.14:9000 streams a line every 200 ms until the client goes away.
203.0.113.15:5000/udp echoes datagrams.
"""

import socket
import socketserver
import struct
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

NAMES = {
    "allowed.test": "203.0.113.10",
    "other.test": "203.0.113.11",
    "blocked.test": "203.0.113.12",
    "stream.test": "203.0.113.14",
    "udp.test": "203.0.113.15",
    "cn-host.test": "203.0.113.16",
    "shared1.test": "203.0.113.17",
    "shared2.test": "203.0.113.17",
    "a.wild.test": "203.0.113.18",
    "b.wild.test": "203.0.113.19",
    "evil.test": "203.0.113.20",
}
HTTP_IPS = [f"203.0.113.{i}" for i in range(10, 21)]


def dns_server():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("203.0.113.53", 53))
    while True:
        data, addr = s.recvfrom(512)
        try:
            tid, flags, qd = struct.unpack("!HHH", data[:6])
            i, labels = 12, []
            while data[i]:
                n = data[i]
                labels.append(data[i + 1:i + 1 + n].decode())
                i += n + 1
            qtype = struct.unpack("!H", data[i + 1:i + 3])[0]
            question = data[12:i + 5]
            name = ".".join(labels).lower()
            print("query", name, flush=True)  # lets tests prove what reached "upstream"
            ip = NAMES.get(name)
            if ip is None:
                resp = struct.pack("!HHHHHH", tid, 0x8183, 1, 0, 0, 0) + question
            elif qtype == 1:
                ans = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) + socket.inet_aton(ip)
                resp = struct.pack("!HHHHHH", tid, 0x8180, 1, 1, 0, 0) + question + ans
            else:
                resp = struct.pack("!HHHHHH", tid, 0x8180, 1, 0, 0, 0) + question
            s.sendto(resp, addr)
        except Exception as e:  # malformed query: ignore
            print("dns error", e, flush=True)


class Server(ThreadingHTTPServer):
    def server_bind(self):
        # HTTPServer.server_bind calls getfqdn(), a reverse lookup that stalls
        # for seconds per address when no resolver answers.
        socketserver.TCPServer.server_bind(self)
        self.server_name, self.server_port = self.server_address[:2]


class Hello(BaseHTTPRequestHandler):
    def do_GET(self):
        body = f"hello from {self.server.server_address[0]}\n".encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


def stream_server():
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("203.0.113.14", 9000))
    s.listen(16)

    def serve(c):
        import time
        try:
            n = 0
            while True:
                c.sendall(f"tick {n}\n".encode())
                n += 1
                time.sleep(0.2)
        except OSError:
            c.close()

    while True:
        c, _ = s.accept()
        threading.Thread(target=serve, args=(c,), daemon=True).start()


def udp_echo():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("203.0.113.15", 5000))
    while True:
        data, addr = s.recvfrom(2048)
        s.sendto(data, addr)


if __name__ == "__main__":
    for ip in HTTP_IPS:
        srv = Server((ip, 80), Hello)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
    threading.Thread(target=stream_server, daemon=True).start()
    threading.Thread(target=udp_echo, daemon=True).start()
    print("sim servers up", flush=True)
    dns_server()
