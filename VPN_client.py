import ctypes
import ctypes.wintypes as wt
import traceback
import ipaddress
import socket
import sys
import os
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

def isInSameSubnet(addr_a, addr_b, subnet_mask):
    addr_a_int = int(ipaddress.IPv4Address(addr_a))
    addr_b_int = int(ipaddress.IPv4Address(addr_b))
    subnet_mask_int = int(ipaddress.IPv4Address(subnet_mask))

    subnet_a = ipaddress.IPv4Address(addr_a_int & subnet_mask_int)
    subnet_b = ipaddress.IPv4Address(addr_b_int & subnet_mask_int)

    # print(f"IP a: {addr_a}, IP b: {addr_b}, Mask: {subnet_mask}\nSubnet a: {subnet_a}, Subnet b: {subnet_b}\nIn Same subnet: {subnet_a == subnet_b}")

    if (subnet_a == subnet_b):
        return True
    else:
        return False

UDP_PORT = 51820
SERVER_IP = "10.0.30.46"
PSK = b"0123456789ABCDEF0123456789ABCDEF"
MAX_PACK = 65535

aead = ChaCha20Poly1305(PSK)

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.setblocking(False)
server_address = (SERVER_IP, UDP_PORT)

dll_path = os.path.join(os.path.dirname(__file__), "wintun.dll")
wintun = ctypes.WinDLL(dll_path)

WINTUN_ADAPTER_HANDLE = ctypes.c_void_p
WINTUN_SESSION_HANDLE = ctypes.c_void_p

wintun.WintunCreateAdapter.restype = WINTUN_ADAPTER_HANDLE
wintun.WintunCreateAdapter.argtypes = [wt.LPCWSTR, wt.LPCWSTR, wt.LPCWSTR]

wintun.WintunCloseAdapter.restype = None
wintun.WintunCloseAdapter.argtypes = [WINTUN_ADAPTER_HANDLE]

wintun.WintunStartSession.restype = WINTUN_SESSION_HANDLE
wintun.WintunStartSession.argtypes = [WINTUN_ADAPTER_HANDLE, ctypes.c_uint32]

wintun.WintunEndSession.restype = None
wintun.WintunEndSession.argtypes = [WINTUN_SESSION_HANDLE]

wintun.WintunReceivePacket.restype = ctypes.POINTER(ctypes.c_ubyte)
wintun.WintunReceivePacket.argtypes = [WINTUN_SESSION_HANDLE, ctypes.POINTER(ctypes.c_uint32)]

wintun.WintunReleaseReceivePacket.restype = None
wintun.WintunReleaseReceivePacket.argtypes = [WINTUN_SESSION_HANDLE, ctypes.POINTER(ctypes.c_ubyte)]

adapter = wintun.WintunCreateAdapter("VPN_CLIENT", "VPN_CLIENT", None)
if not adapter:
    print("Failed to create adapter (need admin rights + wintun.dll present)")
    sys.exit(1) 

session = wintun.WintunStartSession(adapter, 0x200000)

print("Listening for packets... (Ctrl+C to stop)")

try:
    while True:
        size = ctypes.c_uint32()
        pkt = wintun.WintunReceivePacket(session, ctypes.byref(size))
        if pkt:
            data = bytes(ctypes.cast(pkt, ctypes.POINTER(ctypes.c_ubyte * size.value)).contents)
            
            src_ip_bytes = data[12:16]
            dst_ip_bytes = data[16:20]
            ip_version = data[0] >> 4
            protocol = data[9]

            src_ip = socket.inet_ntoa(src_ip_bytes)
            dest_ip = socket.inet_ntoa(dst_ip_bytes)

            ihl = (data[0] & 0x0F) * 4
            src_port = int.from_bytes(data[ihl:ihl+2], "big")
            dest_port = int.from_bytes(data[ihl+2:ihl+4], "big")

            if ipaddress.IPv4Address(src_ip).is_multicast or ipaddress.IPv4Address(dest_ip).is_multicast:
                continue

            if protocol in (6, 17) and (dest_port not in (80, 443) and src_port not in (80, 443)):
                continue

            if (ip_version != 4):
                continue

            if protocol not in (1, 6, 17):
                continue

            if (True):
                print(f"SRC_IP: {src_ip}, DEST_IP: {dest_ip}")
                
                print (f"Got packet ({size.value} bytes):", data[:20].hex(), "...", f"Forwarding it to the server")
                nonce = os.urandom(12)
                ciphertext = aead.encrypt(nonce, data, b"VPN")
                sock.sendto(nonce + ciphertext, server_address)
                wintun.WintunReleaseReceivePacket(session, pkt)

                try:
                    pkt, addr = sock.recvfrom(MAX_PACK)
                    nonce, ct = pkt[:12], pkt[12:]
                    message = aead.decrypt(nonce, ct, b"VPN")

                    print(f"Got response: {message[:20].hex()}")
                except BlockingIOError:
                    pass

except KeyboardInterrupt:
    pass
except Exception as e:
    print(f"An error occured: {e}")
    traceback.print_exc()

wintun.WintunEndSession(session)
wintun.WintunCloseAdapter(adapter)