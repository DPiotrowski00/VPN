import ctypes
import ctypes.wintypes as wt
import traceback
import socket
import sys
import os
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

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

adapter = wintun.WintunCreateAdapter("VPN_CLIENT", "Example", None)
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

            src_ip = socket.inet_ntoa(src_ip_bytes)
            dest_ip = socket.inet_ntoa(dst_ip_bytes)

            if (not (dest_ip == "224.0.0.22" or dest_ip == "121.105.102.222" or dest_ip == "212.68.175.117")):
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