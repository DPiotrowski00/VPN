import ctypes
import ctypes.wintypes as wt
import socket
import sys
import os
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

UDP_PORT = 51820
PSK = b"0123456789ABCDEF0123456789ABCDEF"
MAX_PACK = 65535

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

adapter = wintun.WintunCreateAdapter("VPN_SERVER", "Example", None)
if not adapter:
    print("Failed to create adapter (need admin rights + wintun.dll present)")
    sys.exit(1) 

session = wintun.WintunStartSession(adapter, 0x200000)
print("Wintun adapter created, listening for VPN packets...")

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(("0.0.0.0", UDP_PORT))
sock.setblocking(False)
print(f"Server listening on UDP port {UDP_PORT}")

aead = ChaCha20Poly1305(PSK)

last_client = None

try:
    while True:
        try:
            pkt, addr = sock.recvfrom(MAX_PACK)
            last_client = addr
            nonce, ct = pkt[:12], pkt[12:]
            message = aead.decrypt(nonce, ct, b"VPN")

            size = ctypes.c_uint32()
            pkt = wintun.WintunReceivePacket(session, ctypes.byref(size))
            if pkt:
                data = bytes(ctypes.cast(pkt, ctypes.POINTER(ctypes.c_ubyte * size.value)).contents)
                nonce = os.urandom(12)
                ciphertext = aead.encrypt(nonce, data, b"VPN")
                sock.sendto(nonce + ciphertext, last_client)
                wintun.WintunReleaseReceivePacket(session, pkt)
        except BlockingIOError:
            pass
        except Exception as e:
            print(f"UDP receive error {e}")
except KeyboardInterrupt:
    print("Exiting...")
finally:
    wintun.WintunEndSession(session)
    wintun.WintunCloseAdapter(adapter)
    sock.Close()