import ctypes
import ctypes.wintypes as wt
import sys
import os

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

adapter = wintun.WintunCreateAdapter("MyVPN", "Example", None)
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
            print (f"Got packet ({size.value} bytes):", data[:20].hex(), "...")
            wintun.WintunReleaseReceivePacket(session, pkt)
except KeyboardInterrupt:
    pass

wintun.WintunEndSession(session)
wintun.WintunCloseAdapter(adapter)