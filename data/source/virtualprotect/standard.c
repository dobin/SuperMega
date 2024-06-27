
BOOL MyVirtualProtect(
    LPVOID lpAddress,
    SIZE_T dwSize,
    DWORD flNewProtect, 
    PDWORD lpflOldprotect
) {
    return VirtualProtect(lpAddress, dwSize, flNewProtect, lpflOldprotect);
}
