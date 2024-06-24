
// How many bytes we VirtualProtect
#define VP_SIZE 16

BOOL MyVirtualProtect(
    LPVOID lpAddress,
    SIZE_T dwSize,
    DWORD flNewProtect, 
    PDWORD lpflOldprotect
) {
    char *dest = (char *)lpAddress;

    for(int n=0; n<(dwSize/4096)+1; n++) {
        if (VirtualProtect(dest + (n * 4096), VP_SIZE, flNewProtect, lpflOldprotect) == 0) {
            return FALSE;
        }
    }
    return TRUE;
}
