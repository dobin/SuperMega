#include <Windows.h>
#include "peb_lookup.h"

/*
	char load_lib_name1[] = { 'N','t','Q','u','e','r','y','S','y','s','t','e','m','E','n','v','i','r','o','n','m','e','n','t','V','a','l','u','e',0 };
	LPVOID load_lib = get_func_by_name((HMODULE)base1, (LPSTR)load_lib_name1);
	if (!load_lib) {
		return 2;
	}
	*/


int main()
{
	wchar_t kernel32_dll_name[] = { 'k','e','r','n','e','l','3','2','.','d','l','l', 0 };
	LPVOID base = get_module_by_name((const LPWSTR)kernel32_dll_name);
	if (!base) {
		return 1;
	}
	char load_lib_name[] = { 'L','o','a','d','L','i','b','r','a','r','y','A',0 };
	LPVOID load_lib = get_func_by_name((HMODULE)base, (LPSTR)load_lib_name);
	if (!load_lib) {
		return 2;
	}
	char get_proc_name[] = { 'G','e','t','P','r','o','c','A','d','d','r','e','s','s',0 };
	LPVOID get_proc = get_func_by_name((HMODULE)base, (LPSTR)get_proc_name);
	if (!get_proc) {
		return 3;
	}
	HMODULE(WINAPI * _LoadLibraryA)(LPCSTR lpLibFileName) = (HMODULE(WINAPI*)(LPCSTR))load_lib;
	FARPROC(WINAPI * _GetProcAddress)(HMODULE hModule, LPCSTR lpProcName)
		= (FARPROC(WINAPI*)(HMODULE, LPCSTR)) get_proc;


	// ntdll.dll: GetEnvironmentVariableW()
	char GetEnvironmentVariableW_str[] = { 'G','e','t','E','n','v','i','r','o','n','m','e','n','t','V','a','r','i','a','b','l','e','W', 0 };
	int (WINAPI * _GetEnvironmentVariableW)(
		_In_opt_ LPCWSTR lpName,
		_Out_opt_ LPWSTR  lpBuffer,
		_In_ DWORD nSize) = (int (WINAPI*)(
			_In_opt_ LPCWSTR lpName,
			_Out_opt_ LPWSTR  lpBuffer,
			_In_opt_ LPCWSTR,
			_In_ DWORD nSize)) _GetProcAddress((HMODULE)base, GetEnvironmentVariableW_str);
	if (_GetEnvironmentVariableW == NULL) return 4;

	

	wchar_t envVarName[] = {'U','S','E','R','P','R','O','F','I','L','E', 0};
	wchar_t tocheck[] = {'C',':','\\','U','s','e','r','s','\\','h','a','c','k','e','r', 0}; // L"C:\\Users\\hacker"

	//LPCWSTR envVarName = L"USERPROFILE";
	WCHAR buffer[1024];  // NOTE: Do not make it bigger, or we have a __chkstack() dependency!
	DWORD result = ((DWORD(WINAPI*)(LPCWSTR, LPWSTR, DWORD))_GetEnvironmentVariableW)(envVarName, buffer, 1024);
	if (result == 0) {
		return 6;
	}
	if (mystrcmp(buffer, tocheck) != 0) { // escape backslash
		return 6;
	}

	// user32.dll: MessageBoxW()
	char user32_dll_name[] = { 'u','s','e','r','3','2','.','d','l','l', 0 };
	LPVOID u32_dll = _LoadLibraryA(user32_dll_name);
	char message_box_name[] = { 'M','e','s','s','a','g','e','B','o','x','W', 0 };
	int (WINAPI * _MessageBoxW)(
		_In_opt_ HWND hWnd,
		_In_opt_ LPCWSTR lpText,
		_In_opt_ LPCWSTR lpCaption,
		_In_ UINT uType) = (int (WINAPI*)(
			_In_opt_ HWND,
			_In_opt_ LPCWSTR,
			_In_opt_ LPCWSTR,
			_In_ UINT)) _GetProcAddress((HMODULE)u32_dll, message_box_name);
	if (_MessageBoxW == NULL) return 4;

	wchar_t msg_content[] = { 'H','e','l','l','o', ' ', 'W','o','r','l','d','!', 0 };
	wchar_t msg_title[] = { 'D','e','m','o','!', 0 };
	_MessageBoxW(0, msg_title, msg_content, MB_OK);

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