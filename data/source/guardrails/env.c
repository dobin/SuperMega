

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


int executionguardrail() {
	// Execution Guardrail: Env Check
	wchar_t envVarName[] = L"USERPROFILE";
	wchar_t tocheck[] = L"C:\\Users\\";
	WCHAR buffer[1024];  // NOTE: Do not make it bigger, or we have a __chkstack() dependency!
	DWORD result = GetEnvironmentVariableW(envVarName, buffer, 1024);
	if (result == 0) {
		return 6;
	}
	if (mystrcmp(buffer, tocheck) != 0) { 
		return 6;
	}
    return 0;
}

