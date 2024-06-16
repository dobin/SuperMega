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