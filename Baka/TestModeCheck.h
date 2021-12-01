#pragma once
#include "UnhookApi.h" 

#define CODEINTEGRITY_OPTION_TESTSIGN 0x00000002
#define CODEINTEGRITY_OPTION_DEBUGMODE_ENABLED 0x00000080


namespace CheckTestMode
{

	bool CodeIntCheck() {


		SYSTEM_CODEINTEGRITY_INFORMATION cInfo{};
		cInfo.Length = sizeof(cInfo);// set length and don't work without this

		NtQuerySystemInformation(
			SystemCodeIntegrityInformation,
			&cInfo,
			sizeof(cInfo),
			NULL
		);



		auto  bResult = (cInfo.CodeIntegrityOptions & CODEINTEGRITY_OPTION_TESTSIGN)
			|| (cInfo.CodeIntegrityOptions & CODEINTEGRITY_OPTION_DEBUGMODE_ENABLED);

		return bResult;
	}







	bool Registry()
	{

		/*
		You can also detect kernel debugger (read -> https://shhoya.github.io/antikernel_kerneldebugging.html	)

		*/

		bool bRet = false;
		char RegKey[_MAX_PATH] = { 0 };
		DWORD BufSize = _MAX_PATH;
		DWORD dataType = REG_SZ;

		HKEY hKey;


		auto openResult = RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Control", NULL, KEY_QUERY_VALUE, &hKey);
		if (openResult == ERROR_SUCCESS)
		{
			auto valSystemOpthion = RegQueryValueExA(hKey, "SystemStartOptions", NULL, &dataType, (LPBYTE)&RegKey, &BufSize);
			if (valSystemOpthion == ERROR_SUCCESS)
			{
				if (NoCrt::string::strstr(RegKey, "TESTSIGNING"))
					bRet = true;
			}
			RegCloseKey(hKey);
		}


		return bRet;
	}




}