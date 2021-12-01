#pragma once
#include "UnhookApi.h"



EXTERN_C void SetAddressNtApi(DWORD64 addressNtApi);

EXTERN_C void  SetSyscallCallNumber(short syscallNumber);

EXTERN_C void  CallSyscall();


namespace AntiDebug
{

	/*
	VMP use syscall for antidebug in exe but we will be use syscall in ntdll!!

	English ->  https://lifeinhex.com/use-of-syscall-and-sysenter-in-vmprotect-3-1/

	RU -> https://yougame.biz/threads/154142/
	*/
	namespace VMPEx
	{

		bool IsDebugObject() {

			HANDLE hDebugObject = NULL;
			bool bDetect = FALSE;

			auto addressNtAapi = ApiWrapper::GetProcAddress(ApiWrapper::GetModuleBaseAddress(L"ntdll.dll"), "ZwQueryEvent");
			auto originalSyscall = ApiUnhook::GetSyscallNumber(L"ntdll.dll", "NtQueryInformationProcess");

			SetAddressNtApi(addressNtAapi + 0x12);
			SetSyscallCallNumber(originalSyscall );

			auto NtQueryInformationProcess = (t_NtQueryInformationProcess)CallSyscall;
			auto status = NtQueryInformationProcess(NtCurrentProcess, ProcessDebugObjectHandle, &hDebugObject, sizeof(ULONG) * 2, NULL);



			if (status == 0x00000000 && hDebugObject)
				bDetect = TRUE;
			return bDetect;

		}


		bool IsProcessDebugPort()
		{

			bool bDetect = FALSE;

			DWORD64 IsRemotePresent = 0;



			auto addressNtAapi = ApiWrapper::GetProcAddress(ApiWrapper::GetModuleBaseAddress(L"ntdll.dll"), "ZwQueryEvent");
			auto originalSyscall = ApiUnhook::GetSyscallNumber(L"ntdll.dll", "NtQueryInformationProcess");

			SetAddressNtApi(addressNtAapi + 0x12);
			SetSyscallCallNumber(originalSyscall);

			auto NtQueryInformationProcess = (t_NtQueryInformationProcess)CallSyscall;

			auto status = NtQueryInformationProcess(NtCurrentProcess, ProcessDebugPort, &IsRemotePresent, sizeof(ULONG) * 2, NULL);
			if (status == 0x00000000 && IsRemotePresent != 0)
				bDetect = TRUE;


			return bDetect;


		}




	}



	namespace Util
	{


		bool BreakpointCheck(const wchar_t* NameModule, const char* ApiName)
		{

			auto baseNtDll = ApiWrapper::GetModuleBaseAddress(NameModule);

			auto addressBase = ApiWrapper::GetProcAddress(baseNtDll, ApiName);


			auto fucthionData = ApiWrapper::RtlLookupFunctionEntry((DWORD64)addressBase, (DWORD64*)&baseNtDll, nullptr);
			auto sizeFuncthion = fucthionData->EndAddress - fucthionData->BeginAddress; //get size functhion
			bool bDetect = false;

			for (size_t i = 0; i < sizeFuncthion; i++)
			{
				if (*(byte*)(addressBase + i) == 0x0f && *(byte*)(addressBase + i + 1) == 0xb)//ud2 breakpoint
				{
					bDetect = true;

				}
				else if (*(byte*)(addressBase + i) == 0xcd && *(byte*)(addressBase + i + 1) == 0x3)//long int 
				{
					bDetect = true;
				}
				else if (*(byte*)(addressBase + i) == 0xcc || *(byte*)(addressBase + i) == 0x90)//check nop and int 3 breakpoint
				{
					bDetect = true;
				}


			}

			return bDetect;


		}


		bool BuildNumberIsHooked()
		{

			bool bDeect = false;
			if (ApiWrapper::GetWindowsNumber() >= 10)
			{

				bDeect = ApiWrapper::GetNumberBuild() != ApiWrapper::PEBGetNumberBuild();

			}

			return bDeect;
		}

	}
}