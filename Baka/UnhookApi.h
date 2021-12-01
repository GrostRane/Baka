#pragma once
#include "ApiWrapper.h"
#include "NtApi.h"


namespace ApiUnhook
{

	/*
	
	https://github.com/LazyAhora/khaleesi/blob/e75a5f117eadaa67db178981745370bae3184ca0/khaleesi/Shared/ScyllaHideDetector.cpp#L4
	*/
	__forceinline NTSTATUS RemapModule(const  wchar_t* ModuleName, PVOID* ModuleBaseAddress) noexcept
	{
		NTSTATUS status = STATUS_NOT_SUPPORTED;
		HANDLE sectionHandle = nullptr;
		SIZE_T viewSize = NULL;
		UNICODE_STRING usSectionName{};
		OBJECT_ATTRIBUTES objAttrib{};


		wchar_t buffer[MAX_PATH];
		NoCrt::mem::memset(buffer, 0, MAX_PATH);

		auto str_KnowDll = L"\\KnownDlls\\";


		NoCrt::string::strcatW(buffer, str_KnowDll);

		NoCrt::string::strcatW(buffer, ModuleName);


		usSectionName = ApiWrapper::InitUnicodeString(buffer);


		InitializeObjectAttributes(&objAttrib, &usSectionName, OBJ_CASE_INSENSITIVE, NULL, NULL);


		status = ZwOpenSection(&sectionHandle, SECTION_MAP_READ, &objAttrib);

		if (!NT_SUCCESS(status))
		{
			return status;
		}

		status = ZwMapViewOfSection(sectionHandle, NtCurrentProcess, ModuleBaseAddress, NULL, NULL, nullptr,
			&viewSize, (SECTION_INHERIT)1, NULL, PAGE_READONLY);
		if (!NT_SUCCESS(status))
		{
			return status;
		}

		if (sectionHandle)
		{
			status = NtClose(sectionHandle);
			if (!NT_SUCCESS(status))
			{
				return status;
			}
		}

		return status;
	}

	// If funthion name don't correct,just return 0(we don't use SEH for this)
	__forceinline bool UnhookApi(const wchar_t* nameModule, const char* ApiName)
	{
		bool functhionIsHooked = false;

		auto baseDll = ApiWrapper::GetModuleBaseAddress(nameModule);
		PVOID mapped_dll = nullptr;
		RemapModule(nameModule, &mapped_dll);


		PVOID hooked_func = (PVOID)ApiWrapper::GetProcAddress(baseDll, ApiName);
		auto func_data = ApiWrapper::RtlLookupFunctionEntry((DWORD64)hooked_func, (DWORD64*)&baseDll, nullptr);

		auto original_func = (PVOID)ApiWrapper::GetProcAddress((DWORD64)mapped_dll, ApiName);

		if (!original_func || !func_data) //check for prevent SEH
		{
			ZwUnmapViewOfSection(NtCurrentProcess, mapped_dll);
			return false;
		}

		auto func_size = func_data->EndAddress - func_data->BeginAddress; //get size api 

		auto size_compare = ApiWrapper::RtlCompareMemory(hooked_func, original_func, func_size);// return size


		// restore bytes detect
		if (size_compare != func_size)
		{
			functhionIsHooked = true;
			DWORD oldprotect = 0;

			VirtualProtect(hooked_func, func_size, PAGE_EXECUTE_READWRITE, &oldprotect);

			//RtlCopyMemory 
			NoCrt::mem::memcpy(hooked_func, original_func, func_size);	//write original byte

			size_compare = ApiWrapper::RtlCompareMemory(hooked_func, original_func, func_size);
			if (size_compare == func_size) //all ok
			{
				VirtualProtect(hooked_func, func_size, oldprotect, &oldprotect);
			}
		}



		ZwUnmapViewOfSection(NtCurrentProcess, mapped_dll);
		return functhionIsHooked;
	}


	short GetSyscallNumber(const  wchar_t* nameModule, const char* ApiName)
	{

		short original_syscall = 0;

		auto baseDll = ApiWrapper::GetModuleBaseAddress(nameModule);
		PVOID mapped_dll = nullptr;
		RemapModule(nameModule, &mapped_dll);


		auto original_func = ApiWrapper::GetProcAddress((DWORD64)mapped_dll, ApiName);

		if (!original_func) //check for prevent SEH
		{
			ZwUnmapViewOfSection(NtCurrentProcess, mapped_dll);
			return false;
		}

		original_syscall = *(short*)(original_func + 4);
		ZwUnmapViewOfSection(NtCurrentProcess, mapped_dll);
		return original_syscall;

	}
}
