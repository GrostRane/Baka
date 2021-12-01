#pragma once
#include "WindowsCode.h"

namespace ApiWrapper
{
    __forceinline    UNICODE_STRING InitUnicodeString(static const wchar_t* string_to_init)
    {

        UNICODE_STRING stringInit;
        if (string_to_init)
        {
            stringInit.Length = NoCrt::string::wstrlen(string_to_init) * sizeof(wchar_t);
            stringInit.MaximumLength = stringInit.Length + 2;
            stringInit.Buffer = (wchar_t*)string_to_init;
        }
        return stringInit;

    }





    __forceinline  int CompareUnicodeString(UNICODE_STRING str_1, UNICODE_STRING str_2, bool case_int_sensitive = false)
    {

        //return 0 if equal
        if (case_int_sensitive)
        {
            return NoCrt::string::wstrcmp(str_1.Buffer, str_2.Buffer);
        }
        else
        {
            return NoCrt::string::wstricmp(str_1.Buffer, str_2.Buffer);
        }

    }



    __forceinline  void FreeUnicodeString(UNICODE_STRING& str)
    {
        //just set buffer/Length

        /*
        in disassembly  RtlFreeUnicodeString use ExFreePoolWithTag wrf?
        */
        str.Buffer = 0;
        str.Length = 0;
        str.MaximumLength = 0;
    }

    __forceinline void NTAPI MyMoveMemory(
        PVOID Destination,
        CONST VOID* Source,
        SIZE_T Length
    )
    {
        NoCrt::mem::memmove(Destination, Source, Length);
    }


    SIZE_T  NTAPI   RtlCompareMemory
    (const VOID* Source1,
        const VOID* Source2,
        SIZE_T Length)
    {
        SIZE_T i;
        for (i = 0; (i < Length) && (((PUCHAR)Source1)[i] == ((PUCHAR)Source2)[i]); i++)
            ;

        return i;
    }

    SIZE_T
        NTAPI
        RtlCompareMemoryUlong(IN PVOID Source,
            IN SIZE_T Length,
            IN ULONG Value)
    {
        PULONG ptr = (PULONG)Source;
        ULONG_PTR len = Length / sizeof(ULONG);
        ULONG_PTR i;

        for (i = 0; i < len; i++)
        {
            if (*ptr != Value)
                break;

            ptr++;
        }

        return (SIZE_T)((PCHAR)ptr - (PCHAR)Source);
    }




    __forceinline   VOID  NTAPI   MyZeroMemory
    (
        PVOID Destination,
        SIZE_T Length)
    {
        NoCrt::mem::memset(Destination, Length, 0);
    }

    __forceinline  VOID NTAPI FillMemoryUlonglong
    (
        PVOID Destination,
        SIZE_T Length,
        ULONGLONG Fill)
    {
        PULONGLONG Dest = (PULONGLONG)Destination;
        SIZE_T Count = Length / sizeof(ULONGLONG);

        while (Count > 0)
        {
            *Dest = Fill;
            Dest++;
            Count--;
        }
    }


    DWORD64 GetModuleBaseAddress(const wchar_t* modName)
    {

        //   VM_DOLPHIN_BLACK_START
        LDR_DATA_TABLE_ENTRY* modEntry = nullptr;





#ifdef _WIN64
        PEB* peb = (PEB*)__readgsqword(0x60);

#else
        PEB* peb = (PEB*)__readfsdword(0x30);
#endif



        LIST_ENTRY head = peb->Ldr->InMemoryOrderModuleList;

        LIST_ENTRY curr = head;

        for (auto curr = head; curr.Flink != &peb->Ldr->InMemoryOrderModuleList; curr = *curr.Flink)
        {
            LDR_DATA_TABLE_ENTRY* mod = (LDR_DATA_TABLE_ENTRY*)CONTAINING_RECORD(curr.Flink, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);

            if (mod->BaseDllName.Buffer)
            {
                if (NoCrt::string::wstrstr(modName, mod->BaseDllName.Buffer))
                {
                    //_wcsicmp
                    modEntry = mod;
                    break;
                }
            }
        }
        //VM_DOLPHIN_BLACK_END
        return (DWORD64)modEntry->DllBase;

    }



    DWORD64 GetProcAddress(DWORD64 base, const char* apiNAME)
    {

        if (!base)
            return 0;
        auto pDOS = (PIMAGE_DOS_HEADER)base;
        if (pDOS->e_magic != IMAGE_DOS_SIGNATURE)
            return 0;
        auto pNT = (PIMAGE_NT_HEADERS)(base + (DWORD)pDOS->e_lfanew);
        if (pNT->Signature != IMAGE_NT_SIGNATURE)
            return 0;
        auto pExport = (PIMAGE_EXPORT_DIRECTORY)(base + pNT->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
        if (!pExport)
            return 0;
        auto names = (PDWORD)(base + pExport->AddressOfNames);
        auto ordinals = (PWORD)(base + pExport->AddressOfNameOrdinals);
        auto functions = (PDWORD)(base + pExport->AddressOfFunctions);

        for (int i = 0; i < pExport->NumberOfFunctions; ++i) {
            auto name = (LPCSTR)(base + names[i]);
            if (!NoCrt::string::strcmp(name, apiNAME))
                return base + functions[ordinals[i]];
        }
    }

    // Get Windows number by    KUSER_SHARED_DATA(support on Windows XP or leater)
    __forceinline  int GetWindowsNumber()
    {

        auto NtMajorVersion = *(BYTE*)0x7FFE026C;
        if (NtMajorVersion == 10)
        {
            auto NtBuildNumber = *(int*)0x7FFE0260;//NtBuildNumber
            if (NtBuildNumber > 22000)
            {
                return WINDOWS_11;
            }
            return WINDOWS_10;
        }
        else if (NtMajorVersion == 5)
        {
            return WINDOWS_XP;//Windows XP
        }
        else if (NtMajorVersion == 6)
        {
            /*
            https://www.godeye.club/2021/06/03/002-mhyprot-insider-callbacks.html
            */
            switch (*(BYTE*)0x7FFE0270)  //0x7FFE0270 NtMinorVersion
            {
            case 1:
                return WINDOWS_7;//windows 7
            case 2:
                return WINDOWS_8; //window 8
            case 3:
                return WINDOWS_8_1; //windows 8.1
            default:
                return 0;
            }

        }

        return 0;
    }


    //Get windows numbe build by NtBuildNumber in KUSER_SHARED_DATA(support in Windows 10 or leater)
    __forceinline   int GetNumberBuild()
    {
        if (GetWindowsNumber() >= WINDOWS_10)
        {
            return *(int*)0x00000007FFE0260; //NtBuildNumber

        }
#ifdef _WIN64
        return *(int*)(__readgsqword(0x60) + 0x120);

#else
        return *(int*)(__readfsdword(0x30) + 0xAC);
#endif 
    }

    //Get OSBuildNumber in PEB
    __forceinline  int PEBGetNumberBuild()
    {



#ifdef _WIN64
        return *(int*)(__readgsqword(0x60) + 0x120);

#else
        return *(int*)(__readfsdword(0x30) + 0xAC);
#endif 

    }








    __forceinline PRUNTIME_FUNCTION
        NTAPI
        RtlLookupFunctionEntry(
            IN DWORD64 ControlPc,
            OUT PDWORD64 ImageBase,
            OUT PUNWIND_HISTORY_TABLE HistoryTable)
    {
        PRUNTIME_FUNCTION FunctionTable, FunctionEntry;
        ULONG TableLength;
        ULONG IndexLo, IndexHi, IndexMid;

        /* Find the corresponding table */
        FunctionTable = WindowsCode::RtlLookupFunctionTable(ControlPc, ImageBase, &TableLength);

        /* Fail, if no table is found */
        if (!FunctionTable)
        {
            return NULL;
        }

        /* Use relative virtual address */
        ControlPc -= *ImageBase;

        /* Do a binary search */
        IndexLo = 0;
        IndexHi = TableLength;
        while (IndexHi > IndexLo)
        {
            IndexMid = (IndexLo + IndexHi) / 2;
            FunctionEntry = &FunctionTable[IndexMid];

            if (ControlPc < FunctionEntry->BeginAddress)
            {
                /* Continue search in lower half */
                IndexHi = IndexMid;
            }
            else if (ControlPc >= FunctionEntry->EndAddress)
            {
                /* Continue search in upper half */
                IndexLo = IndexMid + 1;
            }
            else
            {
                /* ControlPc is within limits, return entry */
                return FunctionEntry;
            }
        }

        /* Nothing found, return NULL */
        return NULL;
    }


}

