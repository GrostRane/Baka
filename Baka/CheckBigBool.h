#pragma once

#include "NtApi.h"
#include <iostream>
/*
Just wallking in biigPool

HyperHide:
PoolTag: HyHd

*/


namespace BlackListPool
{

	bool IsHyperHideDebuggingProcess()
	{

		/*
		HyperHide don't clean big pool then he was unload ^_^ and under debugging NonPagedUsed = 384
		*/

		bool bDetect = false;
	
		NTSTATUS status;
      
		 

		auto	bufferPoolInformathion = (PSYSTEM_POOLTAG_INFORMATION)VirtualAlloc(NULL, 1024 * 1024, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE); // Allocate memory for the module list

        if (!bufferPoolInformathion)
        {
            return 0;
        }
		status = NtQuerySystemInformation(SystemPoolTagInformation, bufferPoolInformathion, 1024 * 1024, NULL);
        if (!NT_SUCCESS(status )) 
        {
          
            VirtualFree(bufferPoolInformathion, 0, MEM_RELEASE);
            return 0;
        }

		PSYSTEM_POOLTAG_INFORMATION sysPoolTagInfo = (PSYSTEM_POOLTAG_INFORMATION)bufferPoolInformathion;
		PSYSTEM_POOLTAG sysPoolTag = (PSYSTEM_POOLTAG)&sysPoolTagInfo->TagInfo->Tag;
		for (ULONG i = 0; i < sysPoolTagInfo->Count; i++)
		{
			
			
			
			if (NoCrt::string::stricmp((char *)sysPoolTag->Tag, "Hyhd") ==0 )
			{
				if (sysPoolTag->PagedAllocs || sysPoolTag->NonPagedAllocs)
				{
					if (sysPoolTag->NonPagedUsed > 10 || sysPoolTag->PagedUsed > 10)//check for detect only for debugging 
					{

						bDetect = true;
					}
				}
			}

			
			sysPoolTag++;
		}





        VirtualFree(bufferPoolInformathion, 0, MEM_RELEASE);




		return bDetect;

	}
}