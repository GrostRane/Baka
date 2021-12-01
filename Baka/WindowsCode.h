#pragma once
#include "NOCrt.h"

namespace WindowsCode
{


    __forceinline NTSTATUS NTAPI
        RtlpImageNtHeaderEx(
            _In_ ULONG Flags,
            _In_ PVOID Base,
            _In_ ULONG64 Size,
            _Out_ PIMAGE_NT_HEADERS* OutHeaders)
    {
        PIMAGE_NT_HEADERS NtHeaders;
        PIMAGE_DOS_HEADER DosHeader;
        BOOLEAN WantsRangeCheck;
        ULONG NtHeaderOffset;

        /* You must want NT Headers, no? */
        if (OutHeaders == NULL)
        {
            return STATUS_INVALID_PARAMETER;
        }

        /* Assume failure */
        *OutHeaders = NULL;

        /* Validate Flags */
        if (Flags & ~RTL_IMAGE_NT_HEADER_EX_FLAG_NO_RANGE_CHECK)
        {
            return STATUS_INVALID_PARAMETER;
        }

        /* Validate base */
        if ((Base == NULL) || (Base == (PVOID)-1))
        {
            return STATUS_INVALID_PARAMETER;
        }

        /* Check if the caller wants range checks */
        WantsRangeCheck = !(Flags & RTL_IMAGE_NT_HEADER_EX_FLAG_NO_RANGE_CHECK);
        if (WantsRangeCheck)
        {
            /* Make sure the image size is at least big enough for the DOS header */
            if (Size < sizeof(IMAGE_DOS_HEADER))
            {
                return STATUS_INVALID_IMAGE_FORMAT;
            }
        }

        /* Check if the DOS Signature matches */
        DosHeader = (PIMAGE_DOS_HEADER)Base;
        if (DosHeader->e_magic != IMAGE_DOS_SIGNATURE)
        {
            /* Not a valid COFF */

            return STATUS_INVALID_IMAGE_FORMAT;
        }

        /* Get the offset to the NT headers (and copy from LONG to ULONG) */
        NtHeaderOffset = DosHeader->e_lfanew;

        /* The offset must not be larger than 256MB, as a hard-coded check.
           In Windows this check is only done in user mode, not in kernel mode,
           but it shouldn't harm to have it anyway. Note that without this check,
           other overflow checks would become necessary! */
        if (NtHeaderOffset >= (256 * 1024 * 1024))
        {
            /* Fail */
            return STATUS_INVALID_IMAGE_FORMAT;
        }

        /* Check if the caller wants validation */
        if (WantsRangeCheck)
        {
            /* Make sure the file header fits into the size */
            if ((NtHeaderOffset +
                RTL_SIZEOF_THROUGH_FIELD(IMAGE_NT_HEADERS, FileHeader)) >= Size)
            {
                return STATUS_INVALID_IMAGE_FORMAT;
            }
        }

        /* Now get a pointer to the NT Headers */
        NtHeaders = (PIMAGE_NT_HEADERS)((ULONG_PTR)Base + NtHeaderOffset);

        /* Check if the mapping is in user space */
        if (Base <= (PVOID)0xFFFFFFFF)
        {
            /* Make sure we don't overflow into kernel space */
            if ((PVOID)(NtHeaders + 1) > (PVOID)0xFFFFFFFF)
            {
                return STATUS_INVALID_IMAGE_FORMAT;
            }
        }

        /* Verify the PE Signature */
        if (NtHeaders->Signature != IMAGE_NT_SIGNATURE)
        {
            /* Fail */
            return STATUS_INVALID_IMAGE_FORMAT;
        }

        /* Now return success and the NT header */
        *OutHeaders = NtHeaders;
        return STATUS_SUCCESS;
    }




    __forceinline  NTSTATUS NTAPI
        RtlImageNtHeaderEx(
            _In_ ULONG Flags,
            _In_ PVOID Base,
            _In_ ULONG64 Size,
            _Out_ PIMAGE_NT_HEADERS* OutHeaders)
    {
        return RtlpImageNtHeaderEx(Flags, Base, Size, OutHeaders);
    }



    __forceinline  PIMAGE_NT_HEADERS
        NTAPI
        RtlImageNtHeader(IN PVOID Base)
    {
        PIMAGE_NT_HEADERS NtHeader;

        /* Call the new API */
        RtlImageNtHeaderEx(RTL_IMAGE_NT_HEADER_EX_FLAG_NO_RANGE_CHECK,
            Base,
            0,
            &NtHeader);
        return NtHeader;
    }














    __forceinline PIMAGE_SECTION_HEADER
        RtlSectionTableFromVirtualAddress(
            IN PIMAGE_NT_HEADERS NtHeaders,
            IN PVOID Base,
            IN ULONG Address
        )

        /*++
        Routine Description:
            This function locates a VirtualAddress within the image header
            of a file that is mapped as a file and returns a pointer to the
            section table entry for that virtual address
        Arguments:
            NtHeaders - Supplies the pointer to the image or data file.
            Base - Supplies the base of the image or data file.
            Address - Supplies the virtual address to locate.
        Return Value:
            NULL - The file does not contain data for the specified directory entry.
            NON-NULL - Returns the pointer of the section entry containing the data.
        --*/

    {
        ULONG i;
        PIMAGE_SECTION_HEADER NtSection;

        NtSection = IMAGE_FIRST_SECTION(NtHeaders);
        for (i = 0; i < NtHeaders->FileHeader.NumberOfSections; i++) {
            if ((ULONG)Address >= NtSection->VirtualAddress &&
                (ULONG)Address < NtSection->VirtualAddress + NtSection->SizeOfRawData
                ) {
                return NtSection;
            }
            ++NtSection;
        }

        return NULL;
    }

    __forceinline PVOID
        RtlAddressInSectionTable(
            IN PIMAGE_NT_HEADERS NtHeaders,
            IN PVOID Base,
            IN ULONG Address
        )

        /*++
        Routine Description:
            This function locates a VirtualAddress within the image header
            of a file that is mapped as a file and returns the seek address
            of the data the Directory describes.
        Arguments:
            NtHeaders - Supplies the pointer to the image or data file.
            Base - Supplies the base of the image or data file.
            Address - Supplies the virtual address to locate.
        Return Value:
            NULL - The file does not contain data for the specified directory entry.
            NON-NULL - Returns the address of the raw data the directory describes.
        --*/

    {
        PIMAGE_SECTION_HEADER NtSection;

        NtSection = RtlSectionTableFromVirtualAddress(NtHeaders,
            Base,
            Address
        );
        if (NtSection != NULL) {
            return(((PCHAR)Base + ((ULONG_PTR)Address - NtSection->VirtualAddress) + NtSection->PointerToRawData));
        }
        else {
            return(NULL);
        }
    }



    __forceinline PVOID RtlpImageDirectoryEntryToData32(
        IN PVOID Base,
        IN BOOLEAN MappedAsImage,
        IN USHORT DirectoryEntry,
        OUT PULONG Size,
        PIMAGE_NT_HEADERS32 NtHeaders
    )
    {
        ULONG DirectoryAddress;

        if (DirectoryEntry >= NtHeaders->OptionalHeader.NumberOfRvaAndSizes) {
            return(NULL);
        }

        if (!(DirectoryAddress = NtHeaders->OptionalHeader.DataDirectory[DirectoryEntry].VirtualAddress)) {
            return(NULL);
        }

        if (Base < (PVOID)0xFFFFFFFF) {
            if ((PVOID)((PCHAR)Base + DirectoryAddress) >= (PVOID)0xFFFFFFFF) {
                return(NULL);
            }
        }

        *Size = NtHeaders->OptionalHeader.DataDirectory[DirectoryEntry].Size;
        if (MappedAsImage || DirectoryAddress < NtHeaders->OptionalHeader.SizeOfHeaders) {
            return((PVOID)((PCHAR)Base + DirectoryAddress));
        }

        return(RtlAddressInSectionTable((PIMAGE_NT_HEADERS)NtHeaders, Base, DirectoryAddress));
    }


    __forceinline PVOID RtlpImageDirectoryEntryToData64
    (
        IN PVOID Base,
        IN BOOLEAN MappedAsImage,
        IN USHORT DirectoryEntry,
        OUT PULONG Size,
        PIMAGE_NT_HEADERS64 NtHeaders
    )
    {
        ULONG DirectoryAddress;

        if (DirectoryEntry >= NtHeaders->OptionalHeader.NumberOfRvaAndSizes) {
            return(NULL);
        }

        if (!(DirectoryAddress = NtHeaders->OptionalHeader.DataDirectory[DirectoryEntry].VirtualAddress)) {
            return(NULL);
        }

        if (Base < (PVOID)0xFFFFFFFF) {
            if ((PVOID)((PCHAR)Base + DirectoryAddress) >= (PVOID)0xFFFFFFFF) {
                return(NULL);
            }
        }

        *Size = NtHeaders->OptionalHeader.DataDirectory[DirectoryEntry].Size;
        if (MappedAsImage || DirectoryAddress < NtHeaders->OptionalHeader.SizeOfHeaders) {
            return((PVOID)((PCHAR)Base + DirectoryAddress));
        }

        return(RtlAddressInSectionTable((PIMAGE_NT_HEADERS)NtHeaders, Base, DirectoryAddress));
    }

    __forceinline PVOID
        RtlImageDirectoryEntryToData(
            IN PVOID Base,
            IN BOOLEAN MappedAsImage,
            IN USHORT DirectoryEntry,
            OUT PULONG Size
        )

        /*++
        Routine Description:
            This function locates a Directory Entry within the image header
            and returns either the virtual address or seek address of the
            data the Directory describes.
        Arguments:
            Base - Supplies the base of the image or data file.
            MappedAsImage - FALSE if the file is mapped as a data file.
                          - TRUE if the file is mapped as an image.
            DirectoryEntry - Supplies the directory entry to locate.
            Size - Return the size of the directory.
        Return Value:
            NULL - The file does not contain data for the specified directory entry.
            NON-NULL - Returns the address of the raw data the directory describes.
        --*/

    {
        PIMAGE_NT_HEADERS NtHeaders;

        if (LDR_IS_DATAFILE(Base)) {
            Base = LDR_DATAFILE_TO_VIEW(Base);
            MappedAsImage = FALSE;
        }

        NtHeaders = RtlImageNtHeader(Base);

        if (!NtHeaders)
            return NULL;

        if (NtHeaders->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
            return (RtlpImageDirectoryEntryToData32(Base,
                MappedAsImage,
                DirectoryEntry,
                Size,
                (PIMAGE_NT_HEADERS32)NtHeaders));
        }
        else if (NtHeaders->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
            return (RtlpImageDirectoryEntryToData64(Base,
                MappedAsImage,
                DirectoryEntry,
                Size,
                (PIMAGE_NT_HEADERS64)NtHeaders));
        }
        else {
            return (NULL);
        }
    }




    __forceinline  PRUNTIME_FUNCTION
        NTAPI
        RtlLookupFunctionTable(
            IN DWORD64 ControlPc,
            OUT PDWORD64 ImageBase,
            OUT PULONG Length)
    {
        PVOID Table;
        ULONG Size;

        /* Find corresponding file header from code address */
       /* if (!RtlPcToFileHeader((PVOID)ControlPc, (PVOID*)ImageBase))
        {

            return NULL;
        }*/

        /* Locate the exception directory */
        Table = WindowsCode::RtlImageDirectoryEntryToData((PVOID)*ImageBase,
            TRUE,
            IMAGE_DIRECTORY_ENTRY_EXCEPTION,
            &Size);

        /* Return the number of entries */
        *Length = Size / sizeof(RUNTIME_FUNCTION);

        /* Return the address of the table */
        return (PRUNTIME_FUNCTION)Table;
    }





}