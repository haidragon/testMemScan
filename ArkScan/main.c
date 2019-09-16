#include <ntifs.h>
#include <ntddk.h>
#include <ntimage.h>
#include <ntstrsafe.h>
#include "NtStructs.h"
#include "NtImport.h"

#define NUMBER_HASH_BUCKETS 37

struct _OBJECT_DIRECTORY_ENTRY
{
    struct _OBJECT_DIRECTORY_ENTRY* ChainLink;
    PDRIVER_OBJECT           Object;
    ULONG                    HashValue;
};

 typedef struct _OBJECT_DIRECTORY_ENTRY  OBJECT_DIRECTORY_ENTRY, *POBJECT_DIRECTORY_ENTRY;


typedef struct _OBJECT_DIRECTORY
{
    POBJECT_DIRECTORY_ENTRY HashBuckets[NUMBER_HASH_BUCKETS];
    EX_PUSH_LOCK            Lock;
    ULONG                   SessionId;
    PVOID                   NamespaceEntry;
    ULONG                   Flags;
}OBJECT_DIRECTORY,*POBJECT_DIRECTORY;

typedef struct _MMPTE_HARDWARE64
{
    ULONGLONG Valid : 1;
    ULONGLONG Dirty1 : 1;
    ULONGLONG Owner : 1;
    ULONGLONG WriteThrough : 1;
    ULONGLONG CacheDisable : 1;
    ULONGLONG Accessed : 1;
    ULONGLONG Dirty : 1;
    ULONGLONG LargePage : 1;
    ULONGLONG Global : 1;
    ULONGLONG CopyOnWrite : 1;
    ULONGLONG Unused : 1;
    ULONGLONG Write : 1;
    ULONGLONG PageFrameNumber : 36;
    ULONGLONG reserved1 : 4;
    ULONGLONG SoftwareWsIndex : 11;
    ULONGLONG NoExecute : 1;
} MMPTE_HARDWARE64, * PMMPTE_HARDWARE64;

typedef struct _MMPTE
{
    union
    {
        ULONG_PTR Long;
        MMPTE_HARDWARE64 Hard;
    } u;
} MMPTE;
typedef MMPTE* PMMPTE;

BOOLEAN CheckDriverObjName(PUNICODE_STRING pusName)
{
    UNICODE_STRING uc = RTL_CONSTANT_STRING(L"\\Driver\\Rtl");
    if (pusName->Length <= uc.Length)
    {
        return FALSE;
    }
    USHORT ulen = uc.Length / sizeof(WCHAR);
    USHORT uTemp = 0;
    while (uTemp < ulen)
    {
        if (uc.Buffer[uTemp] != pusName->Buffer[uTemp])
        {
            return FALSE;
        }
        uTemp++;
    }
    return TRUE;
}

NTSTATUS MakeFakeDriverObject(IN PUNICODE_STRING driverName, OUT PDRIVER_OBJECT* ppdriverObject)
{
    NTSTATUS status;
    ULONG i;
    OBJECT_ATTRIBUTES objectAttributes;
    PDRIVER_OBJECT driverObject;
    InitializeObjectAttributes(&objectAttributes, driverName, OBJ_PERMANENT, (HANDLE)NULL, (PSECURITY_DESCRIPTOR)NULL);

    status = ObCreateObject(ExGetPreviousMode(),
        *IoDriverObjectType,
        &objectAttributes,
        KernelMode,
        (PVOID)NULL,
        (ULONG)(sizeof(DRIVER_OBJECT) + sizeof(DRIVER_EXTENSION) + 256),
        0,
        0,
        (PVOID*)ppdriverObject);

    if (!NT_SUCCESS(status))
    {
        *ppdriverObject = NULL;
        return status;
    }

    driverObject = *ppdriverObject;

    RtlZeroMemory(driverObject, sizeof(DRIVER_OBJECT) + sizeof(DRIVER_EXTENSION) + 256);

    driverObject->DriverExtension = (PDRIVER_EXTENSION)(driverObject + 1);
    driverObject->DriverExtension->DriverObject = driverObject;//���DriverExtension���ã����û��ֱ�Ӳ���
    driverObject->Type = IO_TYPE_DRIVER;
    driverObject->Size = sizeof(DRIVER_OBJECT);
    driverObject->Flags = DRVO_BUILTIN_DRIVER;

    for (i = 0; i <= IRP_MJ_MAXIMUM_FUNCTION; i++)
        driverObject->MajorFunction[i] = NULL;

    driverObject->DriverName.Buffer = ExAllocatePool(NonPagedPool, driverName->MaximumLength);
    if (driverObject->DriverName.Buffer)
    {
        driverObject->DriverName.MaximumLength = driverName->MaximumLength;
        driverObject->DriverName.Length = driverName->Length;
        RtlCopyMemory(driverObject->DriverName.Buffer, driverName->Buffer, driverName->MaximumLength);
    }
    return status;
}

BOOLEAN GetDrvObject()
{
    UNICODE_STRING usDriverName = { 0 };
    WCHAR buffer[60] = { 0 };
    usDriverName.Buffer = buffer;
    usDriverName.Length = 60 * 2;
    usDriverName.MaximumLength = 60 * 2;
    PDRIVER_OBJECT lpDriverObject = NULL;
    PDRIVER_OBJECT lpDriverObject2 = NULL;
    DWORD a = sizeof(DRIVER_OBJECT);
    do 
    {
        RtlUnicodeStringPrintf(&usDriverName, L"\\Driver\\Rtl%08u", PsGetCurrentThreadId());
        NTSTATUS status = MakeFakeDriverObject(&usDriverName, &lpDriverObject);
        if (!NT_SUCCESS(status))
        {
            return FALSE;
        }

    } while (FALSE);

    return TRUE;
}


BOOLEAN DetectSEH(PUNICODE_STRING usDirName)
{
    NTSTATUS status = STATUS_SUCCESS;
    OBJECT_ATTRIBUTES oa = { 0 };
    POBJECT_DIRECTORY pObjDirectory = NULL;
    POBJECT_DIRECTORY_ENTRY pObjDirEntry = NULL;
    HANDLE hDir = NULL;
    PUNICODE_STRING path = NULL;
    BOOLEAN bFind = FALSE;
    do
    {
        InitializeObjectAttributes(&oa, usDirName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
        status = ZwOpenDirectoryObject(&hDir, DIRECTORY_QUERY, &oa);
        if (!NT_SUCCESS(status))
        {
            break;
        }
        status = ObReferenceObjectByHandle(hDir, DIRECTORY_QUERY, NULL, KernelMode, (PVOID*)& pObjDirectory, NULL);
        if (!NT_SUCCESS(status))
        {
            break;
        }
        for (ULONG uIndex = 0; uIndex < NUMBER_HASH_BUCKETS; uIndex++)
        {
            PDRIVER_OBJECT pDriver = NULL;
            pObjDirEntry = pObjDirectory->HashBuckets[uIndex];
            while (pObjDirEntry && MmIsAddressValid((PVOID)pObjDirEntry))
            {
                pDriver = (PDRIVER_OBJECT)pObjDirEntry->Object;
                if (MmIsAddressValid((PVOID)pDriver))
                {
                    PLDR_DATA_TABLE_ENTRY pLdr = pDriver->DriverSection;
                    if (MmIsAddressValid((PVOID)pLdr))
                    {
                        if ((ULONG_PTR)pDriver->DriverStart > (ULONG_PTR)pLdr->DllBase + pLdr->SizeOfImage ||
                            (ULONG_PTR)pDriver->DriverStart < (ULONG_PTR)pLdr->DllBase)
                        {
                            //���DriverStart���ڷ�Χ�ڣ�˵��SEH��������ģ���������
                            bFind = TRUE;
                            break;
                        }
                        if (MmIsAddressValid(pLdr->DllBase))
                        {
                            PIMAGE_DOS_HEADER pDosHead = pLdr->DllBase;
                            if (pDosHead->e_magic != IMAGE_DOS_SIGNATURE)
                            {
                                //PEͷ���޸Ĺ�
                                bFind = TRUE;
                                break;
                            }
                            PIMAGE_NT_HEADERS pNtHead = (PIMAGE_NT_HEADERS)((PCHAR)pDosHead + pDosHead->e_lfanew);
                            if (pNtHead->Signature != IMAGE_NT_SIGNATURE)
                            {
                                bFind = TRUE;
                                break;
                            }

                        }
                    }
                }
            next:
                pObjDirEntry = pObjDirEntry->ChainLink;
            }
        }

    } while (FALSE);

    if (hDir != NULL)
    {
        ZwClose(hDir);
        hDir = NULL;
    }

    if (pObjDirectory != NULL)
    {
        ObDereferenceObject(pObjDirectory);
        pObjDirectory = NULL;
    }
    return bFind;
}

VOID ScanDirObj(PUNICODE_STRING usDirName) 
{
    NTSTATUS status = STATUS_SUCCESS;
    OBJECT_ATTRIBUTES oa = { 0 };
    POBJECT_DIRECTORY pObjDirectory = NULL;
    POBJECT_DIRECTORY_ENTRY pObjDirEntry = NULL;
    HANDLE hDir = NULL;
    PUNICODE_STRING path = NULL;
    do 
    {
        InitializeObjectAttributes(&oa, usDirName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
        status = ZwOpenDirectoryObject(&hDir, DIRECTORY_QUERY, &oa);
        if (!NT_SUCCESS(status))
        {
            break;
        }
        status = ObReferenceObjectByHandle(hDir, DIRECTORY_QUERY, NULL, KernelMode, (PVOID*)& pObjDirectory, NULL);
        if (!NT_SUCCESS(status))
        {
            break;
        }
        for (ULONG uIndex = 0; uIndex < NUMBER_HASH_BUCKETS; uIndex++)
        {
            PDRIVER_OBJECT pDriver = NULL;
            pObjDirEntry = pObjDirectory->HashBuckets[uIndex];
            while (pObjDirEntry && MmIsAddressValid((PVOID)pObjDirEntry))
            {
                pDriver = (PDRIVER_OBJECT)pObjDirEntry->Object;
                if (MmIsAddressValid((PVOID)pDriver))
                {
                    if (MmIsAddressValid(&pDriver->DriverName))
                    {
                        if (MmIsAddressValid(pDriver->DriverName.Buffer))
                        {
                            KdPrint(("DriverObjName:%wZ\n", &pDriver->DriverName));
                            if (CheckDriverObjName(&pDriver->DriverName))
                            {
                                KdBreakPoint();
                            }
                        }
                        else
                        {
                            KdBreakPoint();
                            KdPrint(("DriverObjName:NoName\n"));
                        }
                    }


                    PLDR_DATA_TABLE_ENTRY pLdr = pDriver->DriverSection;
                    if (MmIsAddressValid((PVOID)pLdr))
                    {
                        if ((ULONG_PTR)pDriver->DriverStart > (ULONG_PTR)pLdr->DllBase + pLdr->SizeOfImage ||
                            (ULONG_PTR)pDriver->DriverStart < (ULONG_PTR)pLdr->DllBase)
                        {

                        }
                        if (MmIsAddressValid(pLdr->DllBase))
                        {
                            PIMAGE_DOS_HEADER pDosHead = pLdr->DllBase;
                            if (pDosHead->e_magic != IMAGE_DOS_SIGNATURE)
                            {

                                goto next;
                            }
                            PIMAGE_NT_HEADERS pNtHead = (PIMAGE_NT_HEADERS)((PCHAR)pDosHead + pDosHead->e_lfanew);
                            if (pNtHead->Signature != IMAGE_NT_SIGNATURE)
                            {

                            }

                        }
                    }
                }
            next:
                pObjDirEntry = pObjDirEntry->ChainLink;
            }
        }

    } while (FALSE);

    if (hDir != NULL)
    {
        ZwClose(hDir);
        hDir = NULL;
    }

    if (pObjDirectory != NULL)
    {
        ObDereferenceObject(pObjDirectory);
        pObjDirectory = NULL;
    }

}

VOID Unload(PDRIVER_OBJECT  DriverObject)
{

}

// typedef enum _MEM_VALID
// {
//     VALID,
//     PTE_INVALID,
//     PAE_PTE_INVALID,
//     PAE_PDE_INVALID,
//     PTE_INVALID_X64,
//     PDE_INVALID,
//     PDE_INVALID_X64
// }MEM_VALID;
// 
// 
// ULONG VALIDpage(SIZE_T addr)
// {
//     ULONGLONG* pte = 0, *pde = 0;
//     pde = GET_PDE_ADDR_X64(addr);
//     //���Ե�ַ��Ӧ��PDE�Ƿ���Ч
//     if (MmIsAddressValid((PVOID)pde) && (*(PULONGLONG)pde & 0x1) != 0)
//     {
//         //�Ǵ�ҳ����û��PTE�����ص�ַ��Ч
//         if ((*(PULONGLONG)pde & 0x80) != 0)
//             return VALID;
//         pte = GET_PTE_ADDR_X64(addr);
//         //���Ե�ַ��Ӧ��PTE�Ƿ���Ч
//         if (MmIsAddressValid((PVOID)pte) && (*(PULONGLONG)pte & 0x1) != 0)
//             return VALID;
//         else
//             return PTE_INVALID_X64;
//     }
//     return PDE_INVALID_X64;
// }
// KeCapturePresistent
// MmNonPagedPoolStart;
// 
// 
// 
// KDDEBUGGER_DATA64
// VOID SearchProcessInVirtualMemory()
// {
//     ULONG nProcessCount = 0, ret = 0;
//     SIZE_T i = 0;
//     for (i = gMmNonPagedPoolStart; i < gMmNonPagedPoolEnd; i += 4)
//     {
//         ret = VALIDpage(i);
//         //�ں��н��̽ṹ����object header��object body(Eprocess)
//         if (i + OBJECT_HEADER_SIZE + GetPlantformDependentInfo(EPROCESS_SIZE) >= gMmNonPagedPoolEnd)
//             break;
// 
//         if (IsaRealProcess(i))
//         {
//             if (ShowProcess(i + OBJECT_HEADER_SIZE))
//             {
//                 nProcessCount++;
//                 i += GetPlantformDependentInfo(EPROCESS_SIZE) + OBJECT_HEADER_SIZE - 4;
//             }
//         }
//         else if (ret == PTE_INVALID || ret == PAE_PTE_INVALID)
//         {
//             i -= 4;
//             i += 0x1000;//4k
//         }
//         else if (ret == PDE_INVALID)
//         {
//             i -= 4;
//             i += 0x200000;//2mb
//         }
//         else if (ret == PAE_PDE_INVALID)
//         {
//             i -= 4;
//             i += 0x400000;// 4mb
//         }
//         KdPrint(("-------------------------------------------\r\n"));
//         KdPrint(("=====   Total Processes count:%3d   =======\r\n", nProcessCount));
//         KdPrint(("-------------------------------------------\r\n"));
//     }
// }

// BOOLEAN IsaRealProcess(SIZE_T i) //���ݶ��������ж�
// {
//     SIZE_T pObjectType = 0, ObjectTypeAddress = 0, offset = i;
// 
//     if (!MmIsAddressValid((PVOID)(offset + OBJECT_HEADER_SIZE)))
//     {
//         //KdPrint(("VALIDpage(offset+OBJECT_HEADER_SIZE) != VALID"));
//         return FALSE;
//     }
// 
//     ObjectTypeAddress = offset + GetPlantformDependentInfo(OBJECT_TYPE_OFFSET);
// 
//     if (gWinVerDetail == WINDOWS_VERSION_7)
//     {
//         //win�¶������ͽṹ����,ֱ���ж�TypeIndex��������Ⱦ���
//         if ((g_ulObjectType & 0x000000ff) == (pObjectType & 0x000000ff))
//             return TRUE;
//     }
//     else if (gWinVerDetail != WINDOWS_VERSION_NONE)
//     {
//         if (g_ulObjectType == pObjectType) //ȷ��ObjectType��Process����
//             return TRUE;
//     }
// 
//     return FALSE;
// }

// BOOLEAN  ShowProcess(ULONG pEProcess)
// {
//     PLARGE_INTEGER ExitTime = NULL;
//     ULONG PID = 0, tablePID = 0, objTableHandle = 0, tableCode = 0;
//     PUCHAR pFileName = NULL;
// 
//     ULONG ulRet = 0;
// 
//     __try
//     {
//         ExitTime = (PLARGE_INTEGER)(pEProcess + GetPlantformDependentInfo(EXIT_TIME_OFFSET));
//         if (ExitTime->QuadPart != 0) //�Ѿ������Ľ��̵�ExitTimeΪ����
//         {
//             KdPrint(("Process info error: ExitTime is not zero!"));
//             return FALSE;
//         }
// 
//         if (VALIDpage(pEProcess + GetPlantformDependentInfo(OBJECT_TABLE_OFFSET)) != VALID)
//         {
//             KdPrint(("Process info error: ObjectTable address is invalid->0x%x!",
//                 pEProcess + GetPlantformDependentInfo(OBJECT_TABLE_OFFSET)));
//             return FALSE;
//         }
// 
//         objTableHandle = *(PULONG)(pEProcess + GetPlantformDependentInfo(OBJECT_TABLE_OFFSET));
//         if (objTableHandle == 0)
//         {
//             KdPrint(("Process info error: ObjectTable is zero!"));
//             return FALSE;
//         }
// 
//         if (!IsProcessAlive((PEPROCESS)pEProcess))
//         {
//             KdPrint(("Process is not alive!"));
//             return FALSE;
//         }
// 
//         if (VALIDpage(objTableHandle) != VALID)
//         {
//             KdPrint(("Process info error: ObjectTable is invalid!"));
//             return FALSE;
//         }
// 
//         tableCode = *(PULONG)objTableHandle;
//         if (tableCode == 0)
//         {
//             KdPrint(("Process info error: tableCode is zero!"));
//             return FALSE;
//         }
// 
//         if (VALIDpage(objTableHandle + GetPlantformDependentInfo(HANDLE_TABLE_PID_OFFSET)) != VALID)
//         {
//             KdPrint(("Process info error: HandleTablePid is invalid!"));
//             return FALSE;
//         }
// 
//         tablePID = *(PULONG)(objTableHandle + GetPlantformDependentInfo(HANDLE_TABLE_PID_OFFSET));
// 
//         if (VALIDpage(pEProcess + GetPlantformDependentInfo(PROCESS_ID_OFFSET)) != VALID)
//         {
//             KdPrint(("Process info error: ProcessId is invalid!"));
//             return FALSE;
//         }
// 
//         PID = *(PULONG)(pEProcess + GetPlantformDependentInfo(PROCESS_ID_OFFSET));
//         if (tablePID == PID) //�ų����õ�EProcess,Ϊʲô�������õ���Ҫ��֤
//         {
//             pFileName = (PUCHAR)(pEProcess + GetPlantformDependentInfo(FILE_NAME_OFFSET));
//             KdPrint(("0x%08X  %04d   %s\r\n", pEProcess, PID, pFileName));
//             //�����￪ʼ��RundownProtect��
//             AddEProcess((PEPROCESS)pEProcess); //�Ѿ���ӹ�EprocessҲ����FALSE,���Բ��жϷ���ֵ
//         }
//         else
//         {
//             KdPrint(("Eprocess two pid are not equal!"));
//             return FALSE;
//         }
//     }
//     __except (EXCEPTION_EXECUTE_HANDLER)
//     {
//         KdPrint(("ShowProcess exception catched!"));
//         return FALSE;
//     }
//     return TRUE;
// }
// 

// 1�������ַ���
//    SigPattern = "This is a null terminated string."
//    SigMask = NULL or "xxxxxxxxxxx" or "x?xx????xxx"
//
// 2���������롢����������
//    SigPattern = "\x8B\xCE\xE8\x00\x00\x00\x00\x8B"
//    SigMask = "xxxxxxxx" or "xxx????x"
//
// Mask �е� ? ������ģ��ƥ�䣬�ڱ���������Ƭ�����ж�̬�仯������ʱʹ��(��ָ������ĵ�ַ�����ݵ�)
//
// ���������������ڴ��Ӧ���Ӻ����������ڴ�������棬�����и��˵ķ�������������޹ؾ�ʡ����
//
// ULONGLONG SearchVirtualMemory(ULONGLONG VirtualAddress, ULONGLONG VirtualLength, PUCHAR SigPattern, PCHAR SigMask)
// {
//     // SigMask δָ��ʱ�Զ����ɼ򻯵��ã���ֻ����������ַ�����
//     CHAR TmpMask[PAGE_SIZE];
//     if (SigMask == NULL || SigMask[0] == 0) 
//     {
//         ULONG SigLen = (ULONG)strlen((PCHAR)SigPattern);
//         if (SigLen > PAGE_SIZE - 1) SigLen = PAGE_SIZE - 1;
//         memset(TmpMask, 'x', SigLen);
//         TmpMask[SigLen] = 0;
//         SigMask = TmpMask;
//     }
// 
//     // �������
//     PUCHAR MaxAddress = (PUCHAR)(VirtualAddress + VirtualLength);
//     PUCHAR BaseAddress;
//     PUCHAR CurrAddress;
//     PUCHAR CurrPattern;
//     PCHAR CurrMask;
//     BOOLEAN CurrEqual;
//     register UCHAR CurrUChar;
// 
//     // SSE ������ر���
//     __m128i SigHead = _mm_set1_epi8((CHAR)SigPattern[0]);
//     __m128i CurHead, CurComp;
//     ULONG MskComp, IdxComp;
//     ULONGLONG i, j;
// 
//     //
//     // ��һ�����ʹ�� SSE �����ֽڼ���Ϊ�� 16 �ֽ�ÿ�Σ����ռ��� 12 ��������Ҫ��Դ��ˣ�
//     //
//     // �ڶ����Ӵ�ƥ�䲻��ʹ�� SSE ���٣�ԭ������
//     //     1. SSE ��Ϊ��ָ������ݣ�������ָ�� CPU ���ڱȳ���ָ��Ҫ��
//     //
//     //     2. �Ӹ�������˵���Ӵ�ƥ��ʱ��һ���ֽ�����ʧ���� SSE һ���ԶԱ� 16 ���ֽ�����ʧ���ڸ����ϼ������
//     //
//     //     3. ����ʵ����� SSE �Ż��ڶ����Ӵ�ƥ�佫�����������ղ����ٶ�
//     //
//     //     4. �����ϣ���ʹ SSE ����ָ���볣��ָ�����ͬ����CPU���ڣ����Ҳֻ�ܼ��� 16 ��
//     //
//     for (i = 0; i <= VirtualLength - 16; i += 16)
//     {
//         CurHead = _mm_loadu_si128((__m128i*)(VirtualAddress + i));
//         CurComp = _mm_cmpeq_epi8(SigHead, CurHead);
//         MskComp = _mm_movemask_epi8(CurComp);
// 
//         BaseAddress = (PUCHAR)(VirtualAddress + i);
//         j = 0;
//         while (_BitScanForward(&IdxComp, MskComp))
//         {
//             CurrAddress = BaseAddress + j + IdxComp;
//             CurrPattern = SigPattern;
//             CurrMask = SigMask;
//             for (; CurrAddress <= MaxAddress; CurrAddress++, CurrPattern++, CurrMask++)
//             {
//                 // ��Ϊ�Ǳ�����������ϵͳ�������ڴ棬������������Ķ�ջ����ȻҲ�������������ڴ��һ����
//                 // ���Ϊ�˱���ƥ�䵽���� SigPattern ��������������Ӧ���˲������粻��Ҫ�������м� 2 ��
//                 CurrUChar = *CurrPattern;
//                 // *CurrPattern = CurrUChar + 0x1;
//                 CurrEqual = (*CurrAddress == CurrUChar);
//                 // *CurrPattern = CurrUChar;
// 
//                 if (!CurrEqual) { if (*CurrMask == 'x') break; }
//                 if (*CurrMask == 0) { return (ULONGLONG)(BaseAddress + j + IdxComp); }
//             }
// 
//             ++IdxComp;
//             MskComp = MskComp >> IdxComp;
//             j += IdxComp;
//         }
//     }
// 
//     return 0x0;
// }


VOID ScanMem();


VOID Reinitialize(PDRIVER_OBJECT DriverObject, PVOID Context, ULONG Count)
{
    KdBreakPoint();
    ScanMem();
//     CreatePhysicalOpCR3BySystemCR3(GetCR3ByPID(4), &g_PhysicalOpCR3);
// 
//     ContextVirtualToPhysical(&g_PhysicalOpCR3);
//     ULONG64 Read1 = *(PULONG64)0x0;
//     ContextPhysicalToVirtual(&g_PhysicalOpCR3);
// 
//     ContextVirtualToPhysical(&g_PhysicalOpCR3);
//     ULONG64 Read2 = *(PULONG64)0x1000;
//     ContextPhysicalToVirtual(&g_PhysicalOpCR3);
}
NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT  DriverObject, _In_ PUNICODE_STRING RegistryPath)
{
    KdBreakPoint();
    DriverObject->DriverUnload = Unload;
    KdPrint(("NMSL\n"));
    UNICODE_STRING usDriver = { 0 };
    UNICODE_STRING usFileSystem = { 0 };

    //�Լ���������
    GetDrvObject();


    IoRegisterDriverReinitialization(DriverObject, Reinitialize, NULL);
//     RtlInitUnicodeString(&usDriver, L"\\Driver");
//     RtlInitUnicodeString(&usFileSystem, L"\\FileSystem");
//     ScanDirObj(&usDriver);
//     ScanDirObj(&usFileSystem);
    return STATUS_SUCCESS;
}

typedef VOID(*ScanCallBack)(PVOID pMem, DWORD MemSize, PVOID pContext);

VOID ScanDriverObj(PVOID pMem, DWORD MemSize, PVOID pContext)
{
    for (ULONG_PTR i = pMem; i < (ULONG_PTR)pMem + MemSize - sizeof(DRIVER_OBJECT); i += 8)
    {
        if (MmIsAddressValid(i))
        {
            PDRIVER_OBJECT pObj = (PDRIVER_OBJECT)i;
            if (pObj->Type == 4 && pObj->Size == sizeof(DRIVER_OBJECT))
            {
                if (MmIsAddressValid(&pObj->DriverName) && MmIsAddressValid(pObj->DriverName.Buffer))
                {
                    KdPrint(("DriverObjName:%wZ\n", &pObj->DriverName));
                }
            }
        }

    }
}


VOID ScanMem()
{
    PPHYSICAL_MEMORY_RANGE  pMemRange = MmGetPhysicalMemoryRanges();

    DWORD Index = 0;
    while (pMemRange[Index].NumberOfBytes.QuadPart != 0)
    {
        PVOID pBuf = MmMapIoSpace(pMemRange[Index].BaseAddress, pMemRange[Index].NumberOfBytes.QuadPart, MmNonCached);
        if (pBuf != NULL)
        {
            ScanDriverObj(pBuf, pMemRange[Index].NumberOfBytes.QuadPart, NULL);
            MmUnmapIoSpace(pBuf, pMemRange[Index].NumberOfBytes.QuadPart);
        }
        Index++;
    }

}