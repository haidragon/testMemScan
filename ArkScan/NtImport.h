#pragma once
#include "NtStructs.h"

extern POBJECT_TYPE *IoDriverObjectType;       // ������������
extern POBJECT_TYPE *IoDeviceObjectType;       // �豸��������




NTKERNELAPI
NTSTATUS
ObReferenceObjectByName(
    IN PUNICODE_STRING ObjectName,
    IN ULONG Attributes,
    IN PACCESS_STATE PassedAccessState OPTIONAL,
    IN ACCESS_MASK DesiredAccess OPTIONAL,
    IN POBJECT_TYPE ObjectType,
    IN KPROCESSOR_MODE AccessMode,
    IN OUT PVOID ParseContext OPTIONAL,
    OUT PVOID* Object
);
NTKERNELAPI
NTSTATUS
ObCreateObject(
    __in KPROCESSOR_MODE ProbeMode,            // �����Ƿ�Ҫ��֤����
    __in POBJECT_TYPE ObjectType,              // ��������ָ��
    __in POBJECT_ATTRIBUTES ObjectAttributes,  // ���������, ���ջ�ת����ObAllocateObject��Ҫ��OBJECT_CREATE_INFORMATION�ṹ
    __in KPROCESSOR_MODE OwnershipMode,        // �ں˶���?�û�����? ͬ��
    __inout_opt PVOID ParseContext,            // �����û��
    __in ULONG ObjectBodySize,                 // �������С
    __in ULONG PagedPoolCharge,                // ...
    __in ULONG NonPagedPoolCharge,             // ...
    __out PVOID* Object                        // ���ն������ָ��
);

NTSYSAPI
NTSTATUS
NTAPI
ZwQueryInformationThread(
    IN HANDLE ThreadHandle,
    IN THREADINFOCLASS ThreadInformationClass,
    OUT PVOID ThreadInformation,
    IN ULONG ThreadInformationLength,
    OUT PULONG ReturnLength OPTIONAL
);


NTSYSAPI NTSTATUS NTAPI ZwQuerySystemInformation(
    IN SYSTEM_INFORMATION_CLASS SystemInformationClass,
    OUT PVOID SystemInformation,
    IN UINT32 SystemInformationLength,
    OUT PUINT32 ReturnLength OPTIONAL);
