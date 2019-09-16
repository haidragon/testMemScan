#pragma once
#include "NtStructs.h"

extern POBJECT_TYPE *IoDriverObjectType;       // 驱动对象类型
extern POBJECT_TYPE *IoDeviceObjectType;       // 设备对象类型




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
    __in KPROCESSOR_MODE ProbeMode,            // 决定是否要验证参数
    __in POBJECT_TYPE ObjectType,              // 对象类型指针
    __in POBJECT_ATTRIBUTES ObjectAttributes,  // 对象的属性, 最终会转化成ObAllocateObject需要的OBJECT_CREATE_INFORMATION结构
    __in KPROCESSOR_MODE OwnershipMode,        // 内核对象?用户对象? 同上
    __inout_opt PVOID ParseContext,            // 这参数没用
    __in ULONG ObjectBodySize,                 // 对象体大小
    __in ULONG PagedPoolCharge,                // ...
    __in ULONG NonPagedPoolCharge,             // ...
    __out PVOID* Object                        // 接收对象体的指针
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
