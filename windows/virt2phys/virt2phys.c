/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2020-2021 Dmitry Kozlyuk
 */

#include <ntddk.h>
#include <wdf.h>
#include <initguid.h>

#include "virt2phys.h"
#include "virt2phys_logic.h"
#include "virt2phys_trace.h"
#include "virt2phys.tmh"

DRIVER_INITIALIZE DriverEntry;
EVT_WDF_DRIVER_UNLOAD virt2phys_driver_unload;
EVT_WDF_DRIVER_DEVICE_ADD virt2phys_driver_EvtDeviceAdd;
EVT_WDF_IO_IN_CALLER_CONTEXT virt2phys_device_EvtIoInCallerContext;

static NTSTATUS virt2phys_load_params(
	WDFDRIVER driver, struct virt2phys_params *params);
static VOID virt2phys_on_process_event(
	HANDLE parent_id, HANDLE process_id, BOOLEAN create);

static const ULONG PROCESS_COUNT_LIMIT_DEF = 1 << 4;
static const ULONG PROCESS_MEMORY_LIMIT_DEF = 16 * (1 << 10); /* MB */

_Use_decl_annotations_
NTSTATUS
DriverEntry(PDRIVER_OBJECT driver_object, PUNICODE_STRING registry_path)
{
	WDF_DRIVER_CONFIG config;
	WDF_OBJECT_ATTRIBUTES attributes;
	WDFDRIVER driver;
	struct virt2phys_params params;
	NTSTATUS status;

	PAGED_CODE();

	WDF_OBJECT_ATTRIBUTES_INIT(&attributes);
	WDF_DRIVER_CONFIG_INIT(&config, virt2phys_driver_EvtDeviceAdd);
	config.EvtDriverUnload = virt2phys_driver_unload;
	status = WdfDriverCreate(
		driver_object, registry_path,
		&attributes, &config, &driver);
	if (!NT_SUCCESS(status))
		return status;

	status = virt2phys_load_params(driver, &params);
	if (!NT_SUCCESS(status))
		return status;

	status = virt2phys_init(&params);
	if (!NT_SUCCESS(status))
		return status;

	/*
	 * The goal is to ensure that no process obtains a physical address
	 * of pageable memory. To do this the driver locks every memory region
	 * for which physical address is requested. This memory must remain
	 * locked until process has no access to it anymore. A process can use
	 * the memory after it closes all handles to the interface device,
	 * so the driver cannot unlock memory at device cleanup callback.
	 * It has to track process termination instead, after which point
	 * a process cannot attempt any memory access.
	 */
	status = PsSetCreateProcessNotifyRoutine(
		virt2phys_on_process_event, FALSE);
	if (!NT_SUCCESS(status))
		return status;

	WPP_INIT_TRACING(driver_object, registry_path);

	return status;
}

static NTSTATUS
virt2phys_read_param(WDFKEY key, PCUNICODE_STRING name, ULONG *value,
	ULONG def)
{
	NTSTATUS status;

	status = WdfRegistryQueryULong(key, name, value);
	if (status == STATUS_OBJECT_NAME_NOT_FOUND) {
		*value = def;
		status = STATUS_SUCCESS;
	}
	return status;
}

static NTSTATUS
virt2phys_read_mb(WDFKEY key, PCUNICODE_STRING name, ULONG64 *bytes,
	ULONG def_mb)
{
	ULONG mb;
	NTSTATUS status;

	status = virt2phys_read_param(key, name, &mb, def_mb);
	if (NT_SUCCESS(status))
		*bytes = (ULONG64)mb * (1ULL << 20);
	return status;
}

static NTSTATUS
virt2phys_load_params(WDFDRIVER driver, struct virt2phys_params *params)
{
	static DECLARE_CONST_UNICODE_STRING(
		process_count_limit, L"ProcessCountLimit");
	static DECLARE_CONST_UNICODE_STRING(
		process_memory_limit, L"ProcessMemoryLimitMB");

	WDFKEY key;
	NTSTATUS status;

	status = WdfDriverOpenParametersRegistryKey(
		driver, KEY_READ, WDF_NO_OBJECT_ATTRIBUTES, &key);
	if (!NT_SUCCESS(status))
		return status;

	status = virt2phys_read_param(key, &process_count_limit,
		&params->process_count_limit, PROCESS_COUNT_LIMIT_DEF);
	if (!NT_SUCCESS(status))
		goto cleanup;

	status = virt2phys_read_mb(key, &process_memory_limit,
		&params->process_memory_limit, PROCESS_MEMORY_LIMIT_DEF);
	if (!NT_SUCCESS(status))
		goto cleanup;

cleanup:
	WdfRegistryClose(key);
	return status;
}

_Use_decl_annotations_
VOID
virt2phys_driver_unload(WDFDRIVER driver)
{
	PsSetCreateProcessNotifyRoutine(virt2phys_on_process_event, TRUE);

	virt2phys_cleanup();

	WPP_CLEANUP(WdfDriverWdmGetDriverObject(driver));
}

_Use_decl_annotations_
NTSTATUS
virt2phys_driver_EvtDeviceAdd(WDFDRIVER driver, PWDFDEVICE_INIT init)
{
	WDF_OBJECT_ATTRIBUTES attributes;
	WDFDEVICE device;
	NTSTATUS status;

	UNREFERENCED_PARAMETER(driver);

	WdfDeviceInitSetIoType(
		init, WdfDeviceIoNeither);
	WdfDeviceInitSetIoInCallerContextCallback(
		init, virt2phys_device_EvtIoInCallerContext);

	WDF_OBJECT_ATTRIBUTES_INIT(&attributes);

	status = WdfDeviceCreate(&init, &attributes, &device);
	if (!NT_SUCCESS(status)) {
		TraceError("WdfDriverCreate() = %!STATUS!", status);
		return status;
	}

	status = WdfDeviceCreateDeviceInterface(
		device, &GUID_DEVINTERFACE_VIRT2PHYS, NULL);
	if (!NT_SUCCESS(status)) {
		TraceError("WdfDeviceCreateDeviceInterface() = %!STATUS!",
			status);
		return status;
	}

	return STATUS_SUCCESS;
}

_Use_decl_annotations_
VOID
virt2phys_device_EvtIoInCallerContext(WDFDEVICE device, WDFREQUEST request)
{
	WDF_REQUEST_PARAMETERS params;
	ULONG code;
	PVOID *virt;
	PHYSICAL_ADDRESS *phys;
	size_t size;
	NTSTATUS status;

	UNREFERENCED_PARAMETER(device);
	PAGED_CODE();

	WDF_REQUEST_PARAMETERS_INIT(&params);
	WdfRequestGetParameters(request, &params);

	if (params.Type != WdfRequestTypeDeviceControl) {
		TraceWarning("Bogus IO request type %lu", params.Type);
		WdfRequestComplete(request, STATUS_NOT_SUPPORTED);
		return;
	}

	code = params.Parameters.DeviceIoControl.IoControlCode;
	if (code != IOCTL_VIRT2PHYS_TRANSLATE) {
		TraceWarning("Bogus IO control code %lx", code);
		WdfRequestComplete(request, STATUS_NOT_SUPPORTED);
		return;
	}

	status = WdfRequestRetrieveInputBuffer(
			request, sizeof(*virt), (PVOID *)&virt, &size);
	if (!NT_SUCCESS(status)) {
		TraceWarning("Retrieving input buffer: %!STATUS!", status);
		WdfRequestComplete(request, status);
		return;
	}

	status = WdfRequestRetrieveOutputBuffer(
		request, sizeof(*phys), (PVOID *)&phys, &size);
	if (!NT_SUCCESS(status)) {
		TraceWarning("Retrieving output buffer: %!STATUS!", status);
		WdfRequestComplete(request, status);
		return;
	}

	status = virt2phys_translate(*virt, phys);
	if (NT_SUCCESS(status))
		WdfRequestSetInformation(request, sizeof(*phys));

	TraceInfo("Translate %p to %llx: %!STATUS!",
		virt, phys->QuadPart, status);
	WdfRequestComplete(request, status);
}

static VOID
virt2phys_on_process_event(
	HANDLE parent_id, HANDLE process_id, BOOLEAN create)
{
	UNREFERENCED_PARAMETER(parent_id);

	if (create)
		return;

	virt2phys_process_cleanup(process_id);
}
