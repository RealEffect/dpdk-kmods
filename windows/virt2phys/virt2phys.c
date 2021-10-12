/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2020-2021 Dmitry Kozlyuk
 */

#include <ntddk.h>
#include <wdf.h>
#include <initguid.h>

#include "virt2phys.h"
#include "virt2phys_logic.h"

DRIVER_INITIALIZE DriverEntry;
EVT_WDF_DRIVER_UNLOAD virt2phys_driver_unload;
EVT_WDF_DRIVER_DEVICE_ADD virt2phys_driver_EvtDeviceAdd;
EVT_WDF_IO_IN_CALLER_CONTEXT virt2phys_device_EvtIoInCallerContext;

static VOID virt2phys_on_process_event(
	HANDLE parent_id, HANDLE process_id, BOOLEAN create);

_Use_decl_annotations_
NTSTATUS
DriverEntry(PDRIVER_OBJECT driver_object, PUNICODE_STRING registry_path)
{
	WDF_DRIVER_CONFIG config;
	WDF_OBJECT_ATTRIBUTES attributes;
	NTSTATUS status;

	PAGED_CODE();

	WDF_OBJECT_ATTRIBUTES_INIT(&attributes);
	WDF_DRIVER_CONFIG_INIT(&config, virt2phys_driver_EvtDeviceAdd);
	config.EvtDriverUnload = virt2phys_driver_unload;
	status = WdfDriverCreate(
		driver_object, registry_path,
		&attributes, &config, WDF_NO_HANDLE);
	if (!NT_SUCCESS(status))
		return status;

	status = virt2phys_init();
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

	return status;
}

_Use_decl_annotations_
VOID
virt2phys_driver_unload(WDFDRIVER driver)
{
	UNREFERENCED_PARAMETER(driver);

	PsSetCreateProcessNotifyRoutine(virt2phys_on_process_event, TRUE);

	virt2phys_cleanup();
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
		return status;
	}

	status = WdfDeviceCreateDeviceInterface(
		device, &GUID_DEVINTERFACE_VIRT2PHYS, NULL);
	if (!NT_SUCCESS(status)) {
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
		WdfRequestComplete(request, STATUS_NOT_SUPPORTED);
		return;
	}

	code = params.Parameters.DeviceIoControl.IoControlCode;
	if (code != IOCTL_VIRT2PHYS_TRANSLATE) {
		WdfRequestComplete(request, STATUS_NOT_SUPPORTED);
		return;
	}

	status = WdfRequestRetrieveInputBuffer(
			request, sizeof(*virt), (PVOID *)&virt, &size);
	if (!NT_SUCCESS(status)) {
		WdfRequestComplete(request, status);
		return;
	}

	status = WdfRequestRetrieveOutputBuffer(
		request, sizeof(*phys), (PVOID *)&phys, &size);
	if (!NT_SUCCESS(status)) {
		WdfRequestComplete(request, status);
		return;
	}

	status = virt2phys_translate(*virt, phys);
	if (NT_SUCCESS(status))
		WdfRequestSetInformation(request, sizeof(*phys));
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
