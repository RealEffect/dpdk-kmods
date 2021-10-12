/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2021 Dmitry Kozlyuk
 */

#include <ntifs.h>
#include <ntddk.h>

#include "virt2phys_logic.h"

struct virt2phys_process {
	HANDLE id;
	LIST_ENTRY next;
	SINGLE_LIST_ENTRY blocks;
};

struct virt2phys_block {
	PMDL mdl;
	SINGLE_LIST_ENTRY next;
};

static LIST_ENTRY g_processes;
static PKSPIN_LOCK g_lock;

struct virt2phys_block *
virt2phys_block_create(PMDL mdl)
{
	struct virt2phys_block *block;

	block = ExAllocatePoolZero(NonPagedPool, sizeof(*block), 'bp2v');
	if (block != NULL)
		block->mdl = mdl;
	return block;
}

static void
virt2phys_block_free(struct virt2phys_block *block, BOOLEAN unmap)
{
	if (unmap)
		MmUnlockPages(block->mdl);

	IoFreeMdl(block->mdl);
	ExFreePool(block);
}

static PHYSICAL_ADDRESS
virt2phys_block_translate(struct virt2phys_block *block, PVOID virt)
{
	PPFN_NUMBER pfn;
	PVOID base;
	PHYSICAL_ADDRESS phys;

	pfn = MmGetMdlPfnArray(block->mdl);
	base = MmGetMdlVirtualAddress(block->mdl);
	phys.QuadPart = pfn[0] * PAGE_SIZE +
		((uintptr_t)virt - (uintptr_t)base);
	return phys;
}

static struct virt2phys_process *
virt2phys_process_create(HANDLE process_id)
{
	struct virt2phys_process *process;

	process = ExAllocatePoolZero(NonPagedPool, sizeof(*process), 'pp2v');
	if (process != NULL)
		process->id = process_id;
	return process;
}

static void
virt2phys_process_free(struct virt2phys_process *process, BOOLEAN unmap)
{
	PSINGLE_LIST_ENTRY node;
	struct virt2phys_block *block;

	node = process->blocks.Next;
	while (node != NULL) {
		block = CONTAINING_RECORD(node, struct virt2phys_block, next);
		node = node->Next;
		virt2phys_block_free(block, unmap);
	}

	ExFreePool(process);
}

static struct virt2phys_process *
virt2phys_process_find(HANDLE process_id)
{
	PLIST_ENTRY node;
	struct virt2phys_process *cur;

	for (node = g_processes.Flink; node != &g_processes; node = node->Flink) {
		cur = CONTAINING_RECORD(node, struct virt2phys_process, next);
		if (cur->id == process_id)
			return cur;
	}
	return NULL;
}

static struct virt2phys_block *
virt2phys_process_find_block(struct virt2phys_process *process, PVOID virt)
{
	PSINGLE_LIST_ENTRY node;
	struct virt2phys_block *cur;

	for (node = process->blocks.Next; node != NULL; node = node->Next) {
		cur = CONTAINING_RECORD(node, struct virt2phys_block, next);
		if (cur->mdl->StartVa == virt)
			return cur;
	}
	return NULL;
}

NTSTATUS
virt2phys_init(void)
{
	g_lock = ExAllocatePoolZero(NonPagedPool, sizeof(*g_lock), 'gp2v');
	if (g_lock == NULL)
		return STATUS_INSUFFICIENT_RESOURCES;

	InitializeListHead(&g_processes);

	return STATUS_SUCCESS;
}

void
virt2phys_cleanup(void)
{
	PLIST_ENTRY node, next;
	struct virt2phys_process *process;
	KIRQL irql;

	KeAcquireSpinLock(g_lock, &irql);
	for (node = g_processes.Flink; node != &g_processes; node = next) {
		next = node->Flink;
		process = CONTAINING_RECORD(node, struct virt2phys_process, next);
		RemoveEntryList(&process->next);
		KeReleaseSpinLock(g_lock, irql);

		virt2phys_process_free(process, FALSE);

		KeAcquireSpinLock(g_lock, &irql);
	}
	KeReleaseSpinLock(g_lock, irql);
}

static struct virt2phys_process *
virt2phys_process_detach(HANDLE process_id)
{
	struct virt2phys_process *process;

	process = virt2phys_process_find(process_id);
	if (process != NULL)
		RemoveEntryList(&process->next);
	return process;
}

void
virt2phys_process_cleanup(HANDLE process_id)
{
	struct virt2phys_process *process;
	KIRQL irql;

	KeAcquireSpinLock(g_lock, &irql);
	process = virt2phys_process_detach(process_id);
	KeReleaseSpinLock(g_lock, irql);

	if (process != NULL)
		virt2phys_process_free(process, TRUE);
}

static struct virt2phys_block *
virt2phys_find_block(HANDLE process_id, void *virt,
	struct virt2phys_process **process)
{
	PLIST_ENTRY node;
	struct virt2phys_process *cur;

	for (node = g_processes.Flink; node != &g_processes;
			node = node->Flink) {
		cur = CONTAINING_RECORD(node, struct virt2phys_process, next);
		if (cur->id == process_id) {
			*process = cur;
			return virt2phys_process_find_block(cur, virt);
		}
	}

	*process = NULL;
	return NULL;
}

static BOOLEAN
virt2phys_exceeeds(LONG64 count, ULONG64 limit)
{
	return limit > 0 && count > (LONG64)limit;
}

static BOOLEAN
virt2phys_add_block(struct virt2phys_process *process,
	struct virt2phys_block *block)
{
	struct virt2phys_process *existing;

	existing = virt2phys_process_find(process->id);
	if (existing == NULL)
		InsertHeadList(&g_processes, &process->next);
	else
		process = existing;

	PushEntryList(&process->blocks, &block->next);

	return existing != NULL;
}

static NTSTATUS
virt2phys_query_memory(void *virt, void **base, size_t *size)
{
	MEMORY_BASIC_INFORMATION info;
	SIZE_T info_size;
	NTSTATUS status;

	status = ZwQueryVirtualMemory(
		ZwCurrentProcess(), virt, MemoryBasicInformation,
		&info, sizeof(info), &info_size);
	if (NT_SUCCESS(status)) {
		*base = info.AllocationBase;
		*size = info.RegionSize;
	}
	return status;
}

static BOOLEAN
virt2phys_is_contiguous(PMDL mdl)
{
	PPFN_NUMBER pfn;
	size_t i, pfn_count;

	pfn = MmGetMdlPfnArray(mdl);
	pfn_count = ADDRESS_AND_SIZE_TO_SPAN_PAGES(
		MmGetMdlVirtualAddress(mdl), MmGetMdlByteCount(mdl));
	for (i = 1; i < pfn_count; i++) {
		if (pfn[i] != pfn[i - 1] + 1)
			return FALSE;
	}
	return TRUE;
}

static NTSTATUS
virt2phys_check_memory(PMDL mdl)
{
	MEMORY_BASIC_INFORMATION info;
	SIZE_T info_size;
	PVOID virt;
	size_t size;
	NTSTATUS status;

	if (!virt2phys_is_contiguous(mdl))
		return STATUS_UNSUCCESSFUL;

	virt = MmGetMdlVirtualAddress(mdl);
	size = MmGetMdlByteCount(mdl);
	status = ZwQueryVirtualMemory(
		ZwCurrentProcess(), virt, MemoryBasicInformation,
		&info, sizeof(info), &info_size);
	if (!NT_SUCCESS(status))
		return status;

	if (info.AllocationBase != virt || info.RegionSize != size)
		return STATUS_UNSUCCESSFUL;
	if (info.State != MEM_COMMIT)
		return STATUS_UNSUCCESSFUL;
	if (info.Type != MEM_PRIVATE)
		return STATUS_UNSUCCESSFUL;
	return status;
}

static NTSTATUS
virt2phys_lock_memory(void *virt, size_t size, PMDL *mdl)
{
	*mdl = IoAllocateMdl(virt, (ULONG)size, FALSE, FALSE, NULL);
	if (*mdl == NULL)
		return STATUS_INSUFFICIENT_RESOURCES;

	__try {
		/* Future memory usage is unknown, declare RW access. */
		MmProbeAndLockPages(*mdl, UserMode, IoModifyAccess);
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		IoFreeMdl(*mdl);
		*mdl = NULL;
		return STATUS_UNSUCCESSFUL;
	}
	return STATUS_SUCCESS;
}

static VOID
virt2phys_unlock_memory(PMDL mdl)
{
	MmUnlockPages(mdl);
	IoFreeMdl(mdl);
}

NTSTATUS
virt2phys_translate(PVOID virt, PHYSICAL_ADDRESS *phys)
{
	PMDL mdl;
	HANDLE process_id;
	void *base;
	size_t size;
	struct virt2phys_process *process;
	struct virt2phys_block *block;
	BOOLEAN created, tracked;
	KIRQL irql;
	NTSTATUS status;

	process_id = PsGetCurrentProcessId();

	status = virt2phys_query_memory(virt, &base, &size);
	if (!NT_SUCCESS(status))
		return status;

	KeAcquireSpinLock(g_lock, &irql);
	block = virt2phys_find_block(process_id, base, &process);
	KeReleaseSpinLock(g_lock, irql);

	/* Don't lock the same memory twice. */
	if (block != NULL) {
		*phys = virt2phys_block_translate(block, virt);
		return STATUS_SUCCESS;
	}

	status = virt2phys_lock_memory(base, size, &mdl);
	if (!NT_SUCCESS(status))
		return status;

	status = virt2phys_check_memory(mdl);
	if (!NT_SUCCESS(status)) {
		virt2phys_unlock_memory(mdl);
		return status;
	}

	block = virt2phys_block_create(mdl);
	if (block == NULL) {
		virt2phys_unlock_memory(mdl);
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	created = FALSE;
	if (process == NULL) {
		process = virt2phys_process_create(process_id);
		if (process == NULL) {
			virt2phys_block_free(block, TRUE);
			return STATUS_INSUFFICIENT_RESOURCES;
		}
		created = TRUE;
	}

	KeAcquireSpinLock(g_lock, &irql);
	tracked = virt2phys_add_block(process, block);
	KeReleaseSpinLock(g_lock, irql);

	/* Same process has been added concurrently, block attached to it. */
	if (tracked && created)
		virt2phys_process_free(process, FALSE);

	*phys = virt2phys_block_translate(block, virt);
	return STATUS_SUCCESS;
}
