/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2021 Dmitry Kozlyuk
 */

#ifndef VIRT2PHYS_LOGIC_H
#define VIRT2PHYS_LOGIC_H

/**
 * Initialize internal data structures.
 */
NTSTATUS virt2phys_init(void);

/**
 * Free memory allocated for internal data structures.
 * Do not unlock memory so that it's not paged even if driver is unloaded
 * when an application still uses this memory.
 */
void virt2phys_cleanup(void);

/**
 * Unlock all tracked memory blocks of a process.
 * Free memory allocated for tracking of the process.
 */
void virt2phys_process_cleanup(HANDLE process_id);

/**
 * Lock current process memory region containing @p virt
 * and get physical address corresponding to @p virt.
 */
NTSTATUS virt2phys_translate(PVOID virt, PHYSICAL_ADDRESS *phys);

#endif /* VIRT2PHYS_LOGIC_H */
