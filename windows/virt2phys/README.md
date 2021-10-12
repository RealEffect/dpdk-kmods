Virtual to Physical Address Translator
======================================

Purpose and Operation
---------------------

``virt2phys`` driver allows user-mode processes to obtain physical address
of a given virtual address in their address space.
Virtual addresses must belong to regions from process private working set.
These regions must be physically contiguous.
The driver ensures that memory regions with translated addresses
are not swapped out as long as the process has access to this memory.

It is not safe to administratively unload the driver
while there are processes that have used virt2phys to translate addresses.
Doing so will permanently leak RAM occupied by all memory regions
that contain translated addresses.
Terminate all such processes before unloading the driver.

Configuration
-------------

``virt2phys`` is configured at loading time via registry key
``HKLM\SYSTEM\ControlSet001\Services\virt2phys\Parameters``.

* ``ProcessCountLimit`` (default 16)

  Maximum number of processes that can have access to memory regions
  with translated addresses. When this limit is reached, no more processes
  can translate addresses using ``virt2phys``. Large number of tracked
  processes may slow down system operation. Set limit to 0 to disable it.

* ``ProcessMemoryLimitMB`` (default 16384, i.e. 16 GB)

  Maximum amount of memory in all regions that contain translated addresses,
  total per process. When this limit is reached, the process can not translate
  addresses from new regions. Large values can cause RAM exhaustion.
  Set limit to 0 to disable it.