/* Native macro definitions for GDB on an Intel i[3456]86.
   Copyright 2001, 2004, 2007, 2008 Free Software Foundation, Inc.

   This file is part of GDB.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.  */

#ifndef NM_I386_H
#define NM_I386_H 1

/* Hardware-assisted breakpoints and watchpoints.  */

/* Targets should define this to use the generic x86 watchpoint support.  */
#ifdef I386_USE_GENERIC_WATCHPOINTS

/* Add watchpoint methods to the provided target_ops.  Targets which call
   this should also define I386_WATCHPOINTS_IN_TARGET_VECTOR.  */
struct target_ops;
void i386_use_watchpoints (struct target_ops *);

/* Clear the reference counts and forget everything we knew about DRi.  */
extern void i386_cleanup_dregs (void);

/* Insert a watchpoint to watch a memory region which starts at
   address ADDR and whose length is LEN bytes.  Watch memory accesses
   of the type TYPE.  Return 0 on success, -1 on failure.  */
extern int i386_insert_watchpoint (CORE_ADDR addr, int len, int type);

/* Remove a watchpoint that watched the memory region which starts at
   address ADDR, whose length is LEN bytes, and for accesses of the
   type TYPE.  Return 0 on success, -1 on failure.  */
extern int i386_remove_watchpoint (CORE_ADDR addr, int len, int type);

/* Return non-zero if we can watch a memory region that starts at
   address ADDR and whose length is LEN bytes.  */
extern int i386_region_ok_for_watchpoint (CORE_ADDR addr, int len);

/* Return non-zero if the inferior has some break/watchpoint that
   triggered.  */
extern int i386_stopped_by_hwbp (void);

/* If the inferior has some break/watchpoint that triggered, set
   the address associated with that break/watchpoint and return
   true.  Otherwise, return false.  */
extern int i386_stopped_data_address (struct target_ops *, CORE_ADDR *);

/* Insert a hardware-assisted breakpoint at BP_TGT->placed_address.
   Return 0 on success, EBUSY on failure.  */
struct bp_target_info;
extern int i386_insert_hw_breakpoint (struct bp_target_info *bp_tgt);

/* Remove a hardware-assisted breakpoint at BP_TGT->placed_address.
   Return 0 on success, -1 on failure.  */
extern int  i386_remove_hw_breakpoint (struct bp_target_info *bp_tgt);

extern int i386_stopped_by_watchpoint (void);

#ifndef I386_WATCHPOINTS_IN_TARGET_VECTOR

/* Returns the number of hardware watchpoints of type TYPE that we can
   set.  Value is positive if we can set CNT watchpoints, zero if
   setting watchpoints of type TYPE is not supported, and negative if
   CNT is more than the maximum number of watchpoints of type TYPE
   that we can support.  TYPE is one of bp_hardware_watchpoint,
   bp_read_watchpoint, bp_write_watchpoint, or bp_hardware_breakpoint.
   CNT is the number of such watchpoints used so far (including this
   one).  OTHERTYPE is non-zero if other types of watchpoints are
   currently enabled.

   We always return 1 here because we don't have enough information
   about possible overlap of addresses that they want to watch.  As an
   extreme example, consider the case where all the watchpoints watch
   the same address and the same region length: then we can handle a
   virtually unlimited number of watchpoints, due to debug register
   sharing implemented via reference counts in i386-nat.c.  */

#define TARGET_CAN_USE_HARDWARE_WATCHPOINT(type, cnt, ot) 1

/* Returns non-zero if we can use hardware watchpoints to watch a
   region whose address is ADDR and whose length is LEN.  */

#define TARGET_REGION_OK_FOR_HW_WATCHPOINT(addr, len) \
  i386_region_ok_for_watchpoint (addr, len)

/* After a watchpoint trap, the PC points to the instruction after the
   one that caused the trap.  Therefore we don't need to step over it.
   But we do need to reset the status register to avoid another trap.  */

#define HAVE_CONTINUABLE_WATCHPOINT 1

#define STOPPED_BY_WATCHPOINT(W)       (i386_stopped_by_watchpoint () != 0)

#define target_stopped_data_address(target, x) \
  i386_stopped_data_address(target, x)

/* Use these macros for watchpoint insertion/removal.  */

#define target_insert_watchpoint(addr, len, type) \
  i386_insert_watchpoint (addr, len, type)

#define target_remove_watchpoint(addr, len, type) \
  i386_remove_watchpoint (addr, len, type)

#define target_insert_hw_breakpoint(bp_tgt) \
  i386_insert_hw_breakpoint (bp_tgt)

#define target_remove_hw_breakpoint(bp_tgt) \
  i386_remove_hw_breakpoint (bp_tgt)

#endif /* I386_WATCHPOINTS_IN_TARGET_VECTOR */

#endif /* I386_USE_GENERIC_WATCHPOINTS */

#endif /* NM_I386_H */
