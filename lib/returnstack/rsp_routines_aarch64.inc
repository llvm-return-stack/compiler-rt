//===-- rsp_routines_aarch64.inc ------------------------------------------===//
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
// Author: Philipp Zieris <philipp.zieris@aisec.fraunhofer.de>
//
//===----------------------------------------------------------------------===//
//
// This file provides macros for return stack manipulation on ARM64.
//
//===----------------------------------------------------------------------===//

#define asm_pop_rsp(value) \
  asm volatile ("ldr %0, [x28, #-8]!" \
               : "=r" (value) \
               : /* No inputs */ \
               : "x28")

#define asm_push_rsp(value) \
  asm volatile ("str %0, [x28], #8" \
               : /* No outputs */ \
               : "r" (value) \
               : "x28")

#define asm_read_rsp(rsp) \
  asm volatile ("mov %0, x28" \
               : "=r" (rsp))

#define asm_unwind_rsp(marker) \
  asm volatile ("rs_unwind:" \
                "ldr x0, [x28, #-8]!;" \
                "cmp x0, %0;" \
                "bne rs_unwind;" \
               : /* No outputs */ \
               : "r" (marker) \
               : "cc", "x0", "x28")

#define asm_write_rsp(rsp) \
  asm volatile ("mov x28, %0" \
               : /* No outputs */ \
               : "r" (rsp) \
               : "x28");

