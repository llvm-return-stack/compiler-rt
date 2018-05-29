//===-- rsp_routines_x86_64.inc -------------------------------------------===//
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
// Author: Philipp Zieris <philipp.zieris@aisec.fraunhofer.de>
//
//===----------------------------------------------------------------------===//
//
// This file provides macros for return stack manipulation on x86-64.
//
//===----------------------------------------------------------------------===//

#define asm_pop_rsp(value) \
  asm volatile ("lea -0x8(%%r15), %%r15;" \
                "mov (%%r15), %0;" \
               : "=r" (value) \
               : /* No inputs */ \
               : "r15")

#define asm_push_rsp(value) \
  asm volatile ("mov %0, (%%r15);" \
                "lea 0x8(%%r15), %%r15;" \
               : /* No outputs */ \
               : "r" (value) \
               : "r15")

#define asm_read_rsp(rsp) \
  asm volatile ("movq %%r15, %0" \
               : "=r" (rsp))

#define asm_unwind_rsp(marker) \
  asm volatile ("rs_unwind:" \
                "lea -0x8(%%r15), %%r15;" \
                "cmp (%%r15), %0;" \
                "jne rs_unwind;" \
               : /* No outputs */ \
               : "r" (marker) \
               : "cc", "r15")

#define asm_write_rsp(rsp) \
  asm volatile ("mov %0, %%r15" \
               : /* No outputs */ \
               : "r" (rsp) \
               : "r15")

