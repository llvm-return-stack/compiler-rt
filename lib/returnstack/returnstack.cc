//===-- returnstack.cc ----------------------------------------------------===//
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
// Author: Philipp Zieris <philipp.zieris@aisec.fraunhofer.de>
//
//===----------------------------------------------------------------------===//
//
// This file implements the runtime support for the return stack protection
// mechanism. The runtime manages allocation/deallocation of return stacks
// for the main thread, as well as all pthreads that are created/destroyed
// during program execution.
//
//===----------------------------------------------------------------------===//

#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/random.h>
#include <unistd.h>

#include "interception/interception.h"

using namespace __sanitizer;

#if defined(__aarch64__)
#include "rsp_routines_aarch64.inc"
#elif defined(__x86_64__)
#include "rsp_routines_x86_64.inc"
#else
#error "Return stack runtime support not available for this architecture."
#endif

/// Page size obtained at runtime.
static unsigned pageSize;

/// Base address of the return stack region (not a secret information).
static uptr ReturnStackRegionBase;

/// The size of the return stack region is dependant on the architecture's user
/// space size. The maximum return stack region size is 16 TB, which results in
/// 32 entropy bits for randomizing return stacks.
///
/// Architecture   User space   Return stack region   Entropy
/// ARM64            256 TB            16 TB          32 bits
/// x86-64           128 TB            16 TB          32 bits
#if defined(__aarch64__)
const unsigned long kReturnStackRegionSize = 0x100000000000UL;
#elif defined(__x86_64__)
const unsigned long kReturnStackRegionSize = 0x100000000000UL;
#endif

/// Number of return stack pages.
const unsigned kReturnStackPages = 8;

/// Number of guard pages.
const unsigned kReturnStackGuardPages = 1;

/// Marker placed on the return stack between metadata and return addresses.
#if SANITIZER_WORDSIZE == 64
const unsigned long kReturnStackMarker = 0xffffffffffffffff;
#else
const unsigned long kReturnStackMarker = 0xffffffff;
#endif

typedef struct thread_start {
  void *(*start_routine)(void *);
  void *arg;
} thread_start_t;

static void NORETURN terminate(char const *message) {
  fprintf(stderr, "Return stack runtime error: %s.\n", message);
  exit(EXIT_FAILURE);
}

static inline void return_stack_region_create() {
  uptr addr;

  // Allocate the return stack region.
  addr = (uptr)mmap(0, kReturnStackRegionSize, PROT_NONE,
                    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (addr == (uptr)-1)
    terminate("Failed to allocate the return stack region");

  ReturnStackRegionBase = addr;
}

static inline bool contains_return_stack(uptr addr, size_t size) {
  int fd[2];
  uptr end;

  // Open pipe for writing.
  if (pipe(fd) == -1)
    terminate("Failed to open pipe");

  // Try to read from each page within the range.
  end = addr + size;
  while (addr < end) {
    if (write(fd[1], (void *)addr, 1) != 1)
      return false;
    addr += pageSize;
  }

  return true;
}

static void return_stack_create() {
  size_t guardsize, stacksize;
  uptr addr;
  ssize_t len = sizeof(uptr);

  // Calculate guard and stack sizes.
  guardsize = kReturnStackGuardPages * pageSize;
  stacksize = kReturnStackPages * pageSize;

  // Randomly choose a new return stack and set its access permissions.
  while (1) {
    if (getrandom(&addr, len, 0) < len)
      terminate("Failed to get random offset");
    addr %= kReturnStackRegionSize - stacksize - guardsize;
    addr &= ~((uptr)pageSize - 1);
    addr += ReturnStackRegionBase;
    if (!contains_return_stack(addr, stacksize + 2 * guardsize)) {
      if (mprotect((void *)(addr + guardsize), stacksize, PROT_READ | PROT_WRITE) == -1)
        terminate("Failed to set access permissions for return stack");
      break;
    }
  }

  // Write base address of return stack to the RSP register.
  asm_write_rsp((void *)(addr + guardsize));
  addr = 0;

  // Push stack size and marker.
  asm_push_rsp(stacksize);
  asm_push_rsp(kReturnStackMarker);
}

static void return_stack_destroy(void *arg) {
  size_t stacksize;
  uptr addr;

  // Unwind return stack until the marker is hit.
  asm_unwind_rsp(kReturnStackMarker);

  // Read stack size and base address.
  asm_pop_rsp((size_t)stacksize);
  asm_read_rsp((uptr)addr);

  // Remove access permissions from return stack.
  if (mprotect((void *)addr, stacksize, PROT_NONE) == -1)
    terminate("Failed to remove access permissions from return stack.");
}

static void *thread_start(void *ts) {

  void *(*start_routine)(void *) = ((thread_start_t *)ts)->start_routine;
  void *arg = ((thread_start_t *)ts)->arg;

  memset(ts, 0, sizeof(thread_start_t));
  free(ts);

  // Create return stack for the new thread.
  return_stack_create();

  // Push our clean-up handler on the thread-cancellation stack.
  pthread_cleanup_push(return_stack_destroy, NULL);

  // Call the actual start routine.
  start_routine(arg);

  // Pop our clean-up handler.
  pthread_cleanup_pop(NULL);

  return NULL;
}

INTERCEPTOR(int, pthread_create, pthread_t *thread,
            const pthread_attr_t *attr,
            void *(*start_routine)(void*), void *arg) {

  // This memory is freed by thread_start.
  thread_start_t *ts = (thread_start_t *)malloc(sizeof(thread_start_t));
  if (ts == NULL)
    terminate("Malloc failure");
  memset(ts, 0, sizeof(thread_start_t));
  ts->start_routine = start_routine;
  ts->arg = arg;

  return REAL(pthread_create)(thread, attr, thread_start, ts);
}

extern "C"
__attribute__((visibility("default"))) void __return_stack_init() {

  // Get the page size.
  if ((pageSize = sysconf(_SC_PAGESIZE)) == (unsigned)-1)
    terminate("Failed to retrieve page size");

  // Create the return stack region and allocate a return stack for the main
  // thread.
  return_stack_region_create();
  return_stack_create();

  // Initialize the pthread interceptor for thread allocation.
  INTERCEPT_FUNCTION(pthread_create);
}

extern "C" {
__attribute__((section(".preinit_array"), used))
                      void (*__returnstack_preinit)(void) = __return_stack_init;
}

