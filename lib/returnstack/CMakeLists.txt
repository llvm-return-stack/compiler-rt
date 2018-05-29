add_compiler_rt_component(returnstack)

set(RETURNSTACK_SOURCES returnstack.cc)

include_directories(..)

set(RETURNSTACK_CFLAGS ${SANITIZER_COMMON_CFLAGS})

if (COMPILER_RT_DEFAULT_TARGET_ARCH STREQUAL "aarch64")
  list(APPEND RETURNSTACK_CFLAGS "-ffixed-x28")
elseif (COMPILER_RT_DEFAULT_TARGET_ARCH STREQUAL "x86_64")
  list(APPEND RETURNSTACK_CFLAGS "-ffixed-r15")
endif ()

foreach(arch ${RETURNSTACK_SUPPORTED_ARCH})
  add_compiler_rt_runtime(clang_rt.returnstack
    STATIC
    ARCHS ${arch}
    SOURCES ${RETURNSTACK_SOURCES}
            $<TARGET_OBJECTS:RTInterception.${arch}>
    CFLAGS ${RETURNSTACK_CFLAGS}
    PARENT_TARGET returnstack)
endforeach()

