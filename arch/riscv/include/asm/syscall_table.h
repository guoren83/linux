#include <asm/bitsperlong.h>

#if __riscv_xlen == 64
#include <asm/syscall_table_64.h>
#else
#include <asm/syscall_table_32.h>
#endif
