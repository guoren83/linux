#include <asm/bitsperlong.h>

#ifdef CONFIG_64BIT
#include <asm/syscall_table_64.h>
#else
#include <asm/syscall_table_32.h>
#endif
