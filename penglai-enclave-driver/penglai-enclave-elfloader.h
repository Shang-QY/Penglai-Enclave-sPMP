#ifndef  _PENGLAI_ENCLAVE_ELFLOADER
#define _PENGLAI_ENCLAVE_ELFLOADER
#include <linux/elf.h>
#include "penglai-enclave-page.h"

#define METADATA_SIZE  (1 << RISCV_PT_SHIFT)

typedef struct _meta_area_t{
	unsigned char body[METADATA_SIZE];
} meta_area_t;

int penglai_enclave_eapp_preprare(
		enclave_mem_t* enclave_mem,  
		void* __user elf_ptr, 
		unsigned long size, 
		vaddr_t * elf_entry_point, 
		vaddr_t stack_ptr, 
		int stack_size,
		meta_area_t* enclave_meta);
int map_untrusted_mem(
		enclave_mem_t* enclave_mem, 
		vaddr_t vaddr, 
		paddr_t paddr, 
		unsigned long size);
int map_kbuffer(
		enclave_mem_t* enclave_mem,
		vaddr_t vaddr,
		paddr_t paddr,
		unsigned long size);
int penglai_enclave_elfmemsize(void* __user elf_ptr, int* size);

#endif
