#include "penglai-enclave-elfloader.h"

#define	ROUND_TO(x, align)  (((x) + ((align)-1)) & ~((align)-1))

int penglai_enclave_load_NOBITS_section(enclave_mem_t* enclave_mem, void * elf_sect_addr, int elf_sect_size)
{
	vaddr_t addr;
	vaddr_t enclave_new_page;
	int size;
	for(addr = (vaddr_t)elf_sect_addr; addr < (vaddr_t)elf_sect_addr + elf_sect_size; addr += RISCV_PGSIZE)
	{
		enclave_new_page = enclave_alloc_page(enclave_mem, addr, ENCLAVE_USER_PAGE);
		if (addr + RISCV_PGSIZE >(vaddr_t) elf_sect_addr + elf_sect_size)
			size = elf_sect_size % RISCV_PGSIZE;
		else
			size = RISCV_PGSIZE;
		memset((void *) enclave_new_page, 0, size);
	}
	return 0;
}

/* elf_prog_infile_addr @ content in elf file
   elf_prog_addr @ virtual addr for program begin addr
   elf_prog_size @ size of prog segment
   */
int penglai_enclave_load_program(enclave_mem_t* enclave_mem, vaddr_t elf_prog_infile_addr, void * elf_prog_addr, int elf_prog_size)
{
	vaddr_t addr;
	vaddr_t enclave_new_page;
	int size;
	int r;
	for(addr =  (vaddr_t)elf_prog_addr; addr <  (vaddr_t)elf_prog_addr + elf_prog_size; addr += RISCV_PGSIZE)
	{

		enclave_new_page = enclave_alloc_page(enclave_mem, addr, ENCLAVE_USER_PAGE);
		if (addr + RISCV_PGSIZE > (vaddr_t)elf_prog_addr + elf_prog_size)
			size = elf_prog_size % RISCV_PGSIZE;
		else
			size = RISCV_PGSIZE;
		r = copy_from_user((void* )enclave_new_page, (void *)(elf_prog_infile_addr + addr - (vaddr_t)elf_prog_addr), size);
	}
	return 0;
}

/* ptr @ user pointer
   hdr @ kernel pointer
   */
int penglai_enclave_loadelf(enclave_mem_t*enclave_mem, void* __user elf_ptr, unsigned long size, vaddr_t * elf_entry_point, meta_area_t* enclave_meta)
{
	struct  elfhdr elf_hdr;
	struct elf_phdr elf_prog_hdr;
	struct elf_shdr elf_sect_hdr, shstrtab_hdr;
	struct elf_note note;
	int i,  elf_prog_size;
	vaddr_t elf_sect_ptr, elf_prog_ptr, elf_prog_addr, elf_prog_infile_addr, elf_meta_area;
	int found_metadata_section = 0;
	char *shstrtab, *note_name;
	const char * meta_name = "penglai_metadata";

	if(copy_from_user(&elf_hdr, elf_ptr, sizeof(struct elfhdr)) != 0)
	{
		printk("KERNEL MODULE:  elf_hdr copy_from_user failed\n");
		return -1;
	}
	*elf_entry_point = elf_hdr.e_entry;
	elf_sect_ptr = (vaddr_t) elf_ptr + elf_hdr.e_shoff;
	if (copy_from_user(&shstrtab_hdr, (void*)((struct elf_shdr*)elf_sect_ptr + elf_hdr.e_shstrndx), sizeof(struct elf_shdr))){
		printk("KERNEL MODULE:  shstrtab_hdr copy_from_user failed\n");
		return -1;
	}
	shstrtab = kmalloc(shstrtab_hdr.sh_size, GFP_KERNEL);
	if (copy_from_user(shstrtab, (void*)((vaddr_t)elf_ptr + shstrtab_hdr.sh_offset), shstrtab_hdr.sh_size)){
		printk("KERNEL MODULE:  shstrtab copy_from_user failed\n");
		kfree(shstrtab);
		return -1;
	}
	
	/* Loader section */
	for (i = 0; i < elf_hdr.e_shnum;i++)
	{
		if (copy_from_user(&elf_sect_hdr,(void *)elf_sect_ptr,sizeof(struct elf_shdr)))
		{
			printk("KERNEL MODULE: elf_sect_hdr copy_from_user failed\n");
			elf_sect_ptr += sizeof(struct elf_shdr);
			continue;
		}
		if (!strcmp(shstrtab + elf_sect_hdr.sh_name, ".note.penglaimeta")){
			found_metadata_section = 1;
			if (copy_from_user(&note, (void*)((vaddr_t)elf_ptr + elf_sect_hdr.sh_offset), sizeof(struct elf_note))){
				printk("KERNEL MODULE:  metadata elf_note copy_from_user failed\n");
				kfree(shstrtab);
				return -1;
			}
			if (elf_sect_hdr.sh_size != ROUND_TO(sizeof(struct elf_note) + note.n_namesz + note.n_descsz, elf_sect_hdr.sh_addralign))
			{
				printk("ERROR: The '.note.penglaimeta' section size is not correct.\n");
				kfree(shstrtab);
				return -1;
			}
			note_name = kmalloc(note.n_namesz, GFP_KERNEL);
			if (copy_from_user(note_name, (void*)((vaddr_t)elf_ptr + elf_sect_hdr.sh_offset + sizeof(struct elf_note)), note.n_namesz)){
				printk("KERNEL MODULE:  metadata elf_note name copy_from_user failed\n");
			}
			if (note.n_namesz != (strlen(meta_name)+1) || memcmp(note_name, meta_name, note.n_namesz))
			{
				printk("ERROR: The note in the '.note.penglaimeta' section must be named as \"penglai_metadata\"\n");
				kfree(note_name);
				kfree(shstrtab);
				return -1;
			}
			kfree(note_name);
			elf_meta_area = (vaddr_t)elf_ptr + elf_sect_hdr.sh_offset + sizeof(struct elf_note) + note.n_namesz;
			if (copy_from_user(enclave_meta->body, (void *)elf_meta_area, METADATA_SIZE)){
				printk("KERNEL MODULE:  metadata copy_from_user failed\n");
				kfree(shstrtab);
				return -1;
			}
			printk("SUCCESS: load metadata successfully!\n");
		}
		if (elf_sect_hdr.sh_addr == 0)
		{
			elf_sect_ptr += sizeof(struct elf_shdr);
			continue;
		}

		/* Load NOBITS section */
		if (elf_sect_hdr.sh_type == SHT_NOBITS)
		{
			vaddr_t elf_sect_addr = elf_sect_hdr.sh_addr;
			int elf_sect_size = elf_sect_hdr.sh_size;
			printk("[penglai_enclave_loadelf] Load NOBITS section: sh_addr: 0x%08x%08x, sh_size: %d\n",*((int*)&elf_sect_addr+1), *((int*)&elf_sect_addr), elf_sect_size);
			if (penglai_enclave_load_NOBITS_section(enclave_mem,(void *)elf_sect_addr,elf_sect_size) < 0)
			{
				printk("KERNEL MODULE: penglai enclave load NOBITS  section failed\n");
				kfree(shstrtab);
				return -1;
			}
		}
		elf_sect_ptr += sizeof(struct elf_shdr);
	}

	kfree(shstrtab);
	if (found_metadata_section == 0){
		printk("ERROR: The enclave image should have '.note.penglaimeta' section\n");
		return -1;
	}

	/* Load program segment */
	elf_prog_ptr = (vaddr_t) elf_ptr + elf_hdr.e_phoff;

	for(i = 0; i < elf_hdr.e_phnum;i++)
	{
		if (copy_from_user(&elf_prog_hdr,(void *)elf_prog_ptr,sizeof(struct elf_phdr)))
		{
			printk("KERNEL MODULE: elf_prog_hdr copy_from_user failed\n");
			elf_prog_ptr += sizeof(struct elf_phdr);
			continue;
		}

		/* Virtual addr for program begin address */
		elf_prog_addr = elf_prog_hdr.p_vaddr;
		elf_prog_size = elf_prog_hdr.p_filesz;
		elf_prog_infile_addr = (vaddr_t) elf_ptr + elf_prog_hdr.p_offset;
		printk("[penglai_enclave_loadelf] Load program segment: prog_addr: 0x%08x%08x, prog_size: %d\n",*((int*)&elf_prog_addr+1), *((int*)&elf_prog_addr), elf_prog_size);
		if (penglai_enclave_load_program(enclave_mem, elf_prog_infile_addr, (void *)elf_prog_addr, elf_prog_size) < 0)
		{
			printk("KERNEL MODULE: penglai enclave load program failed\n");
			return -1;
		}
		printk("[Penglai Driver@%s] elf_prog_addr:0x%lx elf_prog_size:0x%x, infile_addr:0x%lx", __func__,
				elf_prog_addr, elf_prog_size, elf_prog_infile_addr);
		elf_prog_ptr += sizeof(struct elf_phdr);
	}
	return 0;
}

int penglai_enclave_elfmemsize(void* __user elf_ptr, int* size)
{
	struct elfhdr elf_hdr;
	struct elf_phdr elf_prog_hdr;
	struct elf_shdr elf_sect_hdr;
	int i, elf_prog_size;
	vaddr_t elf_sect_ptr, elf_prog_ptr;
	if(copy_from_user(&elf_hdr, elf_ptr, sizeof(struct elfhdr)) != 0)
	{
		printk("[Penglai Driver@%s] elf_hdr copy_from_user failed\n", __func__);
		return -1;
	}
	elf_sect_ptr = (vaddr_t) elf_ptr + elf_hdr.e_shoff;

	for (i = 0; i < elf_hdr.e_shnum;i++)
	{
		if (copy_from_user(&elf_sect_hdr,(void *)elf_sect_ptr,sizeof(struct elf_shdr)))
		{
			printk("[Penglai Driver@%s] elf_sect_hdr copy_from_user failed\n", __func__);
			elf_sect_ptr += sizeof(struct elf_shdr);
			return -1;
		}
		if (elf_sect_hdr.sh_addr == 0)
		{
			elf_sect_ptr += sizeof(struct elf_shdr);
			continue;
		}

		// Calculate the size of the NOBITS section
		if (elf_sect_hdr.sh_type == SHT_NOBITS)
		{
			int elf_sect_size = elf_sect_hdr.sh_size;
			*size = *size + elf_sect_size;
		}
		elf_sect_ptr += sizeof(struct elf_shdr);
	}

	// Calculate the size of the PROGBITS segment
	elf_prog_ptr = (vaddr_t) elf_ptr + elf_hdr.e_phoff;

	for(i = 0; i < elf_hdr.e_phnum;i++)
	{
		if (copy_from_user(&elf_prog_hdr,(void *)elf_prog_ptr,sizeof(struct elf_phdr)))
		{
			printk("[Penglai Driver@%s] elf_prog_hdr copy_from_user failed\n", __func__);
			elf_prog_ptr += sizeof(struct elf_phdr);
			return -1;
		}

		// Virtual addr for program begin address
		elf_prog_size = elf_prog_hdr.p_filesz;
		*size = *size + elf_prog_size;
		elf_prog_ptr += sizeof(struct elf_phdr);
	}
	return 0;
}

int penglai_enclave_eapp_preprare(enclave_mem_t* enclave_mem,  void* __user elf_ptr, unsigned long size, vaddr_t * elf_entry_point, vaddr_t stack_ptr, int stack_size, meta_area_t* enclave_meta)
{
	vaddr_t addr;

	/* Init stack */
	for(addr = stack_ptr - stack_size; addr < stack_ptr; addr += RISCV_PGSIZE)
	{
		enclave_alloc_page(enclave_mem, addr, ENCLAVE_STACK_PAGE);
	}

	/* Load elf file */
	if(penglai_enclave_loadelf(enclave_mem, elf_ptr, size, elf_entry_point, enclave_meta) < 0)
	{
		printk("KERNEL MODULE: penglai enclave loadelf failed\n");
	}

	return 0;
}

int map_untrusted_mem(enclave_mem_t* enclave_mem, vaddr_t vaddr, paddr_t paddr, unsigned long size)
{
	vaddr_t addr = vaddr;

	for (; addr < vaddr + size; addr+=RISCV_PGSIZE) {
		map_va2pa(enclave_mem, addr, paddr, ENCLAVE_UNTRUSTED_PAGE);
		paddr += RISCV_PGSIZE;
	}
	return 0;
}

int map_kbuffer(enclave_mem_t* enclave_mem, vaddr_t vaddr, paddr_t paddr, unsigned long size)
{
	vaddr_t addr = vaddr;

	for (; addr < vaddr + size; addr += RISCV_PGSIZE) {
		map_va2pa(enclave_mem, addr, paddr, ENCLAVE_KBUFFER_PAGE);
		paddr += RISCV_PGSIZE;
	}
	return 0;
}
