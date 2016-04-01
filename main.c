#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/mman.h>
#include "elf2.h"

/*elf machine*/
#define EM_NONE			0
#define EM_M32			1
#define EM_SPARC		2
#define EM_386			3
#define EM_68k			4
#define EM_88k			5
#define EM_860			7
#define EM_MIPS			8
#define EM_ARM			40
#define CHECK_ELF_MACHINE(p)		((p)->e_machine)
#define CHECK_ELF_MACHINE_ARM(p)	(CHECK_ELF_MACHINE(p)==EM_ARM)

struct funcStr {
	char *name;
	unsigned int offset;
	struct funcStr *next;
};

void showElf64Hdr(Elf64_Ehdr *ehdr)
{
	printf("elf type : ");
	switch (ehdr->e_type) {
		case ET_NONE	: printf("NONE\n");break;
		case ET_REL	: printf("REL\n"); break;
		case ET_EXEC	: printf("EXEC\n"); break;
		case ET_DYN	: printf("DYN\n"); break;
		case ET_CORE	: printf("CORE\n"); break;
		case ET_LOPROC	: printf("LOPROC\n"); break;
		case ET_HIPROC	: printf("HIPROC\n"); break;
		default		: printf("\n");break;
	};

	printf("elf machine [%02x]: ",ehdr->e_machine);
	switch (ehdr->e_machine) {
		case EM_NONE	: printf("NONE\n");break;
		case EM_M32	: printf("M32\n"); break;
		case EM_SPARC	: printf("SPARC\n"); break;
		case EM_386	: printf("386\n"); break;
		case EM_68k	: printf("68k\n"); break;
		case EM_860	: printf("860\n"); break;
		case EM_MIPS	: printf("MIPS\n"); break;
		case EM_ARM	: printf("ARM\n"); break;
		default		: printf("\n");break;
	};

	printf("entry point address : 0x%X\n", ehdr->e_entry);
	printf("program header offset : %d\n", ehdr->e_phoff);

}

void graphicUnit(char *name, unsigned int size, unsigned int offset)
{
	printf("+---------------+ 0x%x\n", offset);
	printf(" %s(%d)\n", name, size);
}

void graphicShow(Elf32_Ehdr *ehdr,Elf32_Shdr *shdr,unsigned char shdr_no,char *sec_str)
{
	int i,j;
	char name[16];
	unsigned int addr;
	Elf32_Shdr *sptr;

	/* elf header */
	graphicUnit("elf header", ehdr->e_ehsize, 0);
	/* program header */
	for (i = 0; i < ehdr->e_phnum; i++) {
		sprintf(name,"pgm hdr %d", i);
		graphicUnit(name, ehdr->e_phentsize, ehdr->e_phoff + i * ehdr->e_phentsize);
	}
	/* section info */
	sptr = shdr;
	for (j = 0; j < shdr_no; j++) {
		if (sptr->sh_offset >= ehdr->e_shoff)
			break;
		if (sptr->sh_type != 0 ) 
			graphicUnit(&sec_str[sptr->sh_name], sptr->sh_size, sptr->sh_offset);
		sptr++;
	}

	/* section header */
	for (i = 0; i < ehdr->e_shnum; i++) {
		sprintf(name,"sec hdr %d", i);
		addr = ehdr->e_shoff + i * ehdr->e_shentsize;
		graphicUnit(name, ehdr->e_shentsize, addr);
	}

	/* other section */
	for (; j < shdr_no; j++) {
		if (sptr->sh_type != 0 ) { 
			graphicUnit(&sec_str[sptr->sh_name], sptr->sh_size, sptr->sh_offset);
			addr = sptr->sh_offset + sptr->sh_size;
		}
		sptr++;
	}
	/* end */

	printf("+---------------+ 0x%x\n", addr);
}

void showElf32Hdr(Elf32_Ehdr *ehdr)
{
	printf("elf type : ");
	switch (ehdr->e_type) {
		case ET_NONE	: printf("NONE\n");break;
		case ET_REL	: printf("REL\n"); break;
		case ET_EXEC	: printf("EXEC\n"); break;
		case ET_DYN	: printf("DYN\n"); break;
		case ET_CORE	: printf("CORE\n"); break;
		case ET_LOPROC	: printf("LOPROC\n"); break;
		case ET_HIPROC	: printf("HIPROC\n"); break;
		default		: printf("\n");break;
	};

	printf("elf machine [%02x]: ",ehdr->e_machine);
	switch (ehdr->e_machine) {
		case EM_NONE	: printf("NONE\n");break;
		case EM_M32	: printf("M32\n"); break;
		case EM_SPARC	: printf("SPARC\n"); break;
		case EM_386	: printf("386\n"); break;
		case EM_68k	: printf("68k\n"); break;
		case EM_860	: printf("860\n"); break;
		case EM_MIPS	: printf("MIPS\n"); break;
		case EM_ARM	: printf("ARM\n"); break;
		default		: printf("\n");break;
	};

	printf("entry point address : 0x%X\n", ehdr->e_entry);

	printf("\n===== elf header =====\n");
	printf("size    : %d\n", ehdr->e_ehsize);

	printf("\n===== program header =====\n");
	printf("offset  : %d\n", ehdr->e_phoff);
	printf("size    : %d\n", ehdr->e_phentsize);
	printf("no      : %d\n", ehdr->e_phnum);

	printf("\n===== section header =====\n");
	printf("offset  : %d\n", ehdr->e_shoff);
	printf("size    : %d\n", ehdr->e_shentsize);
	printf("no      : %d\n", ehdr->e_shnum);
	printf("str inx : %d\n", ehdr->e_shstrndx);


}

char analyzIdent(char *ident)
{
	/* check elf ident*/
	printf("ident : %c%c%c\n", ident[1], ident[2], ident[3]);
	if ( ident[0] != 0x7f && ident[1] != 'E' && 
		ident[2] != 'L' && ident[3] != 'F') {
		printf("this format is not elf file\n");
		return;
	}
		
	printf("elf class : ");
	switch (ident[4]) {
		case ELFCLASSNONE	: printf("NONE\n");break;
		case ELFCLASS32		: printf(" 32\n"); break;
		case ELFCLASS64		: printf(" 64\n"); break;
		default			: printf("\n");break;
	};

	printf("elf data : ");
	switch (ident[5]) {
		case ELFDATANONE	: printf("NONE\n");break;
		case ELFDATA2LSB	: printf("LSB\n"); break;
		case ELFDATA2MSB	: printf("MSB\n"); break;
		default			: printf("\n");break;
	};
	

	printf("elf version : ");
	switch (ident[6]) {
		case EV_NONE	: printf("NONE\n");break;
		case EV_CURRENT	: printf("CURRENT\n");break;
		case EV_NUM	: printf("NUM\n");break;
		default		: printf("\n");break;
	};

	return ident[4];
}

void showElf32Shdr(Elf32_Shdr *shdr, unsigned char num, char *str)
{
	int no;
	Elf32_Shdr *sptr;
	
	sptr = shdr;
	printf("index\tname\t\t\ttype\toffset\tsize\n");
	for (no = 0; no < num; no++) {
		printf("%d\t", no);
		printf("%s",&str[sptr->sh_name]);
		if(strlen(&str[sptr->sh_name]) >= 16) 
			printf("\t");
		if(strlen(&str[sptr->sh_name]) >= 8) 
			printf("\t\t");
		else
			printf("\t\t\t");
		//printf("name %d\n",sptr->sh_name);
		printf("%d\t",sptr->sh_type);
		printf("0x%x\t",sptr->sh_offset);
		printf("%d\n",sptr->sh_size);
		sptr++;
	}
}

void allow_execution(const void *addr)
{
	long pagesize;
	char *p;

	pagesize = (int)sysconf(_SC_PAGESIZE);
	p = (char *)((long)addr & ~(pagesize - 1));
	mprotect(p, pagesize , PROT_READ | PROT_WRITE | PROT_EXEC);
}

void showFuncList(struct funcStr *list)
{
	struct funcStr *ptr;
	ptr = list;
	if (list == NULL)
		return;

	printf("----- function list -----\n");
	printf("name\t\toffset\n");
	do {
		printf("%s",ptr->name);
		if(strlen(ptr->name) >= 8)
			printf("\t");
		else
			printf("\t\t");
		printf("0x%x",ptr->offset);
		printf("\n");
		ptr = ptr->next;
	} while (ptr != NULL);
}

void genFuncList(Elf32_Sym *symp, char *sym_ptr, struct funcStr **list, unsigned int entry, unsigned int no)
{
	unsigned int i,first;
	Elf32_Sym *ptr;
	struct funcStr *fs,*now;

	first = 1;
	ptr = symp;
	for (i = 0; i < no; i++, ptr++) {
		if(ptr->st_info == 0x12) {
			fs = malloc(sizeof(struct funcStr));
			fs->name = &sym_ptr[ptr->st_name];
			fs->offset = ptr->st_value - entry;
			fs->next = NULL;

			if(first) {
				*list = fs;
				now = fs;
				first = 0;
			} else {
				now->next = fs;
				now = now->next;
			}
		} else
			continue;
	}
}

void showSymbolTable(Elf32_Sym *symp, char *sym_ptr, unsigned int symbol_no)
{
	Elf32_Sym *ptr;
	unsigned int i;
	printf("-----symbol table-----\n");
	printf("name\t\tvalue\t\tsize\tinfo\tother\tindex\n");

	ptr = symp;
	for (i = 0; i < symbol_no; i++, ptr++) {
		printf("%s", &sym_ptr[ptr->st_name]);
		if(strlen(&sym_ptr[ptr->st_name]) >= 8)
			printf("\t");
		else
			printf("\t\t");
		printf("0x%x", ptr->st_value);
		if(ptr->st_value > 100000)
			printf("\t");
		else
			printf("\t\t");

		printf("%d\t0x%02x\t%d\t%d\n",
			ptr->st_size, ptr->st_info, ptr->st_other, ptr->st_shndx);
	}


}

void main(int argc, char *argv[])
{
	char targetFile[32] = "helloWorld";
	char elf_ident[16] = {0};
	char elf_class,*sec_str,*text_ptr,*textfunct,*sym_ptr;
	void *ehdr,*shdr,*ptr;
	FILE *target;
	Elf32_Shdr *sptr;
	Elf32_Sym *symp;
	size_t rtn,shdr_off,shdr_no,shdr_size,str_idx;
	int i,symbol_no;
	struct funcStr *list = NULL, *fsp;

	if (argc >= 2) 
		strcpy(targetFile, argv[1]);
	
	/* check file is exists */
	if( access(targetFile, F_OK) == -1) {
		printf("file %s doesn't exist!!\n",targetFile);
		goto end;
	}

	/* open and read elf header */
	target = fopen(targetFile, "r");
	rtn = fread(elf_ident, 1, sizeof(elf_ident), target);	
	elf_class = analyzIdent(elf_ident);
	fseek(target, 0, SEEK_SET);
	if (elf_class == ELFCLASS32) {
		ehdr = malloc(sizeof(Elf32_Ehdr));
		rtn = fread(ehdr, 1, 52, target);
		//showElf32Hdr(ehdr);
		shdr_off = ((Elf32_Ehdr *)ehdr)->e_shoff;
		shdr_no  = ((Elf32_Ehdr *)ehdr)->e_shnum;
		shdr_size= ((Elf32_Ehdr *)ehdr)->e_shentsize;
		str_idx  = ((Elf32_Ehdr *)ehdr)->e_shstrndx;
	} else if (elf_class == ELFCLASS64) {
		ehdr = malloc(sizeof(Elf64_Ehdr));
		rtn = fread(ehdr, 1, 64, target);
		//showElf64Hdr(ehdr);
		shdr_off = ((Elf64_Ehdr *)ehdr)->e_shoff;
		shdr_no  = ((Elf64_Ehdr *)ehdr)->e_shnum;
		shdr_size= ((Elf64_Ehdr *)ehdr)->e_shentsize;
		str_idx  = ((Elf64_Ehdr *)ehdr)->e_shstrndx;
	} else {
		printf("not support this class\n");
		goto close;
	}

	/* read section header */
	rtn = fseek(target, shdr_off, SEEK_SET);
	shdr = malloc(shdr_size * shdr_no); 
	rtn = fread(shdr, 1, shdr_size * shdr_no, target);	

	/* read section string name */
	sptr = ((Elf32_Shdr *)shdr) + str_idx;
	sec_str = malloc(sptr->sh_size);
	rtn = fseek(target, sptr->sh_offset, SEEK_SET);
	rtn = fread(sec_str, 1, sptr->sh_size, target);	

	//showElf32Shdr(shdr, shdr_no, sec_str);

	//graphicShow(ehdr,shdr,shdr_no,sec_str);
	/* read out string table */
	sptr = (Elf32_Shdr *)shdr;
	while ( sptr->sh_type != 3 
		|| sec_str[sptr->sh_name + 1] != 's' && sec_str[sptr->sh_name + 2] != 't'
		|| sec_str[sptr->sh_name + 3] != 'r' && sec_str[sptr->sh_name + 4] != 't'
		|| sec_str[sptr->sh_name + 5] != 'a' && sec_str[sptr->sh_name + 6] != 'b') 
		sptr++;

	sym_ptr = (char *)malloc(sptr->sh_size);
	fseek(target, sptr->sh_offset, SEEK_SET);
	fread(sym_ptr, 1, sptr->sh_size, target);

	/* read out symbol table */
	sptr = (Elf32_Shdr *)shdr;
	while (sptr->sh_type != SHT_SYMTAB) 
		sptr++;
	
	symp = (Elf32_Sym *)malloc(sptr->sh_size);
	fseek(target, sptr->sh_offset, SEEK_SET);
	fread(symp, 1, sptr->sh_size, target);
	symbol_no = sptr->sh_size / sizeof(Elf32_Sym);
	//showSymbolTable(symp, sym_ptr, symbol_no);

	/* read out .text section into memory */
	sptr = (Elf32_Shdr *)shdr;
	while (sec_str[sptr->sh_name + 1] != 't' && sec_str[sptr->sh_name + 2] != 'e' &&
		sec_str[sptr->sh_name + 2] != 'x' && sec_str[sptr->sh_name + 3] != 't')
		sptr++;

	textfunct = malloc(sptr->sh_size);
	fseek(target, sptr->sh_offset, SEEK_SET);
	fread(textfunct, 1, sptr->sh_size, target);

	/* can't execute heap memory region */
	/* set this region to be executable */
	allow_execution(textfunct);


	/* generate function array */
	genFuncList(symp, sym_ptr, &list, ((Elf32_Ehdr *)ehdr)->e_entry, symbol_no); 
	showFuncList(list);
	printf("execute %s main function\n",targetFile);
	fsp = list;
	while(strcmp(fsp->name,"main") != 0)
		fsp = fsp->next;

	rtn = ((int (*)(void))textfunct + fsp->offset)();
	//asm("call *%0":"=r"(rtn):"r"(textfunct):);
	printf("finish execute, return value : %d\n",rtn);
close:
	free(ehdr);
	fclose(target);
end:
	return;
}
