#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/loader.h"
#include "userprog/gdt.h"
#include "threads/flags.h"
#include "intrinsic.h"

/** #Project 2: System Call */
typedef int pid_t;
#include <string.h>

#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/mmu.h"
#include "threads/palloc.h"
#include "userprog/process.h"

/* Project 3: Virtual Memory */
#include "include/vm/file.h"

struct lock filesys_lock;
/** -----------------------  */

void syscall_entry (void);
void syscall_handler (struct intr_frame *);
tid_t fork_syscall(const char *thread_name, struct intr_frame *f);

/* System call.
 *
 * Previously system call services was handled by the interrupt handler
 * (e.g. int 0x80 in linux). However, in x86-64, the manufacturer supplies
 * efficient path for requesting the system call, the `syscall` instruction.
 *
 * The syscall instruction works by reading the values from the the Model
 * Specific Register (MSR). For the details, see the manual. */

#define MSR_STAR 0xc0000081         /* Segment selector msr */
#define MSR_LSTAR 0xc0000082        /* Long mode SYSCALL target */
#define MSR_SYSCALL_MASK 0xc0000084 /* Mask for the eflags */

void
syscall_init (void) {
	write_msr(MSR_STAR, ((uint64_t)SEL_UCSEG - 0x10) << 48  |
			((uint64_t)SEL_KCSEG) << 32);
	write_msr(MSR_LSTAR, (uint64_t) syscall_entry);

	/* The interrupt service rountine should not serve any interrupts
	 * until the syscall_entry swaps the userland stack to the kernel
	 * mode stack. Therefore, we masked the FLAG_FL. */
	write_msr(MSR_SYSCALL_MASK,
			FLAG_IF | FLAG_TF | FLAG_DF | FLAG_IOPL | FLAG_AC | FLAG_NT);

	lock_init(&filesys_lock);
}

/* The main system call interface */
void
syscall_handler (struct intr_frame *f UNUSED) {
	// TODO: Your implementation goes here.
	// printf ("system call!\n");
#ifdef VM
	thread_current()->rsp_point = f->rsp;
#endif
switch (f->R.rax)
	{
	case SYS_HALT:
		halt_syscall();
		break;
	case SYS_EXIT:
		exit_syscall(f->R.rdi);
		break;
	case SYS_FORK:
		f->R.rax =fork_syscall(f->R.rdi,f);
		break;
	case SYS_EXEC:
		if (exec_syscall(f->R.rdi) == -1)
        {
            exit_syscall(-1);
        }
		break;
	case SYS_WAIT:
		f->R.rax =wait_syscall(f->R.rdi);
		break;
	case SYS_CREATE:
		f->R.rax = create_syscall(f->R.rdi,f->R.rsi);
		break;
	case SYS_REMOVE:
		f->R.rax = remove_syscall(f->R.rdi);
		break;
	case SYS_OPEN:
		f->R.rax = open_syscall(f->R.rdi);
		break;
	case SYS_FILESIZE:
		f->R.rax = filesize_syscall(f->R.rdi);
		break;
	case SYS_READ:
		f->R.rax = read_syscall(f->R.rdi, f->R.rsi, f->R.rdx);
		break;
	case SYS_WRITE:
		f->R.rax = write_syscall(f->R.rdi, f->R.rsi, f->R.rdx);
		break;
	case SYS_SEEK:
		seek_syscall(f->R.rdi, f->R.rsi);
		break;
	case SYS_TELL:
		f->R.rax = tell_syscall(f->R.rdi);
		break;
	case SYS_CLOSE:
		close_syscall(f->R.rdi);
		break;
#ifdef VM
	case SYS_MMAP:
		f->R.rax = mmap_syscall(f->R.rdi,f->R.rsi,f->R.rdx,f->R.r10,f->R.r8);
		break;
	case SYS_MUNMAP:
		munmap_syscall(f->R.rdi);
		break;
#endif
	default:
		exit_syscall(-1);
		break;
	}
}

// ================================= utils =================================

#ifndef VM
/** #Project 2: System Call */
static void check_address(void *addr) {
    THREAD *curr = thread_current();

    if (is_kernel_vaddr(addr) || addr == NULL || pml4_get_page(curr->pml4, addr) == NULL)
        exit_syscall(-1);
}
#else
/** #Project 3: Anonymous Page */
static struct page *check_address(void *addr) {
    THREAD *curr = thread_current();

    if (is_kernel_vaddr(addr) || addr == NULL)
        exit_syscall(-1);

    return spt_find_page(&curr->spt, addr);
}

/** Project 3: Memory Mapped Files - 버퍼 유효성 검사 */
void check_valid_buffer(void *buffer, size_t size, bool writable) {
    for (size_t i = 0; i < size; i++) {
        /* buffer가 spt에 존재하는지 검사 */
        struct page *page = check_address(buffer + i);

        if (!page || (writable && !(page->writable)))
            exit_syscall(-1);
    }
}
#endif


// ================================= system call functions =================================
void halt_syscall(){
	power_off();
}

void exit_syscall(int status){
	struct thread *cur = thread_current();
	
	cur->exit_status = status;

	printf("%s: exit(%d)\n", cur->name, cur->exit_status);

	thread_exit();
}


pid_t fork_syscall(const char *thread_name,struct intr_frame *f){
	return process_fork(thread_name,f);
}

int exec_syscall(const char *cmd_line){
	check_address(cmd_line);

	char *cmd_line_copy;
	cmd_line_copy = palloc_get_page(PAL_ZERO);
	if (cmd_line_copy == NULL)
		exit_syscall(-1);							  
	strlcpy(cmd_line_copy, cmd_line, PGSIZE); 

	if (process_exec(cmd_line_copy) == -1)
		exit_syscall(-1);
}

int wait_syscall(pid_t tid){
	return process_wait(tid);
}

bool create_syscall(const char *file, unsigned initial_size){
	lock_acquire(&filesys_lock);
	check_address(file);
	bool success = filesys_create(file,initial_size);
	lock_release(&filesys_lock);

	return success;
}

bool remove_syscall(const char *file){
	check_address(file);

	bool success = filesys_remove(file);

	return success;
}

int open_syscall(const char *file_name){
	check_address(file_name);
	lock_acquire(&filesys_lock);
	struct file *file = filesys_open(file_name);
	if (file == NULL)
	{
		lock_release(&filesys_lock);
		return -1;
	}
	int fd = process_add_file(file);
	if (fd == -1)
		file_close(file);
	lock_release(&filesys_lock);
	return fd;
}

int filesize_syscall(int fd){
	struct file *file = get_file_from_fd(fd);

	if(file == NULL)
		return -1;

	return file_length(file);
}

int read_syscall(int fd, void *buffer, unsigned length){
	check_address(buffer);

	char *ptr = (char *)buffer;
	int bytes_read = 0;

	lock_acquire(&filesys_lock);
	if (fd == STDIN_FILENO)
	{
		for (int i = 0; i < length; i++)
		{
			*ptr++ = input_getc();
			bytes_read++;
		}
		lock_release(&filesys_lock);
	}
	else
	{
		if (fd < 2)
		{

			lock_release(&filesys_lock);
			return -1;
		}
	struct file *file = get_file_from_fd(fd);
		if (file == NULL)
		{

			lock_release(&filesys_lock);
		return -1;
		}
		struct page *page = spt_find_page(&thread_current()->spt, buffer);
		if (page && !page->writable)
		{
			lock_release(&filesys_lock);
			exit_syscall(-1);
		}
		bytes_read = file_read(file, buffer, length);
    lock_release(&filesys_lock);
	}
	return bytes_read;
}

int write_syscall(int fd, const void *buffer, unsigned length){
	check_address(buffer);

	int bytes_write = 0;
	if (fd == STDOUT_FILENO)
	{
		putbuf(buffer, length);
		bytes_write = length;
	}
	else
	{
		if (fd < 2)
			return -1;
		struct file *file = get_file_from_fd(fd);
		if (file == NULL)
			return -1;
		lock_acquire(&filesys_lock);
		bytes_write = file_write(file, buffer, length);
	lock_release(&filesys_lock);
	}
	return bytes_write;
}

void seek_syscall(int fd, unsigned position){
	struct file *file = get_file_from_fd(fd);

	if(file == NULL)
		return;

	file_seek(file,position);
}

int tell_syscall(int fd){
	struct file *file = get_file_from_fd(fd);

	if(file == NULL || (file >=STDIN && file<=STDERR))
		return -1;
	
	return file_tell(file);
}

void close_syscall(int fd){
	struct file *file = get_file_from_fd(fd);
	if (file == NULL)
		return;
	file_close(file);
	remove_file_in_fd_table(fd);
}

void *mmap_syscall(void *addr, size_t length, int writable, int fd, off_t offset){
	if (!addr || addr != pg_round_down(addr))
		return NULL;

	if (offset != pg_round_down(offset))
		return NULL;

	if (!is_user_vaddr(addr) || !is_user_vaddr(addr + length))
		return NULL;

	if (spt_find_page(&thread_current()->spt, addr))
		return NULL;

	struct file *f = get_file_from_fd(fd);
	if (f == NULL)
		return NULL;

	if (file_length(f) == 0 || (int)length <= 0)
		return NULL;

	return do_mmap(addr, length, writable, f, offset); 
}

void munmap_syscall(void *addr){
	do_munmap(addr);

	return;
}
