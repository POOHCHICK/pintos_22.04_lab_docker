#include "userprog/syscall.h"

#include <stdio.h>
#include <syscall-nr.h>

#include "include/filesys/file.h"
#include "include/filesys/filesys.h"
#include "include/lib/string.h"
#include "include/threads/palloc.h"
#include "intrinsic.h"
#include "lib/kernel/console.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/loader.h"
#include "threads/malloc.h"
#include "threads/thread.h"
#include "userprog/gdt.h"
#include "userprog/process.h"

void syscall_entry(void);
void syscall_handler(struct intr_frame *);

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

struct lock filesys_lock;

void syscall_init(void)
{
    write_msr(MSR_STAR, ((uint64_t) SEL_UCSEG - 0x10) << 48 |
                            ((uint64_t) SEL_KCSEG) << 32);
    write_msr(MSR_LSTAR, (uint64_t) syscall_entry);

    /* The interrupt service rountine should not serve any interrupts
     * until the syscall_entry swaps the userland stack to the kernel
     * mode stack. Therefore, we masked the FLAG_FL. */
    write_msr(MSR_SYSCALL_MASK,
              FLAG_IF | FLAG_TF | FLAG_DF | FLAG_IOPL | FLAG_AC | FLAG_NT);

    lock_init(&filesys_lock);
}

void check_writable(void *vaddr)
{
    struct thread *curr = thread_current();
    struct page *p = NULL;

    p = spt_find_page(&curr->spt, vaddr);
    if (p == NULL)
    {
        return;
    }

    if (!p->writable)
    {
        sys_exit(-1);
    }
}

void check_valid(void *vaddr)
{
    struct thread *curr = thread_current();

    if (!is_user_vaddr(vaddr) || vaddr == NULL)
    {
        sys_exit(-1);
    }
}

void check_fd(int fd)
{
    struct thread *curr = thread_current();

    if (fd < 0 || fd == NULL || (int) fd >= MAX_FD_NUM)
    {
        sys_exit(-1);
    }
}

int allocate_file(struct file *open_file)
{
    struct thread *curr = thread_current();

    for (int i = 0; i < MAX_FD_NUM; i++)
    {
        if (curr->fdt[i] == NULL)
        {
            curr->fdt[i] = malloc(sizeof(struct uni_file));
            curr->fdt[i]->fd_type = FD_FILE;
            curr->fdt[i]->data.file = open_file;

            return i;
        }
    }

    return -1;
}

void sys_halt(void)
{
    power_off();
}

void sys_exit(int status)
{
    struct thread *curr = thread_current();
    curr->exit_status = status;

    printf("%s: exit(%d)\n", curr->name, curr->exit_status);

    thread_exit();
}

pid_t sys_fork(const char *thread_name, struct intr_frame *if_)
{
    return process_fork(thread_name, if_);
}

int sys_exec(const char *file)
{
    check_valid(file);

    void *new_page = palloc_get_page(PAL_ASSERT | PAL_ZERO);
    strlcpy(new_page, file, strlen(file) + 1);

    int exec_result = process_exec(new_page);

    if (exec_result == -1)
    {
        sys_exit(exec_result);
    }
}

int sys_wait(pid_t pid)
{
    return process_wait(pid);
}

bool sys_create(const char *file, unsigned initial_size)
{
    check_valid(file);

    lock_acquire(&filesys_lock);
    bool file_create_result = filesys_create(file, initial_size);
    lock_release(&filesys_lock);

    if (file_create_result)
    {
        return true;
    }
    else
    {
        return false;
    }
}

bool sys_remove(const char *file)
{
    check_valid(file);

    bool file_remove_result = filesys_remove(file);

    return file_remove_result;
}

int sys_open(const char *file)
{
    check_valid(file);

    lock_acquire(&filesys_lock);
    struct file *open_file = filesys_open(file);
    lock_release(&filesys_lock);

    if (open_file == NULL)
    {
        return -1;
    }

    int fd_num = allocate_file(open_file);

    /* ! 실패 원인!!!!!!!!! */
    if (fd_num == -1)
    {
        file_close(open_file);
    }

    return fd_num;
}

int sys_filesize(int fd)
{
    check_fd(fd);

    struct thread *curr = thread_current();
    struct file *file = curr->fdt[fd]->data.file;
    return file_length(file);
}

int sys_read(int fd, void *buffer, unsigned length)
{
    check_writable(buffer);
    check_valid(buffer);
    check_fd(fd);

    if (fd == 1)
    {
        return -1;
    }

    struct thread *curr = thread_current();
    struct file *reading_file = curr->fdt[fd]->data.file;

    if (reading_file == NULL)
    {
        return -1;
    }

    lock_acquire(&filesys_lock);
    off_t bytes_read = file_read(reading_file, buffer, length);
    lock_release(&filesys_lock);

    return bytes_read;
}

int sys_write(int fd, const void *buffer, unsigned length)
{
    check_writable(buffer);
    check_valid(buffer);
    check_fd(fd);

    if (fd == 0)
    {
        return -1;
    }

    if (fd == 1)
    {
        putbuf(buffer, length);
        return length;
    }

    struct thread *curr = thread_current();
    struct file *file = curr->fdt[fd]->data.file;

    if (file == NULL)
    {
        return -1;
    }

    lock_acquire(&filesys_lock);
    off_t bytes_written = file_write(file, buffer, length);
    lock_release(&filesys_lock);

    return bytes_written;
}

void sys_seek(int fd, unsigned position)
{
    check_fd(fd);

    struct thread *curr = thread_current();
    struct file *file = curr->fdt[fd]->data.file;

    file_seek(file, position);
}

unsigned sys_tell(int fd)
{
    check_fd(fd);

    struct thread *curr = thread_current();
    struct file *file = curr->fdt[fd]->data.file;

    off_t file_pos = file_tell(file);

    return file_pos;
}

void sys_close(int fd)
{
    /*
     * 주어진 fd로 file descriptor table에서 file을 찾아온다.
     * 그 파일을 file_close에 넣어준다.
     * file_close이후
     * fd_type을 FD_FREE로 만들고
     * fd_ptr을 NULL로 만들어준다
     * */
    check_fd(fd);

    struct thread *curr = thread_current();

    if (curr->fdt[fd] == NULL)
    {
        return;
    }

    struct file *closing_file = curr->fdt[fd]->data.file;

    file_close(closing_file);

    curr->fdt[fd] = NULL;
}

void *sys_mmap(void *addr, size_t length, int writable, int fd, off_t offset)
{
    struct thread *curr = thread_current();

    struct file *f = curr->fdt[fd]->data.file;
    if (f == NULL)
    {
        return NULL;
    }

    if (file_length(f) == 0)
    {
        return NULL;
    }

    if (addr != pg_round_down(addr))
    {
        return NULL;
    }

    if (offset != pg_ofs(offset))
    {
        return NULL;
    }

    if (is_kernel_vaddr(addr))
    {
        return NULL;
    }

    if ((uintptr_t) addr + (size_t) length < (uintptr_t) addr)
    {
        return NULL;
    }

    if (addr == 0)
    {
        return NULL;
    }

    if (length == 0)
    {
        return NULL;
    }

    if (spt_find_page(&curr->spt, addr) != NULL)
    {
        return NULL;
    }

    if (fd == 0 || fd == 1)
    {
        return NULL;
    }

    return do_mmap(addr, length, writable, f, offset);
}

void sys_munmap(void *addr)
{
}

int sys_dup2(int oldfd, int newfd)
{
}

/* The main system call interface */
void syscall_handler(struct intr_frame *f)
{
    /* user mode에서 kernel 모드로 전환 시 rsp 설정 */
    struct thread *curr = thread_current();
    curr->rsp = f->rsp;

    switch (f->R.rax)
    {
        case SYS_HALT:
            sys_halt();
            break;
        case SYS_EXIT:
            sys_exit(f->R.rdi);
            break;
        case SYS_FORK:
            f->R.rax = sys_fork(f->R.rdi, f);
            break;
        case SYS_EXEC:
            f->R.rax = sys_exec(f->R.rdi);
            break;
        case SYS_WAIT:
            f->R.rax = sys_wait(f->R.rdi);
            break;
        case SYS_CREATE:
            f->R.rax = sys_create(f->R.rdi, f->R.rsi);
            break;
        case SYS_OPEN:
            f->R.rax = sys_open(f->R.rdi);
            break;
        case SYS_FILESIZE:
            f->R.rax = sys_filesize(f->R.rdi);
            break;
        case SYS_READ:
            f->R.rax = sys_read(f->R.rdi, f->R.rsi, f->R.rdx);
            break;
        case SYS_WRITE:
            f->R.rax = sys_write(f->R.rdi, f->R.rsi, f->R.rdx);
            break;
        case SYS_SEEK:
            sys_seek(f->R.rdi, f->R.rsi);
            break;
        case SYS_TELL:
            f->R.rax = sys_tell(f->R.rdi);
            break;
        case SYS_CLOSE:
            sys_close(f->R.rdi);
            break;
        case SYS_MMAP:
            f->R.rax =
                sys_mmap(f->R.rdi, f->R.rsi, f->R.rdx, f->R.r10, f->R.r8);
            break;
        case SYS_MUNMAP:
            sys_munmap(f->R.rdi);
            break;
        case SYS_DUP2:
            break;
        default:
            break;
    }
}
