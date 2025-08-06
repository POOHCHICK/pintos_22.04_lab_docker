#include "userprog/syscall.h"

#include <stdio.h>
#include <syscall-nr.h>

#include "include/filesys/file.h"
#include "include/filesys/filesys.h"
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

void check_valid(void *vaddr)
{
    struct thread *curr = thread_current();

    if (!is_user_vaddr(vaddr) || vaddr == NULL ||
        pml4_get_page(curr->pml4, vaddr) == NULL)
    {
        sys_exit(-1);
    }
}

void check_fd(int fd)
{
    struct thread *curr = thread_current();

    if (fd < 0 || fd == NULL || (int) fd >= curr->next_fd)
    {
        sys_exit(-1);
    }
}

int allocate_file(struct file *open_file)
{
    struct thread *curr = thread_current();
    int idx = 0;

    while (idx != curr->next_fd)
    {
        if (curr->fdt[idx] == NULL)
        {
            curr->fdt[idx] = malloc(sizeof(struct uni_file *));
            curr->fdt[idx]->fd_type = FD_FILE;
            curr->fdt[idx]->fd_ptr = open_file;

            return idx;
        }
        idx++;
    }

    realloc(curr->fdt, ((curr->next_fd + 1) * sizeof(struct uni_file *)));
    curr->fdt[curr->next_fd] = malloc(sizeof(struct uni_file *));
    curr->fdt[curr->next_fd]->fd_type = FD_FILE;
    curr->fdt[curr->next_fd]->fd_ptr = open_file;

    return curr->next_fd++;
}

void sys_halt(void)
{
    power_off();
}

void sys_exit(int status)
{
    struct thread *curr = thread_current();
    curr->exit_status = status;

    if (lock_held_by_current_thread(&filesys_lock))
    {
        lock_release(&filesys_lock);
    }

    thread_exit();
}

pid_t sys_fork(const char *thread_name, struct intr_frame *if_)
{
    //     pid_t child_pid = process_fork(thread_name, if_);
    // if (child_pid == -1)
    // {
    //     sys_exit(child_pid);
    // }
    // return child_pid;
    return process_fork(thread_name, if_);
}

int sys_exec(const char *file)
{
}

int sys_wait(pid_t pid)
{
    return process_wait(pid);
}

bool sys_create(const char *file, unsigned initial_size)
{
    check_valid(file);

    if (filesys_create(file, initial_size))
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

    int valid_fd = allocate_file(open_file);

    return valid_fd;
}

int sys_filesize(int fd)
{
    check_fd(fd);

    struct thread *curr = thread_current();
    struct file *file = curr->fdt[fd]->fd_ptr;
    return file_length(file);
}

int sys_read(int fd, void *buffer, unsigned length)
{
    check_valid(buffer);
    check_fd(fd);

    if (fd == 1)
    {
        return -1;
    }

    struct thread *curr = thread_current();
    struct file *reading_file = curr->fdt[fd]->fd_ptr;

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
    struct file *file = curr->fdt[fd]->fd_ptr;

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
}

unsigned sys_tell(int fd)
{
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
    struct file *closing_file = curr->fdt[fd]->fd_ptr;

    file_close(closing_file);

    free(curr->fdt[fd]);
    curr->fdt[fd] = NULL;
}

int sys_dup2(int oldfd, int newfd)
{
}

/* The main system call interface */
void syscall_handler(struct intr_frame *f)
{
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
            break;
        case SYS_TELL:
            break;
        case SYS_CLOSE:
            break;
        case SYS_DUP2:
            break;
        default:
            break;
    }
}
