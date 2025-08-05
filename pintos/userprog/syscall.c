#include "userprog/syscall.h"

#include <stdio.h>
#include <syscall-nr.h>

#include "intrinsic.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/loader.h"
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
}

void sys_halt(void)
{
    power_off();
}

void sys_exit(int status)
{
    struct thread *curr = thread_current();
    curr->exit_status = status;
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
}

bool sys_create(const char *file, unsigned initial_size)
{
}

bool sys_remove(const char *file)
{
}

int sys_open(const char *file)
{
}

int sys_filesize(int fd)
{
}

int sys_read(int fd, void *buffer, unsigned length)
{
}

int sys_write(int fd, const void *buffer, unsigned length)
{
}

void sys_seek(int fd, unsigned position)
{
}

unsigned sys_tell(int fd)
{
}

void sys_close(int fd)
{
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
            break;
        case SYS_OPEN:
            break;
        case SYS_FILESIZE:
            break;
        case SYS_READ:
            break;
        case SYS_WRITE:
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
