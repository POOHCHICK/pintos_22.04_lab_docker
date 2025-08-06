#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include <debug.h>
#include <stdbool.h>
#include <stddef.h>

#include "lib/user/syscall.h"
#include "threads/interrupt.h"

extern struct lock filesys_lock;

void syscall_init(void);

void check_valid(void *vaddr);
void check_fd(int fd);

int allocate_file(struct file *open_file);

void sys_halt(void) NO_RETURN;
void sys_exit(int status) NO_RETURN;
pid_t sys_fork(const char *thread_name, struct intr_frame *if_);
int sys_exec(const char *file);
int sys_wait(pid_t pid);
bool sys_create(const char *file, unsigned initial_size);
bool sys_remove(const char *file);
int sys_open(const char *file);
int sys_filesize(int fd);
int sys_read(int fd, void *buffer, unsigned length);
int sys_write(int fd, const void *buffer, unsigned length);
void sys_seek(int fd, unsigned position);
unsigned sys_tell(int fd);
void sys_close(int fd);

int sys_dup2(int oldfd, int newfd);

#endif /* userprog/syscall.h */
