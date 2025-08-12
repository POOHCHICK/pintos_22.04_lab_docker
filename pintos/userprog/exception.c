#include "userprog/exception.h"

#include <inttypes.h>
#include <stdio.h>

#include "intrinsic.h"
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "userprog/gdt.h"
#include "userprog/syscall.h"

/* Number of page faults processed. */
static long long page_fault_cnt;

static void kill(struct intr_frame *);
static void page_fault(struct intr_frame *);

/* Registers handlers for interrupts that can be caused by user
   programs.

   In a real Unix-like OS, most of these interrupts would be
   passed along to the user process in the form of signals, as
   described in [SV-386] 3-24 and 3-25, but we don't implement
   signals.  Instead, we'll make them simply kill the user
   process.

   Page faults are an exception.  Here they are treated the same
   way as other exceptions, but this will need to change to
   implement virtual memory.

   Refer to [IA32-v3a] section 5.15 "Exception and Interrupt
   Reference" for a description of each of these exceptions. */
void exception_init(void)
{
    /* These exceptions can be raised explicitly by a user program,
       e.g. via the INT, INT3, INTO, and BOUND instructions.  Thus,
       we set DPL==3, meaning that user programs are allowed to
       invoke them via these instructions. */
    intr_register_int(3, 3, INTR_ON, kill, "#BP Breakpoint Exception");
    intr_register_int(4, 3, INTR_ON, kill, "#OF Overflow Exception");
    intr_register_int(5, 3, INTR_ON, kill,
                      "#BR BOUND Range Exceeded Exception");

    /* These exceptions have DPL==0, preventing user processes from
       invoking them via the INT instruction.  They can still be
       caused indirectly, e.g. #DE can be caused by dividing by
       0.  */
    intr_register_int(0, 0, INTR_ON, kill, "#DE Divide Error");
    intr_register_int(1, 0, INTR_ON, kill, "#DB Debug Exception");
    intr_register_int(6, 0, INTR_ON, kill, "#UD Invalid Opcode Exception");
    intr_register_int(7, 0, INTR_ON, kill,
                      "#NM Device Not Available Exception");
    intr_register_int(11, 0, INTR_ON, kill, "#NP Segment Not Present");
    intr_register_int(12, 0, INTR_ON, kill, "#SS Stack Fault Exception");
    intr_register_int(13, 0, INTR_ON, kill, "#GP General Protection Exception");
    intr_register_int(16, 0, INTR_ON, kill, "#MF x87 FPU Floating-Point Error");
    intr_register_int(19, 0, INTR_ON, kill,
                      "#XF SIMD Floating-Point Exception");

    /* Most exceptions can be handled with interrupts turned on.
       We need to disable interrupts for page faults because the
       fault address is stored in CR2 and needs to be preserved. */
    intr_register_int(14, 0, INTR_OFF, page_fault, "#PF Page-Fault Exception");
}

/* Prints exception statistics. */
void exception_print_stats(void)
{
    printf("Exception: %lld page faults\n", page_fault_cnt);
}

/* Handler for an exception (probably) caused by a user process. */
static void kill(struct intr_frame *f)
{
    /* This interrupt is one (probably) caused by a user process.
       For example, the process might have tried to access unmapped
       virtual memory (a page fault).  For now, we simply kill the
       user process.  Later, we'll want to handle page faults in
       the kernel.  Real Unix-like operating systems pass most
       exceptions back to the process via signals, but we don't
       implement them. */

    /* The interrupt frame's code segment value tells us where the
       exception originated. */
    switch (f->cs)
    {
        case SEL_UCSEG:
            /* User's code segment, so it's a user exception, as we
               expected.  Kill the user process.  */
            printf("%s: dying due to interrupt %#04llx (%s).\n", thread_name(),
                   f->vec_no, intr_name(f->vec_no));
            intr_dump_frame(f);
            thread_exit();

        case SEL_KCSEG:
            /* Kernel's code segment, which indicates a kernel bug.
               Kernel code shouldn't throw exceptions.  (Page faults
               may cause kernel exceptions--but they shouldn't arrive
               here.)  Panic the kernel to make the point.  */
            intr_dump_frame(f);
            PANIC("Kernel bug - unexpected interrupt in kernel");

        default:
            /* Some other code segment?  Shouldn't happen.  Panic the
               kernel. */
            printf("Interrupt %#04llx (%s) in unknown segment %04x\n",
                   f->vec_no, intr_name(f->vec_no), f->cs);
            thread_exit();
    }
}

/* 페이지 폴트 처리기. 가상 메모리를 구현하기 위해 채워 넣어야 하는 뼈대
   코드이다. 프로젝트 2의 일부 해법에서는 이 코드를 수정해야 할 수도 있다.

   진입 시 폴트가 발생한 주소는 CR2(Control Register 2)에 들어 있으며,
   예외 원인 정보는 exception.h의 PF_* 매크로에 설명된 형식으로
   f의 error_code 멤버에 들어 있다. 아래 예제 코드는 그 정보를
   어떻게 해석하는지 보여 준다. 이에 대한 더 자세한 내용은
   [IA32-v3a] 5.15절 "Exception and Interrupt Reference"의
   "Interrupt 14--Page Fault Exception (#PF)" 항목을 참고하라. */
static void page_fault(struct intr_frame *f)
{
    bool not_present; /* true: 페이지가 존재하지 않음, false: 읽기 전용 페이지에
                         쓰기 */
    bool write; /* true: 쓰기 접근, false: 읽기 접근 */
    bool user;  /* true: 사용자 모드 접근, false: 커널 모드 접근 */
    void *fault_addr; /* 폴트가 발생한 주소 */

    /* 폴트를 유발한 가상 주소(접근된 주소)를 얻는다.
       이 주소는 코드나 데이터를 가리킬 수 있다.
       이것이 폴트를 일으킨 명령어의 주소와 반드시 같지는 않다
       (명령어의 주소는 f->rip에 있다). */

    fault_addr = (void *) rcr2();

    /* 인터럽트를 다시 켠다( CR2가 바뀌기 전에 확실히 읽기 위해
       잠시만 꺼 두었었다 ). */
    intr_enable();

    /* page fault의 원인을 판별한다. */
    /* not_present:
     * 페이지가 메모리에 존재하지 않아서 발생한 폴트 (not-present page)인가
     * 페이지는 존재하지만 권한 위반으로 발생한 폴트 (writing to read-only
     * page)인가? */
    /* write: 어떤 접근으로 인해 발생한 page fault인가? */
    /* user: user mode에서 발생한 page fault인가?
     * 아니면 커널 모드에서 발생한 page fault인가? */
    not_present = (f->error_code & PF_P) == 0;
    write = (f->error_code & PF_W) != 0;
    user = (f->error_code & PF_U) != 0;

#ifdef VM
    /* 프로젝트 3 이후를 위한 코드. */
    if (vm_try_handle_fault(f, fault_addr, user, write, not_present)) return;
#endif

    /* 페이지 폴트를 카운트한다. */
    page_fault_cnt++;

    /* 폴트가 진짜 폴트라면 정보를 보여 주고 종료한다. */
    //  printf("Page fault at %p: %s error %s page in %s context.\n",
    //  fault_addr,
    //         not_present ? "not present" : "rights violation",
    //         write ? "writing" : "reading", user ? "user" : "kernel");

    sys_exit(-1);
}