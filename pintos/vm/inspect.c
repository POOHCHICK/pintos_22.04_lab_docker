/* inspect.c: VM 테스트 유틸리티 */
/* ! DO NOT MODIFY THIS FILE. */

#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/mmu.h"
#include "vm/inspect.h"

static void inspect(struct intr_frame *f)
{
    const void *va = (const void *) f->R.rax;
    f->R.rax = PTE_ADDR(pml4_get_page(thread_current()->pml4, va));
}

/* VM 컴포넌트 테스트 도구. int 0x42를 통해 이 함수를 호출합니다.
 * 입력:
 *   @RAX - 검사할 가상 주소
 * 출력:
 *   @RAX - 입력과 매핑된 물리 주소 */
void register_inspect_intr(void)
{
    intr_register_int(0x42, 3, INTR_OFF, inspect, "Inspect Virtual Memory");
}