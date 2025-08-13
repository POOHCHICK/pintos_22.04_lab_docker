/* vm.c: Generic interface for virtual memory objects. */

#include "threads/malloc.h"
#include "threads/mmu.h"
#include "vm/vm.h"
#include "vm/inspect.h"

/* 각 서브시스템의 초기화 코드를 호출하여
 * 가상 메모리 서브시스템을 초기화합니다. */
void vm_init(void)
{
    vm_anon_init();
    vm_file_init();
#ifdef EFILESYS /* For project 4 */
    pagecache_init();
#endif
    register_inspect_intr();
    /* ! DO NOT MODIFY UPPER LINES. */
    /* TODO: Your code goes here. */
}

/* 페이지의 타입을 가져옵니다.
 * 이 함수는 페이지가 초기화된 이후 해당 페이지의 타입을 알고 싶을 때
 * 유용합니다. 현재 이 함수는 완전히 구현되어 있습니다. */
/* Get the type of the page. This function is useful if you want to know the
 * type of the page after it will be initialized.
 * This function is fully implemented now. */
enum vm_type page_get_type(struct page *page)
{
    int ty = VM_TYPE(page->operations->type);
    switch (ty)
    {
        case VM_UNINIT:
            return VM_TYPE(page->uninit.type);
        default:
            return ty;
    }
}

/* Helpers */
static struct frame *vm_get_victim(void);
static bool vm_do_claim_page(struct page *page);
static struct frame *vm_evict_frame(void);

/* 초기화 함수를 사용하여 대기(pending) 페이지 객체를 생성합니다.
 * 페이지를 만들고자 할 때, 직접 생성하지 말고
 * 반드시 이 함수나 `vm_alloc_page`를 통해 생성하십시오. */
bool vm_alloc_page_with_initializer(enum vm_type type, void *upage,
                                    bool writable, vm_initializer *init,
                                    void *aux)
{
    ASSERT(VM_TYPE(type) != VM_UNINIT)

    struct supplemental_page_table *spt = &thread_current()->spt;

    /* upage가 이미 사용 중인지 확인합니다. */
    if (spt_find_page(spt, upage) == NULL)
    {
        /* 페이지를 생성하고, */
        struct page *new_page = malloc(sizeof(struct page));
        if (new_page == NULL)
        {
            goto err;
        }

        /* VM 타입에 따라 초기화 함수를 가져옵니다 */
        bool (*page_initializer)(struct page *, enum vm_type, void *);

        switch (VM_TYPE(type))
        {
            case VM_ANON:
                page_initializer = anon_initializer;
                break;
            case VM_FILE:
                page_initializer = file_backed_initializer;
                break;
            default:
                goto err;
        }

        /* uninit_new를 호출하여 "uninit" 페이지 구조체를 생성합니다. */
        uninit_new(new_page, upage, init, type, aux, page_initializer);

        /* uninit_new를 호출한 이후에 해당 필드를 수정합니다. */
        new_page->writable = writable;

        /* 생성한 페이지를 spt에 삽입합니다. */
        if (!spt_insert_page(spt, new_page))
        {
            free(new_page);
            goto err;
        }

        return true;
    }
err:
    return false;
}

/* spt에서 VA를 찾아 페이지를 반환합니다. 오류가 발생하면 NULL을 반환합니다. */
struct page *spt_find_page(struct supplemental_page_table *spt, void *va)
{
    struct page page;
    struct hash_elem *e;

    page.va = pg_round_down(va);
    e = hash_find(&spt->hash_table, &page.hash_elem);

    if (e == NULL)
    {
        return NULL;
    }
    return hash_entry(e, struct page, hash_elem);
}

/* 검증 후 PAGE를 spt에 삽입합니다. */
bool spt_insert_page(struct supplemental_page_table *spt, struct page *page)
{
    bool succ = false;
    if (hash_insert(&spt->hash_table, &page->hash_elem) == NULL)
    {
        succ = true;
    }
    return succ;
}

void spt_remove_page(struct supplemental_page_table *spt, struct page *page)
{
    vm_dealloc_page(page);
    return true;
}

/* 제거될(struct frame) 프레임을 가져옵니다. */
static struct frame *vm_get_victim(void)
{
    struct frame *victim = NULL;
    /* TODO: The policy for eviction is up to you. */

    return victim;
}

/* 페이지 하나를 제거하고 해당 프레임을 반환합니다.
 * 오류가 발생하면 NULL을 반환합니다. */
static struct frame *vm_evict_frame(void)
{
    struct frame *victim UNUSED = vm_get_victim();
    /* TODO: 희생 프레임을 스왑 아웃하고, 제거된 프레임을 반환합니다. */

    return NULL;
}

/* palloc()을 호출하여 프레임을 가져옵니다.
 * 사용 가능한 페이지가 없으면 페이지를 제거(evict)하여 반환합니다.
 * 이 함수는 항상 유효한 주소를 반환합니다.
 * 즉, 사용자 풀 메모리가 가득 찼을 경우,
 * 이 함수는 프레임을 제거하여 사용 가능한 메모리 공간을 확보합니다. */
static struct frame *vm_get_frame(void)
{
    struct frame *frame = NULL;
    void *kva = palloc_get_page(PAL_USER);
    if (kva == NULL)
    {
        PANIC("jinwoo");
    }

    frame = malloc(sizeof(struct frame));
    frame->kva = kva;
    frame->page = NULL;

    ASSERT(frame != NULL);
    ASSERT(frame->page == NULL);
    return frame;
}

/* 스택을 확장합니다. */
static void vm_stack_growth(void *addr)
{
    vm_alloc_page(VM_ANON | VM_MARKER_0, pg_round_down(addr), true);
}

/* 쓰기 보호된 페이지에서 발생한 폴트를 처리합니다. */
static bool vm_handle_wp(struct page *page UNUSED)
{
}

enum sg_type
{
    GENERAL,
    PUSH
};

/**
 * 스택 포인터가 1MB 스택 제한 범위 내에 있는지 검증합니다.
 *
 * @param rsp 검증할 스택 포인터 위치
 * @param type 스택 접근 타입 (GENERAL 또는 PUSH)
 * @return 스택 포인터가 유효 범위 내에 있으면 true, 그렇지 않으면 false
 */
static bool is_stack_pointer_valid(void *rsp, enum sg_type type)
{
    switch (type)
    {
        case GENERAL:
            /* 현재 스택 포인터가 1MB 제한 내에 있는지 자격 검증
             * (rsp >= 0x47380000 조건으로 스택 오버플로우 방지) */
            return rsp >= USER_STACK_END;
        case PUSH:
            /* PUSH 동작 후 스택 포인터 위치가 1MB 제한 내에 있을지 미리 검증
             * (rsp-8 >= 0x47380000 조건으로 PUSH 실행 가능성 사전 확인) */
            /* x86-64 PUSH 명령어는 8바이트 스택 포인터 이동을 수반하므로
             * 실행 전에 rsp-8 위치가 USER_STACK_END(0x47380000) 이상인지
             * 미리 검증하여 스택 오버플로우를 방지 */
            return rsp - 8 >= USER_STACK_END;
        default:
            PANIC("invalid stack growth type!");
    }
}

/**
 * 스택 성장을 위한 메모리 접근이 유효한지 검증합니다.
 *
 * @param rsp 현재 스택 포인터 위치
 * @param addr page fault가 발생한 메모리 주소
 * @param type 스택 접근 타입 (GENERAL 또는 PUSH)
 * @return 유효한 접근이면 true, 그렇지 않으면 false
 */
static bool is_addr_access_valid(void *rsp, void *addr, enum sg_type type)
{
    switch (type)
    {
        case GENERAL:
            /* 일반적인 스택 접근: 스택 포인터보다 높은 주소 접근만 허용
             * (스택은 아래쪽으로 성장하므로 rsp 위쪽 접근은 유효함) */
            return addr >= rsp;
        case PUSH:
            /* PUSH 명령어 접근: x86-64 PUSH는 스택 포인터 조정 전에
             * rsp-8 위치의 접근 권한을 확인하므로 정확히 rsp-8에서만 유효 */
            return addr == rsp - 8;
        default:
            PANIC("invalid stack growth type!");
    }
}

/**
 * 접근 주소가 사용자 스택의 상한선을 넘지 않는지 검증합니다.
 *
 * @param addr 검증할 메모리 주소
 * @return 주소가 USER_STACK 이하이면 true, 그렇지 않으면 false
 */
static bool is_addr_valid(void *addr)
{
    /* 접근 주소가 USER_STACK(0x47480000) 이하인지 확인
     * (스택 상한선을 벗어난 접근을 방지하여 메모리 보안 유지) */
    return addr <= USER_STACK;
}

/* 폴트를 검증합니다. - 성공하면 true를 반환합니다. */
bool vm_try_handle_fault(struct intr_frame *f, void *addr, bool user,
                         bool write, bool not_present)
{
    struct supplemental_page_table *spt = &thread_current()->spt;
    struct page *page = NULL;
    void *rsp = f->rsp;

    if (addr == NULL)
    {
        return false;
    }

    if (is_kernel_vaddr(addr))
    {
        return false;
    }

    if (not_present)
    {
        if (!user)
        {
            /* kenel 모드에서 page fault 발생 시, 이전에 syscall에서 설정해
             * 두었던 rsp 값을유효한 rsp 값으로 설정 */
            rsp = thread_current()->rsp;
        }

        if (is_stack_pointer_valid(rsp, GENERAL) &&
            is_addr_access_valid(rsp, addr, GENERAL) && is_addr_valid(addr))
        {
            /* 일반적인 stack 확장 경우. - stack growth signal로 판단한다 */
            vm_stack_growth(addr);
        }
        else if (is_stack_pointer_valid(rsp, PUSH) &&
                 is_addr_access_valid(rsp, addr, PUSH) && is_addr_valid(addr))
        {
            /* stack의 push 동작 시 - stack growth signal로 판단한다 */
            vm_stack_growth(addr);
        }

        page = spt_find_page(spt, addr);
        if (page == NULL)
        {
            /* spt에 페이지가 존재하지 않으면 처리 실패. */
            return false;
        }

        if (write == true && page->writable == false)
        {
            /* spt에 존재하는 page가 writable하지 않으면 처리 실패. */
            return false;
        }

        return vm_do_claim_page(page);
    }
    else
    {
        return false;
    }
}

/* 페이지를 해제합니다. */
/* ! DO NOT MODIFY THIS FUNCTION. */
void vm_dealloc_page(struct page *page)
{
    destroy(page);
    free(page);
}

/* VA에 할당된 페이지를 확보(claim)합니다. */
bool vm_claim_page(void *va)
{
    struct thread *curr = thread_current();
    struct page *page = spt_find_page(&curr->spt, va);

    if (page == NULL)
    {
        return false;
    }

    return vm_do_claim_page(page);
}

/* PAGE를 확보(claim)하고 MMU를 설정합니다. */
static bool vm_do_claim_page(struct page *page)
{
    struct frame *frame = vm_get_frame();
    if (frame == NULL)
    {
        return false;
    }

    /* 링크를 설정합니다. */
    frame->page = page;
    page->frame = frame;

    /* 페이지의 가상 주소(VA)를 프레임의 물리 주소(PA)에
     * 매핑하도록 페이지 테이블 엔트리를 삽입합니다. */
    struct thread *curr = thread_current();
    if (!pml4_set_page(curr->pml4, page->va, frame->kva, page->writable))
    {
        free(frame);
        return false;
    }

    if (!swap_in(page, frame->kva))
    {
        free(frame);
        pml4_clear_page(curr->pml4, page->va);
        return false;
    }

    return true;
}

uint64_t do_hash(const struct hash_elem *e, void *aux)
{
    struct page *p = hash_entry(e, struct page, hash_elem);
    uintptr_t key = (uintptr_t) p->va;
    return hash_bytes(&key, sizeof(p->va));
}

bool hash_less(const struct hash_elem *a, const struct hash_elem *b, void *aux)
{
    struct page *page_a = hash_entry(a, struct page, hash_elem);
    struct page *page_b = hash_entry(b, struct page, hash_elem);

    return (uintptr_t) page_a->va < (uintptr_t) page_b->va;
}

/* 새로운 보조 페이지 테이블을 초기화합니다. */
void supplemental_page_table_init(struct supplemental_page_table *spt)
{
    hash_init(&spt->hash_table, do_hash, hash_less, NULL);
}

/* src에서 dst로 보조 페이지 테이블을 복사합니다. */
bool supplemental_page_table_copy(struct supplemental_page_table *dst,
                                  struct supplemental_page_table *src)
{
    struct hash_iterator i;

    hash_first(&i, &src->hash_table);
    while (hash_next(&i))
    {
        struct page *parent_page =
            hash_entry(hash_cur(&i), struct page, hash_elem);
        enum vm_type future_type = page_get_type(
            parent_page); /* uninit 페이지가 미래에 될 타입을 가져온다. */
        void *upage = parent_page->va;
        bool writable = parent_page->writable;

        if (VM_TYPE(parent_page->operations->type) == VM_UNINIT)
        {
            struct lazy_load_info *aux =
                (struct lazy_load_info *) malloc(sizeof(struct lazy_load_info));
            memcpy(aux, parent_page->uninit.aux, sizeof(struct lazy_load_info));

            if (!vm_alloc_page_with_initializer(future_type, upage, writable,
                                                parent_page->uninit.init, aux))
            {
                return false;
            }
        }
        else
        {
            if (!vm_alloc_page(future_type, upage, writable))
            {
                return false;
            }

            if (!vm_claim_page(upage))
            {
                return false;
            }

            struct page *child_page = spt_find_page(dst, upage);
            memcpy(child_page->frame->kva, parent_page->frame->kva, PGSIZE);
            child_page->frame->page = child_page;
        }
    }

    return true;
}

void hash_destructor(struct hash_elem *e, void *aux)
{
    struct page *page_to_destroy = hash_entry(e, struct page, hash_elem);

    destroy(page_to_destroy); /* 실제 file type에 따른 destroy 함수 호출*/
    free(page_to_destroy);    /* 호출자의 몫임 */
}

/* 보조 페이지 테이블이 보유하고 있던 모든 리소스를 해제합니다.
 *이 함수는 프로세스가 종료될 때 호출됩니다 (userprog/process.c의
 *process_exit()에서). 페이지 테이블의 각 페이지 항목을 반복하며 테이블 내
 *페이지에 대해 destroy(page)를 호출해야 합니다. 이 함수에서는 실제 페이지
 *테이블(pml4)과 물리 메모리(palloc으로 할당된 메모리)에 대해 걱정할 필요가
 *없습니다; 호출자가 보조 페이지 테이블이 정리된 후 이를 정리합니다. */
void supplemental_page_table_kill(struct supplemental_page_table *spt)
{
    /* TODO: 수정된 모든 내용을 저장소에 기록합니다. */
    hash_destroy(&spt->hash_table, hash_destructor);
}