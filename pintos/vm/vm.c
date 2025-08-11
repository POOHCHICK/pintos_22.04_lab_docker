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
static void vm_stack_growth(void *addr UNUSED)
{
}

/* 쓰기 보호된 페이지에서 발생한 폴트를 처리합니다. */
static bool vm_handle_wp(struct page *page UNUSED)
{
}

/* 폴트를 검증합니다. - 성공하면 true를 반환합니다. */
bool vm_try_handle_fault(struct intr_frame *f, void *addr, bool user,
                         bool write, bool not_present)
{
    struct supplemental_page_table *spt = &thread_current()->spt;
    struct page *page = NULL;

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
        struct page *page = spt_find_page(spt, addr);
        if (page == NULL)
        {
            return false;
        }

        if (write == true && page->writable == false)
        {
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
    if (!pml4_set_page(curr->pml4, page->va, frame->kva, true))
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
}

/* 보조 페이지 테이블이 보유한 자원을 해제합니다. */
void supplemental_page_table_kill(struct supplemental_page_table *spt)
{
    /* TODO: 스레드가 보유한 모든 supplemental_page_table을 제거하고,
     * TODO: 수정된 모든 내용을 저장소에 기록합니다. */
}
