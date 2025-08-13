/* file.c: 메모리를 기반으로 하는 파일 객체(mmap된 객체)의 구현 */

#include "vm/vm.h"
#include "threads/vaddr.h"
#include "userprog/process.h"

static bool file_backed_swap_in(struct page *page, void *kva);
static bool file_backed_swap_out(struct page *page);
static void file_backed_destroy(struct page *page);

/* ! DO NOT MODIFY this struct */
static const struct page_operations file_ops = {
    .swap_in = file_backed_swap_in,
    .swap_out = file_backed_swap_out,
    .destroy = file_backed_destroy,
    .type = VM_FILE,
};

/* 파일 기반 VM의 초기화 함수 */
void vm_file_init(void)
{
}

/* 파일 기반 페이지 초기화 */
bool file_backed_initializer(struct page *page, enum vm_type type, void *kva)
{
    /* 핸들러 설정 */
    page->operations = &file_ops;

    struct file_page *file_page = &page->file;
}

/* 파일에서 내용을 읽어 페이지를 스왑 인 */
static bool file_backed_swap_in(struct page *page, void *kva)
{
    struct file_page *file_page UNUSED = &page->file;
}

/* 파일에 내용을 기록하여 페이지를 스왑 아웃 */
static bool file_backed_swap_out(struct page *page)
{
    struct file_page *file_page UNUSED = &page->file;
}

/* 파일 기반 페이지를 제거합니다. PAGE는 호출자가 해제합니다. */
static void file_backed_destroy(struct page *page)
{
    struct file_page *file_page UNUSED = &page->file;
}

static bool lazy_load_file(struct page *page, void *aux)
{
    struct lazy_load_info *load_info = (struct lazy_load_info *) aux;

    struct file *file_to_load = load_info->file_to_load;
    off_t ofs = load_info->ofs;
    size_t page_read_bytes = load_info->page_read_bytes;
    size_t page_zero_bytes = PGSIZE - page_read_bytes;

    file_seek(file_to_load, ofs);

    if (file_read(file_to_load, page->frame->kva, page_read_bytes) !=
        (int) page_read_bytes)
    {
        palloc_free_page(page->frame->kva);
        return false;
    }

    memset(page->frame->kva + page_read_bytes, 0, page_zero_bytes);

    return true;
}

/* mmap 수행 */
void *do_mmap(void *addr, size_t length, int writable, struct file *file,
              off_t offset)
{
    /* read_bytes: 총 읽어야 하는 바이트 수 */
    off_t file_size_bytes = file_length(file);
    if (file_size_bytes < length)
    {
        length = file_size_bytes;
    }
    uint32_t read_bytes = length;

    while (read_bytes > 0)
    {
        size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
        size_t page_zero_bytes = PGSIZE - page_read_bytes;

        struct lazy_load_info *aux = malloc(sizeof(struct lazy_load_info));
        aux->file_to_load = file;
        aux->ofs = offset;
        aux->page_read_bytes = page_read_bytes;

        if (!vm_alloc_page_with_initializer(VM_FILE, addr, writable,
                                            lazy_load_file, aux))
            return false;

        read_bytes -= page_read_bytes;
        addr += PGSIZE;
        offset = offset + page_read_bytes;
    }

    return addr;
}

/* munmap 수행 */
void do_munmap(void *addr)
{
}