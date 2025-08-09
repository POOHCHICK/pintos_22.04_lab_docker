/* file.c: 메모리를 기반으로 하는 파일 객체(mmap된 객체)의 구현 */

#include "vm/vm.h"

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

/* mmap 수행 */
void *do_mmap(void *addr, size_t length, int writable, struct file *file,
              off_t offset)
{
}

/* munmap 수행 */
void do_munmap(void *addr)
{
}