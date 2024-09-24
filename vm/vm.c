/* vm.c: Generic interface for virtual memory objects. */

#include "lib/kernel/hash.h"
#include "threads/malloc.h"
#include "vm/vm.h"
#include "vm/inspect.h"
#include "include/threads/vaddr.h"
#include "include/threads/mmu.h"
//#include "userprog/process.c"

static struct frame_table frame_table;

/* Initializes the virtual memory subsystem by invoking each subsystem's
 * intialize codes. */
void
vm_init (void) {
	vm_anon_init ();
	vm_file_init ();
#ifdef EFILESYS  /* For project 4 */
	pagecache_init ();
#endif
	register_inspect_intr ();
	/* DO NOT MODIFY UPPER LINES. */
	/* TODO: Your code goes here. */
}

/* Get the type of the page. This function is useful if you want to know the
 * type of the page after it will be initialized.
 * This function is fully implemented now. */
enum vm_type
page_get_type (struct page *page) {
	int ty = VM_TYPE (page->operations->type);
	switch (ty) {
		case VM_UNINIT:
			return VM_TYPE (page->uninit.type);
		default:
			return ty;
	}
}

/* Helpers */
static struct frame *vm_get_victim (void);
static bool vm_do_claim_page (struct page *page);
static struct frame *vm_evict_frame (void);

/* Create the pending page object with initializer. If you want to create a
 * page, do not create it directly and make it through this function or
 * `vm_alloc_page`. */
bool
vm_alloc_page_with_initializer (enum vm_type type, void *upage, bool writable,
		vm_initializer *init, void *aux) {

	ASSERT (VM_TYPE(type) != VM_UNINIT)

	struct supplemental_page_table *spt = &thread_current ()->spt;

	/* Check wheter the upage is already occupied or not. */
	if (spt_find_page (spt, upage) == NULL) {
		/* TODO: Create the page, fetch the initialier according to the VM type,
		 * TODO: and then create "uninit" page struct by calling uninit_new. You
		 * TODO: should modify the field after calling the uninit_new. */
		struct page *p = (struct page *)malloc(sizeof(struct page));

		bool (*page_initializer) (struct page *, enum vm_type, void *kva);

		switch (VM_TYPE(type))
		{
		case VM_ANON:
			page_initializer = anon_initializer;
			break;
		case VM_FILE:
			page_initializer = file_backed_initializer;
			break;
		default:
			break;
		}

		uninit_new(p,upage,init,type,aux,page_initializer);

		p->writable = writable;

		/* TODO: Insert the page into the spt. */
		return spt_insert_page(spt,p);
	}
err:
	return false;
}

/* Find VA from spt and return page. On error, return NULL. */
struct page *
spt_find_page (struct supplemental_page_table *spt UNUSED, void *va UNUSED) {
	struct page *page = NULL;
	/* TODO: Fill this function. */
	page = (struct page*)malloc(sizeof(struct page));
	struct hash_elem *e;
	
	page->va = pg_round_down(va);
	e = hash_find(&(spt->hash_table),&(page->hash_elem));

	free(page);

	return e != NULL ? hash_entry(e,struct page,hash_elem) : NULL;
}

/* Insert PAGE into spt with validation. */
bool
spt_insert_page (struct supplemental_page_table *spt UNUSED,
		struct page *page UNUSED) {
	int succ = false;
	/* TODO: Fill this function. */

	if(hash_insert(&spt->hash_table,&page->hash_elem) == NULL)
		succ = true;

	return succ;
}

void
spt_remove_page (struct supplemental_page_table *spt, struct page *page) {
	vm_dealloc_page (page);
	return true;
}

unsigned page_hash(const struct hash_elem *p_,void *aux UNUSED){
	const struct page *p = hash_entry(p_,struct page,hash_elem);
	return hash_bytes(&p->va,sizeof p->va);
}

bool page_less(const struct hash_elem *a_,const struct hash_elem *b_,void *aux UNUSED){
	const struct page *a = hash_entry (a_, struct page, hash_elem);
  	const struct page *b = hash_entry (b_, struct page, hash_elem);

  	return a->va < b->va;
}

/* Get the struct frame, that will be evicted. */
static struct frame *
vm_get_victim (void) {
	struct frame *victim = NULL;
	 /* TODO: The policy for eviction is up to you. */

	return victim;
}

/* Evict one page and return the corresponding frame.
 * Return NULL on error.*/
static struct frame *
vm_evict_frame (void) {
	struct frame *victim UNUSED = vm_get_victim ();
	/* TODO: swap out the victim and return the evicted frame. */

	return NULL;
}

/* palloc() and get frame. If there is no available page, evict the page
 * and return it. This always return valid address. That is, if the user pool
 * memory is full, this function evicts the frame to get the available memory
 * space.*/
static struct frame *
vm_get_frame (void) {
	struct frame *frame = NULL;
	/* TODO: Fill this function. */
	frame = (struct frame*)malloc(sizeof(struct frame));
	frame->page = NULL;
	frame->kva = palloc_get_page(PAL_USER);
	list_init(&frame_table.frames);

	if(frame->kva == NULL){
		frame = vm_evict_frame();
		frame->page = NULL;
		return frame;
	}
	list_push_back(&frame_table.frames,&frame->frame_elem);

	ASSERT (frame != NULL);
	ASSERT (frame->page == NULL);
	return frame;
}

/* Growing the stack. */
static void
vm_stack_growth (void *addr UNUSED) {
	vm_alloc_page(VM_ANON | VM_MARKER_0,addr,1);
}

/* Handle the fault on write_protected page */
static bool
vm_handle_wp (struct page *page UNUSED) {
}

/* Return true on success */
bool
vm_try_handle_fault (struct intr_frame *f UNUSED, void *addr UNUSED,
		bool user UNUSED, bool write UNUSED, bool not_present UNUSED) {
	struct supplemental_page_table *spt UNUSED = &thread_current ()->spt;
	struct page *page = NULL;
	/* TODO: Validate the fault */
	/* TODO: Your code goes here */
	if(addr == NULL || is_kernel_vaddr(addr))
		return false;

	//physical page가 존재하지 않을 경우
	if(not_present){
		uint64_t current_rsp_point;
		if(user)
			current_rsp_point = f->rsp;
		else
			current_rsp_point = thread_current()->rsp_point;
		
		//rsp - 8이 페이지 할당한 만큼의 영역 내에 있고, addr값이 rsp -8이며 addr가 USER STACK보다 아래에 있을 경우
		bool is_stack_allowance_range = (USER_STACK - MAX_STACK_POINT <= current_rsp_point - 8
		&& current_rsp_point - 8 == addr && addr <= USER_STACK);
		//rsp이 페이지 할당한 만큼의 영역 내에 있고, addr값이 rsp 영역 내부에 있으며 addr가 USER STACK보다 아래에 있을 경우
		bool is_in_allowance_range = (USER_STACK - MAX_STACK_POINT <= current_rsp_point
		&& current_rsp_point <= addr && addr <= USER_STACK);
		
		if(is_stack_allowance_range || is_in_allowance_range){
			vm_stack_growth(pg_round_down(addr));
		}
			page = spt_find_page(spt,addr);
			if(page == NULL)
				return false;
			if(write == 1 && page->writable == 0)
				return false;

			return vm_do_claim_page(page);
	}

	return false;
}

/* Free the page.
 * DO NOT MODIFY THIS FUNCTION. */
void
vm_dealloc_page (struct page *page) {
	destroy (page);
	free (page);
}

/* Claim the page that allocate on VA. */
bool
vm_claim_page (void *va UNUSED) {
	struct page *page = NULL;
	/* TODO: Fill this function */
	page = spt_find_page(&thread_current()->spt,va);

	if(page == NULL)
		return false;

	return vm_do_claim_page (page);
}

/* Claim the PAGE and set up the mmu. */
static bool
vm_do_claim_page (struct page *page) {
	struct frame *frame = vm_get_frame ();

	/* Set links */
	frame->page = page;
	page->frame = frame;

	/* TODO: Insert page table entry to map page's VA to frame's PA. */
	struct thread *current = thread_current();
	pml4_set_page(current->pml4, page->va, frame->kva, page->writable);

	return swap_in(page,frame->kva);
}

/* Initialize new supplemental page table */
void
supplemental_page_table_init (struct supplemental_page_table *spt UNUSED) {
	hash_init(&(spt->hash_table),page_hash,page_less,NULL);
}

/* Copy supplemental page table from src to dst */
bool
supplemental_page_table_copy (struct supplemental_page_table *dst UNUSED,
		struct supplemental_page_table *src UNUSED) {
			struct hash_iterator iterator;
			hash_first(&iterator,&src->hash_table);

			while(hash_next(&iterator)){
				struct page *src_page = hash_entry(hash_cur(&iterator),struct page,hash_elem);
				enum vm_type type = src_page->operations->type;
				void *upage = src_page->va;
				bool writable = src_page->writable;

				if(type == VM_UNINIT){
					vm_initializer *initializer = src_page->uninit.init;
					void *aux = src_page->uninit.aux;
					vm_alloc_page_with_initializer(VM_ANON,upage,writable,initializer,aux);
					continue;
				}

				if(!vm_alloc_page(type,upage,writable)){
					return false;
				}

				if(!vm_claim_page(upage))
					return false;

				struct page *dst_page = spt_find_page(dst,upage);
				memcpy(dst_page->frame->kva,src_page->frame->kva,PGSIZE);
			}
			return true;
}

/* Free the resource hold by the supplemental page table */
void
supplemental_page_table_kill (struct supplemental_page_table *spt UNUSED) {
	/* TODO: Destroy all the supplemental_page_table hold by thread and
	 * TODO: writeback all the modified contents to the storage. */
	hash_clear(&spt->hash_table,hash_page_destroy);
}

void hash_page_destroy(struct hash_elem *e,void *aux){
	struct page *page = hash_entry(e,struct page,hash_elem);
	destroy(page);
	free(page);
}