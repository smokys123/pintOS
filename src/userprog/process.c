#include "userprog/process.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <list.h>
#include "userprog/gdt.h"
#include "userprog/pagedir.h"
#include "userprog/tss.h"
#include "userprog/syscall.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/palloc.h"
#include "threads/malloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "lib/kernel/list.h"

#include "vm/page.h"

static thread_func start_process NO_RETURN;
static bool load (const char *cmdline, void (**eip) (void), void **esp);

/* Starts a new thread running a user program loaded from
   FILENAME.  The new thread may be scheduled (and may even exit)
   before process_execute() returns.  Returns the new process's
   thread id, or TID_ERROR if the thread cannot be created. */
tid_t
process_execute (const char *file_name) 
{
  char *fn_copy;
  tid_t tid;
  char *parsed_file_name, *save_ptr;
  /* Make a copy of FILE_NAME.
     Otherwise there's a race between the caller and load(). */
  fn_copy = palloc_get_page (0);
  if (fn_copy == NULL)
    return TID_ERROR;
  strlcpy (fn_copy, file_name, PGSIZE);
  
  // 첫번째 공백 전까지의 문자열 저장 
  parsed_file_name = palloc_get_page(0);
  if(parsed_file_name ==NULL)
      return TID_ERROR;
  strlcpy(parsed_file_name, file_name, PGSIZE);
  parsed_file_name = strtok_r(parsed_file_name, " ",&save_ptr);

  /* Create a new thread to execute FILE_NAME. */
  //thread_create 함수의 첫번째 인자값은 스레드의 이름
  tid = thread_create (parsed_file_name, PRI_DEFAULT, start_process, fn_copy);
 
  /*메모리 해*/
  palloc_free_page(parsed_file_name); 
  if (tid == TID_ERROR)
    palloc_free_page (fn_copy); 
  return tid;
}

/* A thread function that loads a user process and starts it
   running. */
static void
start_process (void *file_name_)
{
  char *file_name = file_name_;
  char *token = NULL;
  char *save_ptr = NULL;
  char **parsed_list = NULL;
  int count = 0;
  int i=0;
  struct intr_frame if_;
  bool success;
  
  //문자열 파싱
  parsed_list = palloc_get_page(0);
  for(token = strtok_r(file_name, " ", &save_ptr); token != NULL; token = strtok_r(NULL, " ",&save_ptr)){
    parsed_list[count] = malloc(strlen(token));
    strlcpy(parsed_list[count], token, PGSIZE);
    count++;
  }
  //vm_init함수를 이용해서 해시 테이블을 초기화 합니다.
  vm_init(&thread_current()->vm);
  list_init( &thread_current() -> mmap_list);
  /* Initialize interrupt frame and load executable. */
  memset (&if_, 0, sizeof if_);
  if_.gs = if_.fs = if_.es = if_.ds = if_.ss = SEL_UDSEG;
  if_.cs = SEL_UCSEG;
  if_.eflags = FLAG_IF | FLAG_MBS;
 
  //파싱된 문자열의 첫번째 문자열은 프로그램 이름 
  success = load (parsed_list[0], &if_.eip, &if_.esp);
  //메모리 해제
  palloc_free_page (file_name);
  //load 함수 실행 완료시 부모 프로세스 다시 진
  sema_up(&thread_current()->sema_load);
  /* If load failed, quit. */
  //메모리 적재 실패시 프로세스 디스크립터에 적재 실패를 알림
  if (!success) {
    thread_current()->load_flag = FAIL_LOAD;  
    thread_exit ();
  }
  else{// 메모리 적재 성공시 프로세스 디스크립터에 적재 성공을 알림
    thread_current()->load_flag = SUCCESS_LOAD;
    //유저 스택에 인자값 저장
    argument_stack(parsed_list, count, &if_.esp);
  }
  
  //메모리 해제
  for(i=0; i< count; i++){
    free(parsed_list[i]);
  }
  palloc_free_page(parsed_list);
  /* Start the user process by simulating a return from an
     interrupt, implemented by intr_exit (in
     threads/intr-stubs.S).  Because intr_exit takes all of its
     arguments on the stack in the form of a `struct intr_frame',
     we just point the stack pointer (%esp) to our stack frame
     and jump to it. */
  asm volatile ("movl %0, %%esp; jmp intr_exit" : : "g" (&if_) : "memory");
  NOT_REACHED ();
}

/* Waits for thread TID to die and returns its exit status.  If
   it was terminated by the kernel (i.e. killed due to an
   exception), returns -1.  If TID is invalid o행r if it was not a
   child of the calling process, or if process_wait() has already
   been successfully called for the given TID, returns -1
   immediately, without waiting.

   This function will be implemented in problem 2-2.  For now, it
   does nothing. */
int
process_wait (tid_t child_tid UNUSED) 
{
 int status;
  //해당 tid의 자식 프로세스 디스크립터를 가져옴
  struct thread *child_process = get_child_process(child_tid);
  if(child_process==NULL){  //없을시 예외처리
    return -1;
  }
  // 자식 프로세스가 종료 될때 까지 대기
  sema_down( &child_process ->sema_exit);
  // 자식프로세스 디스크립터  제거, exit status 리
  list_remove( &child_process -> child_elem);
  status = (child_process->exit_status);
  remove_child_process(child_process);
  return status; 
}

/* Free the current process's resources. */
void
process_exit (void)
{
  struct thread *cur = thread_current ();
  uint32_t *pd;
  
  //해당 프로세스에 열른 모든 파일을 닫음  
  while( cur -> next_fd > 2){
    cur -> next_fd --;
    process_close_file( cur-> next_fd) ;
  }
  //프로세스 종료 시 현재 실행하고 있는 프로그램 닫음 
  if( cur-> exfd)
    file_close( cur->exfd);

  //메모리 해제
  palloc_free_page( cur-> ftd);
  munmap(-1);
  
  /* Destroy the current process's page directory and switch back
     to the kernel-only page directory. */
  vm_destroy(&cur->vm);
  pd = cur->pagedir;
  if (pd != NULL) 
    {
      /* Correct ordering here is crucial.  We must set
         cur->pagedir to NULL before switching page directories,
         so that a timer interrupt can't switch back to the
         process page directory.  We must activate the base page
         directory before destroying the process's page
         directory, or our active page directory will be one
         that's been freed (and cleared). */
      cur->pagedir = NULL;
      pagedir_activate (NULL);
      pagedir_destroy (pd);
    }
}

/* Sets up the CPU for running user code in the current
   thread.
   This function is called on every context switch. */
void
process_activate (void)
{
  struct thread *t = thread_current ();

  /* Activate thread's page tables. */
  pagedir_activate (t->pagedir);

  /* Set thread's kernel stack for use in processing
     interrupts. */
  tss_update ();
}

/* We load ELF binaries.  The following definitions are taken
   from the ELF specification, [ELF1], more-or-less verbatim.  */

/* ELF types.  See [ELF1] 1-2. */
typedef uint32_t Elf32_Word, Elf32_Addr, Elf32_Off;
typedef uint16_t Elf32_Half;

/* For use with ELF types in printf(). */
#define PE32Wx PRIx32   /* Print Elf32_Word in hexadecimal. */
#define PE32Ax PRIx32   /* Print Elf32_Addr in hexadecimal. */
#define PE32Ox PRIx32   /* Print Elf32_Off in hexadecimal. */
#define PE32Hx PRIx16   /* Print Elf32_Half in hexadecimal. */

/* Executable header.  See [ELF1] 1-4 to 1-8.
   This appears at the very beginning of an ELF binary. */
struct Elf32_Ehdr
  {
    unsigned char e_ident[16];
    Elf32_Half    e_type;
    Elf32_Half    e_machine;
    Elf32_Word    e_version;
    Elf32_Addr    e_entry;
    Elf32_Off     e_phoff;
    Elf32_Off     e_shoff;
    Elf32_Word    e_flags;
    Elf32_Half    e_ehsize;
    Elf32_Half    e_phentsize;
    Elf32_Half    e_phnum;
    Elf32_Half    e_shentsize;
    Elf32_Half    e_shnum;
    Elf32_Half    e_shstrndx;
  };

/* Program header.  See [ELF1] 2-2 to 2-4.
   There are e_phnum of these, starting at file offset e_phoff
   (see [ELF1] 1-6). */
struct Elf32_Phdr
  {
    Elf32_Word p_type;
    Elf32_Off  p_offset;
    Elf32_Addr p_vaddr;
    Elf32_Addr p_paddr;
    Elf32_Word p_filesz;
    Elf32_Word p_memsz;
    Elf32_Word p_flags;
    Elf32_Word p_align;
  };

/* Values for p_type.  See [ELF1] 2-3. */
#define PT_NULL    0            /* Ignore. */
#define PT_LOAD    1            /* Loadable segment. */
#define PT_DYNAMIC 2            /* Dynamic linking info. */
#define PT_INTERP  3            /* Name of dynamic loader. */
#define PT_NOTE    4            /* Auxiliary info. */
#define PT_SHLIB   5            /* Reserved. */
#define PT_PHDR    6            /* Program header table. */
#define PT_STACK   0x6474e551   /* Stack segment. */

/* Flags for p_flags.  See [ELF3] 2-3 and 2-4. */
#define PF_X 1          /* Executable. */
#define PF_W 2          /* Writable. */
#define PF_R 4          /* Readable. */

static bool setup_stack (void **esp);
static bool validate_segment (const struct Elf32_Phdr *, struct file *);
static bool load_segment (struct file *file, off_t ofs, uint8_t *upage,
                          uint32_t read_bytes, uint32_t zero_bytes,
                          bool writable);

/* Loads an ELF executable from FILE_NAME into the current thread.
   Stores the executable's entry point into *EIP
   and its initial stack pointer into *ESP.
   Returns true if successful, false otherwise. */
bool
load (const char *file_name, void (**eip) (void), void **esp) 
{
  struct thread *t = thread_current();
  struct Elf32_Ehdr ehdr;
  struct file *file = NULL;
  off_t file_ofs;
  bool success = false;
  int i;

  /* Allocate and activate page directory. */
  t->pagedir = pagedir_create ();
  if (t->pagedir == NULL) 
    goto done;
  process_activate();

  /* Open executable file. */
  //파일의 동시접근을 막기위한 락
  lock_acquire( &filesys_lock);
  file = filesys_open(file_name);
  if (file == NULL) 
  { 
    //파일이 없을시 락해제
    lock_release(&filesys_lock);
    printf ("load: %s: open failed\n", file_name);
    goto done;  
  }
  // 파일 오픈 성공시 file_deny_write함수 호출 및 락해
  t->exfd = file;
  file_deny_write(file);
  lock_release( &filesys_lock);

  /* Read and verify executable header. */
  if (file_read (file, &ehdr, sizeof ehdr) != sizeof ehdr
      || memcmp (ehdr.e_ident, "\177ELF\1\1\1", 7)
      || ehdr.e_type != 2
      || ehdr.e_machine != 3
      || ehdr.e_version != 1
      || ehdr.e_phentsize != sizeof (struct Elf32_Phdr)
      || ehdr.e_phnum > 1024) 
    {
      printf ("load: %s: error loading executable\n", file_name);
      goto done; 
    }

  /* Read program headers. */
  file_ofs = ehdr.e_phoff;
  for (i = 0; i < ehdr.e_phnum; i++) 
    {
      struct Elf32_Phdr phdr;

      if (file_ofs < 0 || file_ofs > file_length (file))
        goto done;
      file_seek (file, file_ofs);

      if (file_read (file, &phdr, sizeof phdr) != sizeof phdr)
        goto done;
      file_ofs += sizeof phdr;
      switch (phdr.p_type) 
        {
        case PT_NULL:
        case PT_NOTE:
        case PT_PHDR:
        case PT_STACK:
        default:
          /* Ignore this segment. */
          break;
        case PT_DYNAMIC:
        case PT_INTERP:
        case PT_SHLIB:
          goto done;
        case PT_LOAD:
          if (validate_segment (&phdr, file)) 
            {
              bool writable = (phdr.p_flags & PF_W) != 0;
              uint32_t file_page = phdr.p_offset & ~PGMASK;
              uint32_t mem_page = phdr.p_vaddr & ~PGMASK;
              uint32_t page_offset = phdr.p_vaddr & PGMASK;
              uint32_t read_bytes, zero_bytes;
              if (phdr.p_filesz > 0)
                {
                  /* Normal segment.
                     Read initial part from disk and zero the rest. */
                  read_bytes = page_offset + phdr.p_filesz;
                  zero_bytes = (ROUND_UP (page_offset + phdr.p_memsz, PGSIZE)
                                - read_bytes);
                }
              else 
                {
                  /* Entirely zero.
                     Don't read anything from disk. */
                  read_bytes = 0;
                  zero_bytes = ROUND_UP (page_offset + phdr.p_memsz, PGSIZE);
                }
              if (!load_segment (file, file_page, (void *) mem_page,
                                 read_bytes, zero_bytes, writable))
                goto done;
            }
          else
            goto done;
          break;
        }
    }

  /* Set up stack. */
  if (!setup_stack (esp))
    goto done;

  /* Start address. */
  *eip = (void (*) (void)) ehdr.e_entry;

  success = true;

 done:
  /* We arrive here whether the load is successful or not. */
//  file_close (file);   add to process_exit(void) 
  return success;
}

/* load() helpers. */

static bool install_page (void *upage, void *kpage, bool writable);

/* Checks whether PHDR describes a valid, loadable segment in
   FILE and returns true if so, false otherwise. */
static bool
validate_segment (const struct Elf32_Phdr *phdr, struct file *file) 
{
  /* p_offset and p_vaddr must have the same page offset. */
  if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK)) 
    return false; 

  /* p_offset must point within FILE. */
  if (phdr->p_offset > (Elf32_Off) file_length (file)) 
    return false;

  /* p_memsz must be at least as big as p_filesz. */
  if (phdr->p_memsz < phdr->p_filesz) 
    return false; 

  /* The segment must not be empty. */
  if (phdr->p_memsz == 0)
    return false;
  
  /* The virtual memory region must both start and end within the
     user address space range. */
  if (!is_user_vaddr ((void *) phdr->p_vaddr))
    return false;
  if (!is_user_vaddr ((void *) (phdr->p_vaddr + phdr->p_memsz)))
    return false;

  /* The region cannot "wrap around" across the kernel virtual
     address space. */
  if (phdr->p_vaddr + phdr->p_memsz < phdr->p_vaddr)
    return false;

  /* Disallow mapping page 0.
     Not only is it a bad idea to map page 0, but if we allowed
     it then user code that passed a null pointer to system calls
     could quite likely panic the kernel by way of null pointer
     assertions in memcpy(), etc. */
  if (phdr->p_vaddr < PGSIZE)
    return false;

  /* It's okay. */
  return true;
}

/* Loads a segment starting at offset OFS in FILE at address
   UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
   memory are initialized, as follows:

        - READ_BYTES bytes at UPAGE must be read from FILE
          starting at offset OFS.

        - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.

   The pages initialized by this function must be writable by the
   user process if WRITABLE is true, read-only otherwise.

   Return true if successful, false if a memory allocation error
   or disk read error occurs. */
static bool
load_segment (struct file *file, off_t ofs, uint8_t *upage,
              uint32_t read_bytes, uint32_t zero_bytes, bool writable) 
{
  ASSERT ((read_bytes + zero_bytes) % PGSIZE == 0);
  ASSERT (pg_ofs (upage) == 0);
  ASSERT (ofs % PGSIZE == 0);

  file_seek (file, ofs);
  while (read_bytes > 0 || zero_bytes > 0) 
    {
      /* Calculate how to fill this page.
         We will read PAGE_READ_BYTES bytes from FILE
         and zero the final PAGE_ZERO_BYTES bytes. */
      size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
      size_t page_zero_bytes = PGSIZE - page_read_bytes;

      struct vm_entry *vm_e = (struct vm_entry *)malloc(sizeof(struct vm_entry));    //vm_entry생성

      //vm_entry 필드 초기화
      vm_e->type = VM_BIN;          
      vm_e->writable = writable;
      vm_e->is_loaded = false;
      vm_e->file = file;
      vm_e->offset = ofs;
      vm_e->vaddr = upage;
      vm_e->read_bytes = page_read_bytes;
      vm_e->zero_bytes = page_zero_bytes;

      if(!insert_vme(&thread_current()->vm, vm_e)){      //vm_entry 해시테이블에 vme 삽입
          return false;
      }      
       
/*
      // Get a page of memory. 
      uint8_t *kpage = palloc_get_page (PAL_USER);
      if (kpage == NULL)
        return false;

      // Load this page. 
      if (file_read (file, kpage, page_read_bytes) != (int) page_read_bytes)
        {
          palloc_free_page (kpage);
          return false; 
        }
      memset (kpage + page_read_bytes, 0, page_zero_bytes);

      // Add the page to the process's address space. //
      if (!install_page (upage, kpage, writable)) 
        {
          palloc_free_page (kpage);
          return false; 
        }
*/
      /* Advance. */
      read_bytes -= page_read_bytes;
      zero_bytes -= page_zero_bytes;
      ofs += page_read_bytes;
      upage += PGSIZE;
    }

  return true;
}

/* Create a minimal stack by mapping a zeroed page at the top of
   user virtual memory. */
static bool
setup_stack (void **esp) 
{
  uint8_t *kpage;
  bool success = false;

  kpage = palloc_get_page (PAL_USER | PAL_ZERO);
  if (kpage != NULL) 
    {
      success = install_page (((uint8_t *) PHYS_BASE) - PGSIZE, kpage, true);
      if (success){
        *esp = PHYS_BASE;      
      }
      else
        palloc_free_page (kpage);
    }
  
  struct vm_entry *vm_e = (struct vm_entry *)malloc(sizeof(struct vm_entry));
  if(!vm_e)
    return false;
 // void *kaddr = palloc_get_page(PAL_USER | PAL_ZERO);
 
  //vm_e 멤버 설정
  vm_e->vaddr = ((uint8_t*)PHYS_BASE) - PGSIZE;
  vm_e->writable = true;
  vm_e->type =  VM_BIN;
  vm_e->is_loaded = true;
  insert_vme(&thread_current()->vm, vm_e);

  /*if(!install_page(vm_e->vaddr, kaddr,vm_e->writable)){
    palloc_free_page(kaddr);
  return success;
  }*/


  return success;
}

/* Adds a mapping from user virtual address UPAGE to kernel
   virtual address KPAGE to the page table.
   If WRITABLE is true, the user process may modify the page;
   otherwise, it is read-only.
   UPAGE must not already be mapped.
   KPAGE should probably be a page obtained from the user pool
   with palloc_get_page().
   Returns true on success, false if UPAGE is already mapped or
   if memory allocation fails. */
static bool
install_page (void *upage, void *kpage, bool writable)
{
  struct thread *t = thread_current ();

  /* Verify that there's not already a page at that virtual
     address, then map our page there. */
  return (pagedir_get_page (t->pagedir, upage) == NULL
          && pagedir_set_page (t->pagedir, upage, kpage, writable));
}

void argument_stack(char **parse, int count, void **esp){
  int i,j;
  char **argv_address = palloc_get_page(0);
  uint8_t word_align = 0;

  //유저스택에 인자저장, 프로그램이름 및 인자 저장
  for(i=count-1; i>-1; i--){
    for(j=strlen(parse[i]); j >-1; j--){
      *esp = *esp-1;
      **(char **)esp = parse[i][j];
    }
    argv_address[i] = *esp;
  }

  /*4byte word-align*/
  while( (uint32_t)(*esp)%4 != 0 ){
    *esp = *esp-1;
    **(uint8_t**)esp = word_align;
  }

  *esp = *esp-4;
  **(uint32_t **)esp = 0;
  //프로그램 이름 및 인자를 가리키는 주소 저장
  for(i=count-1; i>-1 ;i--){
    *esp = *esp-4;
    **(uint32_t **)esp = (uint32_t)argv_address[i];
  }    
  //argv 문자열을 가리키는 주소들의 배열을 가리킴
  *esp = *esp-4;
  **(uint32_t **)esp = (uint32_t)*esp+4;
  //argc 문자열의 개수저장
  *esp = *esp-4;
  **(uint32_t **)esp = count;

  //fake address(0) 
  *esp = *esp-4;
  **(uint32_t **)esp = 0;

  //argv_address free
  palloc_free_page(argv_address);

}

struct thread *get_child_process(int pid){
  //현재 프로세스의 디스크립터를 반환
  struct thread *t = thread_current();
  struct list_elem *elem = list_begin(&t->child_list);
  struct list_elem *next = list_begin( &t->child_list);
  
  //자식 리스트 탐색
  while( elem != list_end(&t->child_list)){
    next = list_next(elem);
    //존재하는 프로세스 디스크립터를 가져옴
	struct thread *cp = list_entry( elem, struct thread, child_elem);
    if( pid == cp-> tid){
	 return cp;
	}
	elem = next;
	}

  return NULL;
}

void remove_child_process(struct thread *cp){
  //현재 프로세스의 자식 리스트에서 인자값으로온 스레드 삭제
  list_remove(&cp->child_elem);
  //자식 프로세스 메모리 해제
  palloc_free_page(cp);
}

struct file *process_get_file( int fd)
{
    //현제 프로세스의 디스크립터를 가져옴
    struct thread *thread  = thread_current();
    //예외 처리 후 파일 디스크립터에 테이블에서 해당 fd값의 파일 객체 반환
	if( fd < 2 || fd >= thread->next_fd || thread -> ftd[fd] == NULL){
		return NULL;
	 }
    else
	  return thread->ftd[fd];
}

void process_close_file( int fd)
{  
  // 현재 프로세스 디스크립터를 가져옴
  struct thread* t = thread_current();
  // fd 값에 해당하는 파일 객체를 이용해서 파일을 닫음
  if( t -> ftd[fd] != NULL){
    file_close( t-> ftd[fd] );       
  }
  //초기화   
  t-> ftd[fd] = NULL;				
}

int process_add_file( struct file *f){
  ///현재 프로세스 디스크립터를 가져옴   
  struct thread* t = thread_current();
  if (f == NULL){//예외처리
    printf("file open add file NULL\n");
    return -1;
  }
  //파일 객체에 대한 파일 디스크립터 할당 next_fd이동
  int fd = t-> next_fd;
  t->ftd[fd] = f;
  t->next_fd++;
  return fd;
}

bool handle_mm_fault(struct vm_entry *vme){
  
  bool success = false;
  //이미 적재 되어있으면 success반환
  if(vme->is_loaded)
    return success;
  //물리 메모리 할당
  void *kaddr = palloc_get_page(PAL_USER);
  if(kaddr == NULL)
      return false;
  //vm_entry의 type별 처리
  switch(vme->type){
    case VM_BIN:      //load_file함수를 이용해서 물리 메모리에 로드
      success = load_file(kaddr, vme);
      break;
    case VM_FILE:
		success = load_file( kaddr, vme);
      break;
    case VM_ANON:
      break;
  }
  if(success == false){  //VM_BIN이 아닌경우, 로드를 못한경우 할당해제
    palloc_free_page(kaddr);
    return false;
  }
  //물리메모리의 페이지와 가상메모리의 페이지 맵핑
  if(install_page(vme->vaddr, kaddr, vme->writable)==false){
    palloc_free_page(kaddr);
    return false;
  }
  vme->is_loaded = true;      //로드 성공
  return true;
}



