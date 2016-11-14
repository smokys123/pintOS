#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include "filesys/file.h"
#include "threads/interrupt.h"
#include "threads/malloc.h"
#include "threads/palloc.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include "userprog/process.h"
#include "userprog/syscall.h"
#include "vm/page.h"
#include "hash.h"


static unsigned vm_hash_func(const struct hash_elem *e, void *aux){
  struct vm_entry *vm_e = hash_entry(e, struct vm_entry, elem);         //hash_entry함수를 이용해서 e에해당하는 vm_entry 구조체 탐색
  return hash_int((int)vm_e->vaddr);                       //vm_entry의 vaddr에 대한 해쉬값 반환
}

static bool vm_less_func(const struct hash_elem *a, const struct hash_elem *b){
  struct vm_entry *vm_a = hash_entry(a, struct vm_entry, elem);        //hash_entry함수를 이용해서 a에 해당하는 vm_entry구조체 탐색
  struct vm_entry *vm_b = hash_entry(b, struct vm_entry, elem);        //hash_entry함수를 이용해서 b에 해당하는 vm_entry구조체 탐색

  if(vm_a->vaddr < vm_b->vaddr)    //vm_entry a와 b를 비교하여 결과 값 리턴
      return true;
  else 
      return false;
}

//vm_entry 해시 테이블을 초기화하는 함수 구현
void vm_init(struct hash* vm){  
  hash_init(vm, vm_hash_func, vm_less_func, NULL);           //hash_init함수를 이용해서 vm_emtry 테이블 초기화
}
//vm_entry에 insert하는 함수
bool insert_vme(struct hash *vm, struct vm_entry *vme){
  
 // struct hash_elem *check_insert = hash_insert(vm, &vme->elem);
 // return true;
  
  if(hash_insert(vm, &vme->elem)==NULL)      //hash_insert함수를 이용해서 vme->elem을 vm_entry 해시 테이블에 삽입
      return true;
  else
      return false;
}

//vm_entry에서 인자 하나를 delete하는 함수
bool delete_vme(struct hash *vm, struct vm_entry *vme){
  if(hash_delete(vm, &vme->elem)==NULL)               //hash_delete함수를 이용해 vme->elem에 해당하는 vm_emtry 제거
    return false;
  else 
    return true;
}

//인자로 받은 vaddr에 해당하는 vm_entry를 검색, 반환하는 함수
struct vm_entry *find_vme(void *vaddr){
 
  struct vm_entry vm_e;
  struct hash_elem *e;
  vm_e.vaddr = pg_round_down(vaddr);                    //pg_round_down으로 vaddr에서 상위 20bit인  페이지 번호를 얻는다 
  e = hash_find(&thread_current()->vm, &vm_e.elem);   //hash_find함수를 vm_e에 해당하는 elem를 찾아낸다
  if(!e)   //존재하진 않을시 NULL리턴
    return NULL;
  //존재하면 hash_entry를 이용해서 vm_entry구조체 리턴
  return hash_entry(e, struct vm_entry, elem);
}

//vm_entry 해시 테이블의 vm_entry제거하는 함수
void vm_destroy(struct hash *vm){
  hash_destroy(vm, vm_destroy_func);    //해시 bucket의 vm에 해당하는 entry를 삭제 해준다
}

//물리 페이지 해제, 페이지 테이블 해제, vm_entry에서 해재하는 함수
void vm_destroy_func(struct hash_elem *e, void *aux UNUSED){
  if(e != NULL){
    struct vm_entry *vm_e = hash_entry(e, struct vm_entry, elem);        //e에 해당하는 vm_entry 검색
    if(vm_e->is_loaded){         
      palloc_free_page(pagedir_get_page(thread_current()->pagedir, vm_e->vaddr));
      pagedir_clear_page(thread_current()->pagedir, vm_e->vaddr);
    }
    free(vm_e);
  }
}

bool load_file(void *kaddr, struct vm_entry *vme){

  if(vme->read_bytes > 0){
    if((int)vme->read_bytes != file_read_at(vme->file, kaddr, vme->read_bytes, vme->offset)){
        palloc_free_page(kaddr);
        return false;
    }
    memset(kaddr + vme -> read_bytes, 0, vme->zero_bytes);
  }
  else
    memset(kaddr, 0, PGSIZE);

  return true;


}
