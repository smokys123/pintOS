#include<hash.h>
#include<list.h>
#include<threads/synch.h>

#define VM_BIN  0
#define VM_FILE 1
#define VM_ANON 2

struct vm_entry{
  uint8_t type;                    //VM_BIN ,VM_FILE, VM_ANON type 저장
  void *vaddr;                     //vm_entry의 가상페이지번호(VPN)
  bool writable;                    //수정 가능한가?를 나타내는것
                                   //true-> write가능 false-> write불가능
  bool is_loaded;                  //해당 vm_entry가 물리 메모리의 탑재여부를 알려주는 플래그
  struct file* file;               //현재 가상주소와 맵핑된 파일
  struct list_elem mmap_elem;      //mmap list element
 
  size_t offset;                   //읽어야할 파일의 오프셋
  size_t read_bytes;               //가상페이지에 쓰여져 있는 데이터 크기
  size_t zero_bytes;               //0으로 채울 남은 페이지 바이트

  size_t swap_slot;                //스왑 슬롯

  struct hash_elem elem;           //hash table의 element
};

struct mmap_file{
	int mapid;       //returned mapping id
	struct file* file;   // mapping file's file object
	struct list_elem elem; //mmap_file list
	struct list vme_list;  // mmap_file vm_entry list
};


void vm_init(struct hash *vm);
struct vm_entry *find_vme(void *vaddr);
bool insert_vme(struct hash *vm, struct vm_entry *vme);
bool delete_vme(struct hash *vm, struct vm_entry *vme);
void vm_destroy(struct hash *vm);
void vm_destroy_func(struct hash_elem *e, void *aux UNUSED);

bool handle_mm_fault(struct vm_entry *vme);

bool load_file(void* kaddr, struct vm_entry *vme);

