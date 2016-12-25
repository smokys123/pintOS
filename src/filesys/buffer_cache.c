#include "threads/malloc.h"
#include "devices/block.h"
#include "filesys/buffer_cache.h"
#include <string.h>
#include "filesys/filesys.h"

#define BUFFER_CACHE_ENTRY_NB 64  //buffer cache 의 entry의 개수

void *p_buffer_cache;      //버퍼 캐시를 가리키는 포인터
struct buffer_head bufferhead[BUFFER_CACHE_ENTRY_NB];  //buffer head설정
int clock_hand;     //victim설정하는데 쓰는 clock 알고리즘의 시계바늘

//버퍼 캐시영역 할당 및 head자료구조 초기화하는 함수
void bc_init(void){
    int i; 
	p_buffer_cache = malloc( BUFFER_CACHE_ENTRY_NB*512);
	clock_hand = 0 ;
    //buffer head 자료구조 초기화
	for( i = 0 ; i < BUFFER_CACHE_ENTRY_NB ; i++){
		bufferhead[i].f_dirty = false;
		bufferhead[i].f_used = false;
		bufferhead[i].sector = -1;
		bufferhead[i].clock = false;
		bufferhead[i].data = p_buffer_cache + (BLOCK_SECTOR_SIZE * i);
		lock_init(&bufferhead[i].buf_lock);
	}
}

//buffer_head를 돌며 디스크 블록의 캐싱여부 검사하는 함수
struct buffer_head *bc_lookup( block_sector_t sector){
	int i;
    //buffer_head를 돌며 sector 값과 동일한 sector를 가지는 entry가 있는 지 확인
	for ( i  = 0 ; i < BUFFER_CACHE_ENTRY_NB ; i++){
 	  if( bufferhead[i].sector == sector&& bufferhead[i].f_used == true){
        return &bufferhead[i];
	  }
    }
	return NULL;
}

//버퍼 캐시 데이터를 디스크로  flush하는 함수
void bc_flush_entry( struct buffer_head* p_flush_entry){
  //락잠금 
  lock_acquire( &p_flush_entry->buf_lock);
  //인자로 전달 받은 buffer cache entry의 데이터를 디스크로 flush
  block_write( fs_device , p_flush_entry->sector,p_flush_entry->data);
  p_flush_entry->f_dirty = false;    //buffer head의 dirty값 설정
  lock_release(&p_flush_entry->buf_lock);
}

//버퍼 캐시를 돌며 dirty인 entry의 데이터를 디스크로 flush 하는 함수
void bc_flush_all_entries( void){
	int i ;
    //buffer head를 돌며 dirty인 entry를 디스크로 flush
	for( i = 0 ; i < BUFFER_CACHE_ENTRY_NB ; i++){
		if( bufferhead[i].sector != -1 && bufferhead[i].f_dirty == true )
			bc_flush_entry( &bufferhead[i]);
	}
}
//버퍼 캐시에 캐싱된 데이터를 디스크 블록으로 flush하는 함수
void bc_term(void){
    //모든 buffer cache entry를 디스크로 flush
	bc_flush_all_entries();  
	free( p_buffer_cache);  //buffer cache영역 할당해제
}

//clock 알고리즘을 통해 버퍼캐시에서 victim 선정 하는 함수
struct buffer_head *bc_select_victim(void){
  //victim 선정 clock 알고리즘 이용
  while(1){
    if(bufferhead[clock_hand].f_used == false)
	  return &bufferhead[clock_hand];
    if(bufferhead[clock_hand].clock == 1)		
	  bufferhead[clock_hand].clock = 0 ;
    else
      break;
    clock_hand = (clock_hand+1)% BUFFER_CACHE_ENTRY_NB;
  }
  //선택된 victim의 dirty일경우 디스크로 flush
  if( bufferhead[clock_hand].f_dirty == true){
	bc_flush_entry(&bufferhead[clock_hand]);
  }
  //victim의 buffer_head 데이터 설정
  bufferhead[clock_hand].f_used = false;
  bufferhead[clock_hand].f_dirty = false;
  return &bufferhead[clock_hand]; 
}

//buffer cache,디스크 에서 데이터를 읽어 유저 buffer 캐시에 저장하는 함수
bool bc_read( block_sector_t sector_idx, void *buffer, off_t bytes_read, int chunk_size, int sector_ofs){
  //sector_idx를 buffer_head에서 검색
  struct buffer_head *buffer_list = bc_lookup( sector_idx);
  //버퍼에 없을경우 디스크 블록을 캐싱할 buffer_entry의 buffer_head를 구함
  if( buffer_list == NULL){
	buffer_list = bc_select_victim();
	buffer_list-> sector = sector_idx;
	buffer_list->f_used = true;
	buffer_list->f_dirty= false;
    //디스크 블록 데이터를 buffer cache로 읽어옴
    block_read( fs_device, sector_idx, buffer_list->data);
  }
  //memcpy 함수를 통해 buffer에 디스크 블록 데이터를 복사
  memcpy( buffer + bytes_read, buffer_list->data + sector_ofs, chunk_size);
  buffer_list->clock = 1;    //buffer_head의 clock bit를 설정
  return true;
}

//buffer의 데이터를 buffer cache에 기록하는 함수
bool bc_write( block_sector_t sector_idx, void *buffer, off_t bytes_written, int chunk_size, int sector_ofs){
    //sector_idx를 buffer_head에서 검색하여 buffer에 복사
	struct buffer_head *buffer_list = bc_lookup( sector_idx);
    //buffer cache 에 빈 엔트리가 없으면 victim을 선정해서 디스크에 기록
	if( buffer_list == NULL){
     	buffer_list = bc_select_victim();
		buffer_list -> sector = sector_idx;
		buffer_list->f_used = true;
		buffer_list->f_dirty = false;
        block_read( fs_device, sector_idx, buffer_list->data);
	}
    //버퍼의 데이터를 buffer cache에 복사
	memcpy( buffer_list -> data + sector_ofs, buffer + bytes_written, chunk_size);
    //buffer_head  갱신
	buffer_list->f_dirty = true;
	buffer_list->clock = true;

	return true;
}




