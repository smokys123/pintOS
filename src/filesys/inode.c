#include "filesys/inode.h"
#include <list.h>
#include <debug.h>
#include <round.h>
#include <string.h>
#include "filesys/filesys.h"
#include "filesys/free-map.h"
#include "threads/malloc.h"
#include "filesys/buffer_cache.h"

/* Identifies an inode. */
#define INODE_MAGIC 0x494e4f44
#define INDIRECT_BLOCK_ENTRIES (BLOCK_SECTOR_SIZE / sizeof( block_sector_t))
#define DIRECT_BLOCK_ENTRIES 124   //direct방식으로 저장할 블록의 개수

//inode가 block을 저장하는 방식
enum direct_t{  
	NORMAL_DIRECT,    //direct
	INDIRECT,         //indirect
	DOUBLE_INDIRECT,  //double indirect
	OUT_LIMIT         //error
};
//블록 주소 접근 방식, 인덱스 블록내의 오프셋 저장하는 구조체
struct sector_location{
	int directness;    //디스크 블록 접근 방식
	int index1;        //첫번째 index블록에서 접근할 offset
	int index2;        //두번째 index블록에서 접근할 offset
};
//index블록을 표현하는 구조체
struct inode_indirect_block{
	block_sector_t map_table[INDIRECT_BLOCK_ENTRIES];
};

/* On-disk inode.
   Must be exactly BLOCK_SECTOR_SIZE bytes long. */
struct inode_disk
  {
    off_t length;                       /* File size in bytes. */
    unsigned magic;                     /* Magic number. */
	block_sector_t direct_map_table[DIRECT_BLOCK_ENTRIES];    //direct방식으로 접근할 디스크 블록의 번호 전장됨
	block_sector_t indirect_block_sec;        //indirect방식으로 접근할 인덱스 블록 번호 저장됨
	block_sector_t double_indirect_block_sec;  //double indirect방식으로 접근할 경우 1차 인덱스블록의 번호 저장됨
  };

/* Returns the number of sectors to allocate for an inode SIZE
   bytes long. */
/*static inline size_t
bytes_to_sectors(off_t size)
{
  return DIV_ROUND_UP (size, BLOCK_SECTOR_SIZE);
}*/

/* In-memory inode. */
struct inode 
  {
    struct list_elem elem;              /* Element in inode list. */
    block_sector_t sector;              /* Sector number of disk location. */
    int open_cnt;                       /* Number of openers. */
    bool removed;                       /* True if deleted, false otherwise. */
    int deny_write_cnt;                 /* 0: writes ok, >0: deny writes. */
    //struct inode_disk data;             /* Inode content. */
	struct lock extend_lock;
    
  };

static void  locate_byte( off_t pos, struct sector_location *sec_loc);
static bool register_sector(struct inode_disk *inode_disk, block_sector_t new_sector, struct sector_location sec_loc);

static inline size_t
bytes_to_sectors(off_t size)
{	
	return DIV_ROUND_UP ( size, BLOCK_SECTOR_SIZE);
}
/* Returns the block device sector that contains byte offset POS
   within INODE.
   Returns -1 if INODE does not contain data for a byte at offset
   POS. */
//파일 오프셋으로 ondisk inode를 검색하여 디스크 블록 번호를 반환하는 함수
static block_sector_t
byte_to_sector (const struct inode_disk *inode_disk, off_t pos) 
{
  block_sector_t result_sec=-1;    //결과를 반환할  sector번호	 
  block_sector_t *ind_block = ( block_sector_t *)malloc(BLOCK_SECTOR_SIZE);
  if(!ind_block) 
    return -1;

  if( pos < inode_disk -> length ){
	struct sector_location sec_loc;   
	locate_byte( pos, &sec_loc);    //인덱스 블록 offset계산
    
	switch( sec_loc.directness){
	  case NORMAL_DIRECT:   //direct 방식인경우
        //ondisk inode의 direct_map_table에서 디스크 블록 번호를 얻음
		result_sec = inode_disk -> direct_map_table[sec_loc.index1];
		free(ind_block);
		break;
	  case INDIRECT:  //indirect 방식인 경우
        //buffer cache에서 인덱스 블록을 읽어서 가져옴
		bc_read( inode_disk-> indirect_block_sec, (void*)ind_block, 0, BLOCK_SECTOR_SIZE,0);
		result_sec = ind_block[ sec_loc.index1];	//인덱스 블록에서 디스크 블록 번호 확인	
		free(ind_block);
		break;
	  case DOUBLE_INDIRECT:   //double indirect 방식인경우
        //1차 2차 인덱스 블록을 buffer cache 에서 읽음
		bc_read( inode_disk->double_indirect_block_sec, (void*)ind_block,0, BLOCK_SECTOR_SIZE,0);
		block_sector_t sector_idx = ind_block[sec_loc.index1];
		bc_read( sector_idx,(void*)ind_block, 0, BLOCK_SECTOR_SIZE, 0);
		result_sec = ind_block[sec_loc.index2];	  //인덱스 블록에서 디스크 블록 번호 읽음
		free(ind_block);
		break;
	  default:
		free(ind_block);
		return result_sec;
	}
  }
  return result_sec;
}
/* List of open inodes, so that opening a single inode twice
   returns the same `struct inode'. */
static struct list open_inodes;

/* Initializes the inode module. */
//inode 를 버퍼캐시로 부터 읽어서 전달하는 함수
static bool get_disk_inode( const struct inode *inode, struct inode_disk *inode_disk){
   //sector에 해당하는 ondisk inode를  buffer cache에서 읽어 inode_disk에 저장함
	return bc_read( inode->sector, (void*)inode_disk, 0, BLOCK_SECTOR_SIZE, 0 );
   
}
//디스크 블록 접근방법, offset을 확인하는 함수
static void locate_byte( off_t pos, struct sector_location *sec_loc){
	//direct, indirect,double indirct 인지 확인
    off_t pos_sector = (pos / BLOCK_SECTOR_SIZE);
    //direct방식인경우
	if( pos_sector < DIRECT_BLOCK_ENTRIES){
	    //sec_loc 자료구조의 변수 값 업데이트
		sec_loc -> directness = NORMAL_DIRECT;
		sec_loc -> index1 = pos_sector;
	} //indirect방식인경우
	else if( pos_sector < (off_t)(DIRECT_BLOCK_ENTRIES + INDIRECT_BLOCK_ENTRIES) ){
		//sec_loc자료구조의 변수 값 업데이트
        sec_loc -> directness = INDIRECT;
		sec_loc -> index1 = pos_sector - DIRECT_BLOCK_ENTRIES;
	}//double indirect방식인경우
	else if( pos_sector <(off_t) (DIRECT_BLOCK_ENTRIES + INDIRECT_BLOCK_ENTRIES*(INDIRECT_BLOCK_ENTRIES+1))){
    //sec_loc 자료구조 변수 업데이트	
    sec_loc -> directness = DOUBLE_INDIRECT;
	sec_loc -> index1 = (pos_sector - DIRECT_BLOCK_ENTRIES)/INDIRECT_BLOCK_ENTRIES;
	sec_loc -> index2 = (pos_sector - DIRECT_BLOCK_ENTRIES)%INDIRECT_BLOCK_ENTRIES;
	}
	else //error일때 
      sec_loc->directness = OUT_LIMIT;
}
//파일에 할당된 모든 디스크 블록의 할당 해제하는 함수
static void free_inode_sectors (struct inode_disk *inode_disk)
{
  struct inode_indirect_block *index_block1;
  int i, j;
  //double indirect방식으로 할당된 블록해제
  if(inode_disk->double_indirect_block_sec > 0)
  {
    index_block1 = (struct inode_indirect_block *) malloc (BLOCK_SECTOR_SIZE);
    if (index_block1)
    {
    //buffer cache로부터 1차 인데스 디스크번호를 읽음
    bc_read(inode_disk->double_indirect_block_sec,(void*)index_block1, 0, BLOCK_SECTOR_SIZE, 0);
    }
    struct inode_indirect_block *index_block2;
    i = 0;
    //1 차 인덱스 블록을 통해 2차 인덱스 블록 접근하는 부분
    while (index_block1->map_table[i] > 0)
    {
      index_block2 = (struct inode_indirect_block *) malloc (BLOCK_SECTOR_SIZE);
      //버퍼캐시에서 2차 인덱스 블록을 읽음
      bc_read(index_block1->map_table[i],(void*)index_block2, 0, BLOCK_SECTOR_SIZE, 0);
      j = 0;
      //2차 인덱스 블록에 저장된 디스브 블록에 접근함
      while (index_block2->map_table[j] > 0)
      {
        //2차 인덱스 블록 할당 해제
        free_map_release (index_block2->map_table[j], 1);
        j++;
      }
      //1차 인덱스 블록 할당 해제
      free_map_release (index_block1->map_table[i], 1);
      i++;
      free(index_block2); 
    }
    //double_indirect 섹터 할당 해제
    free_map_release (inode_disk->double_indirect_block_sec, 1);
    free(index_block1);
  }
  //indirect 방식으로 할당된 디스크 섹터인 경우 할당해지 과정
  if(inode_disk->indirect_block_sec > 0)
  {
    index_block1 = (struct inode_indirect_block *) malloc (BLOCK_SECTOR_SIZE);
    if (index_block1)
    {
       //buffer cache에서 인덱스 블록을 읽음
      bc_read(inode_disk->indirect_block_sec, (void*)index_block1, 0, BLOCK_SECTOR_SIZE, 0);
    }
    i = 0;
    //인덱스 블록에 저장된 디스크 블록에 접근한다.
    while(index_block1->map_table[i] > 0)
    {
      //디스크 블록 할당해제
       free_map_release (index_block1->map_table[i], 1);
       i++;
    }
    free_map_release (inode_disk->indirect_block_sec, 1);
    free(index_block1); 
  }
  //direct 방식으로 할당된 디스크 블록 해제
  i = 0;
  while (inode_disk->direct_map_table[i] > 0)
  {
    free_map_release (inode_disk->direct_map_table[i], 1);
    i++;
  }
}

//파일 오프셋이 기존 파일 크기 보다 클경우 새로운 디스크 블록 할당 및 inode 업데이트 하는 함수
static bool inode_update_file_length( struct inode_disk* inode_disk, off_t start_pos, off_t end_pos){
	
	off_t size = (end_pos-start_pos)+1 ;
	off_t offset = start_pos;
	block_sector_t sector_idx;
	int chunk_size=0;
	inode_disk -> length = end_pos +1;
	struct sector_location sec_loc;
	//void *zeros = malloc( BLOCK_SECTOR_SIZE);
	//memset(zeros, 0 , BLOCK_SECTOR_SIZE);
	char *zeros = calloc(BLOCK_SECTOR_SIZE, sizeof(char));
    while( size > 0 ){
	  off_t  sector_ofs = offset % BLOCK_SECTOR_SIZE;   //디스크 블록내 오프셋 계산
	  chunk_size = BLOCK_SECTOR_SIZE - sector_ofs; 
	  if( size < BLOCK_SECTOR_SIZE){	
        if(sector_ofs + size <= BLOCK_SECTOR_SIZE)
		chunk_size = size;
	  } 
      //offset이 0보다 클경우는 이미 할당된 것이므로 동작 하지 않음
	  if( sector_ofs > 0 ){
	  }
	  else{   //아닌 경우 새로운 디스크 블록 할당
		if( free_map_allocate( 1, &sector_idx)){
          //indoe_disk에 새로 할당 받은 디스크 블록 번호 업데이트해줌
		  locate_byte( offset, &sec_loc);
		  register_sector( inode_disk, sector_idx, sec_loc);
	    }
		else{
		  free(zeros);
		  return false;
		}
        //새로운 디스크 블록을 0으로 초기화
		bc_write( sector_idx, zeros, 0, BLOCK_SECTOR_SIZE, 0);
	  }
	  size -= chunk_size;
	  offset += chunk_size;
	}
    free(zeros);
	return true;
}
void
inode_init (void) 
{
  list_init (&open_inodes);
}

/* Initializes an inode with LENGTH bytes of data and
   writes the new inode to sector SECTOR on the file system
   device.
   Returns true if successful.
   Returns false if memory or disk allocation fails. */
bool
inode_create (block_sector_t sector, off_t length)
{
  struct inode_disk *disk_inode = NULL;
  bool success = false;

  ASSERT (length >= 0);

  /* If this assertion fails, the inode structure is not exactly
     one sector in size, and you should fix that. */

 ASSERT (sizeof *disk_inode == BLOCK_SECTOR_SIZE);

  disk_inode = calloc (1, sizeof *disk_inode);
  if (disk_inode != NULL)
    {
      disk_inode->length = length;
      disk_inode->magic = INODE_MAGIC;
	  if( length > 0 ){
          //length만큼 디스크 블록을 inode_update_file_length()를 호출하여 할당
  		  inode_update_file_length( disk_inode, 0, (length-1));
		}
        //ondisk inode를 buffer cache에 기록
		if( bc_write( sector, (void*)disk_inode, 0, BLOCK_SECTOR_SIZE, 0))
            success = true;  //success 변수 update
    }
    //disk_inode 할당해제
	free(disk_inode);
  return success;
}

/* Reads an inode from SECTOR
   and returns a `struct inode' that contains it.
   Returns a null pointer if memory allocation fails. */
struct inode *
inode_open (block_sector_t sector)
{
  struct list_elem *e;
  struct inode *inode;

  /* Check whether this inode is already open. */
  for (e = list_begin (&open_inodes); e != list_end (&open_inodes);
       e = list_next (e)) 
    {
      inode = list_entry (e, struct inode, elem);
      if (inode->sector == sector) 
        {
          inode_reopen (inode);
          return inode; 
        }
    }

  /* Allocate memory. */
  inode = malloc (sizeof *inode);
  if (inode == NULL)
    return NULL;

  /* Initialize. */
  list_push_front (&open_inodes, &inode->elem);
  inode->sector = sector;
  inode->open_cnt = 1;
  inode->deny_write_cnt = 0;
  inode->removed = false;
  lock_init( &inode->extend_lock);
 // block_read (fs_device, inode->sector, &inode->data);
  return inode;
}

/* Reopens and returns INODE. */
struct inode *
inode_reopen (struct inode *inode)
{
  if (inode != NULL)
    inode->open_cnt++;
  return inode;
}

/* Returns INODE's inode number. */
block_sector_t
inode_get_inumber (const struct inode *inode)
{
  return inode->sector;
}

/* Closes INODE and writes it to disk.
   If this was the last reference to INODE, frees its memory.
   If INODE was also a removed inode, frees its blocks. */
void
inode_close (struct inode *inode) 
{
  /* Ignore null pointer. */
  if (inode == NULL)
    return;

  /* Release resources if this was the last opener. */
  if (--inode->open_cnt == 0)
    {
      /* Remove from inode list and release lock. */
      list_remove (&inode->elem);
 
      /* Deallocate blocks if removed. */
      if (inode->removed) { 
          //struct inode_disk *disk_inode = (struct inode_disk *)malloc(BLOCK_SECTOR_SIZE);
		  struct inode_disk disk_inode;
          //버퍼캐시에서 ondisk indoe획득
          get_disk_inode( inode, &disk_inode);
		  free_inode_sectors(&disk_inode);   //디스크 블록 반환
          free_map_release (inode->sector, 1);   //ondisk inode 반환
          //free(disk_inode);
		}
      free (inode); 
    }
}

/* Marks INODE to be deleted when it is closed by the last caller who
   has it open. */
void
inode_remove (struct inode *inode) 
{
  ASSERT (inode != NULL);
  inode->removed = true;
}

/* Reads SIZE bytes from INODE into BUFFER, starting at position OFFSET.
   Returns the number of bytes actually read, which may be less
   than SIZE if an error occurs or end of file is reached. */
off_t
inode_read_at (struct inode *inode, void *buffer_, off_t size, off_t offset) 
{
  uint8_t *buffer = buffer_;
  off_t bytes_read = 0;
  off_t length;
  //uint8_t *bounce = NULL;
  //inode disk 자료형의 disk_inode 변수를 동적할당
  struct inode_disk *disk_inode = (struct inode_disk*)malloc( BLOCK_SECTOR_SIZE);
  get_disk_inode( inode, disk_inode);    //버퍼 캐시에서 ondisk indoe를 읽어옴
  length = disk_inode->length;

  while (size > 0) 
    {
      block_sector_t sector_idx = byte_to_sector (disk_inode, offset);
      int sector_ofs = offset % BLOCK_SECTOR_SIZE;

      /* Bytes left in inode, bytes left in sector, lesser of the two. */
      off_t inode_left = inode_length (inode) - offset;
      int sector_left = BLOCK_SECTOR_SIZE - sector_ofs;
      int min_left = inode_left < sector_left ? inode_left : sector_left;

      /* Number of bytes to actually copy out of this sector. */
      int chunk_size = size < min_left ? size : min_left;
      if (chunk_size <= 0)
        break;
		    bc_read( sector_idx, (void*)buffer, bytes_read, chunk_size, sector_ofs);
      /* Advance. */
      size -= chunk_size;
      offset += chunk_size;
      bytes_read += chunk_size;
    }
	bc_write( inode->sector, (void*)disk_inode, 0, BLOCK_SECTOR_SIZE,0);
 // free (bounce);
  free(disk_inode);
  return bytes_read;
}

/* Writes SIZE bytes from BUFFER into INODE, starting at OFFSET.
   Returns the number of bytes actually written, which may be
   less than SIZE if end of file is reached or an error occurs.
   (Normally a write at end of file would extend the inode, but
   growth is not yet implemented.) */
off_t
inode_write_at (struct inode *inode, const void *buffer_, off_t size,
                off_t offset) 
{
  const uint8_t *buffer = buffer_;
  off_t bytes_written = 0;
 // uint8_t *bounce = NULL;
  struct inode_disk disk_inode;
	disk_inode.length = 0 ;
  
  if (inode->deny_write_cnt)
    return 0;
    //버퍼캐시에서 ondisk inode를 읽어옴
   get_disk_inode( inode, &disk_inode);
   lock_acquire( &inode-> extend_lock);  //락 획득
   int old_length = disk_inode.length;
   int write_end = offset + size -1;
   if( write_end > old_length -1 ){  //파일의 길이가 증가 했을 경우 ondisk inode업데이트
	   inode_update_file_length( &disk_inode, old_length, write_end);
		bc_write( inode->sector, (void*)&disk_inode, 0, BLOCK_SECTOR_SIZE, 0);
	//	old_length = disk_inode.length;
	}
	lock_release( &inode-> extend_lock);  //락해제
  while (size > 0) 
    {
   // lock_acquire(&inode->extend_lock);
      /* Sector to write, starting byte offset within sector. */
      block_sector_t sector_idx = byte_to_sector (&disk_inode, offset);
      int sector_ofs = offset % BLOCK_SECTOR_SIZE;

      /* Bytes left in inode, bytes left in sector, lesser of the two. */
      off_t inode_left = inode_length (inode) - offset;
      int sector_left = BLOCK_SECTOR_SIZE - sector_ofs;
      int min_left = inode_left < sector_left ? inode_left : sector_left;

      /* Number of bytes to actually write into this sector. */
      int chunk_size = size < min_left ? size : min_left;
      if (chunk_size <= 0)
        break;

          /* If the sector contains data before or after the chunk
             we're writing, then we need to read in the sector
             first.  Otherwise we start with a sector of all zeros. */
			bc_write( sector_idx, (void*)buffer, bytes_written, chunk_size, sector_ofs);
     //       lock_release(&inode->extend_lock);
      /* Advance. */
      size -= chunk_size;
      offset += chunk_size;
      bytes_written += chunk_size;
    }
	//bc_write( sector_idx, buffer, bytes_written, chunk_size, sector_ofs);
  //free (bounce);
  return bytes_written;
}

/* Disables writes to INODE.
   May be called at most once per inode opener. */
void
inode_deny_write (struct inode *inode) 
{
  inode->deny_write_cnt++;
  ASSERT (inode->deny_write_cnt <= inode->open_cnt);
}

/* Re-enables writes to INODE.
   Must be called once by each inode opener who has called
   inode_deny_write() on the inode, before closing the inode. */
void
inode_allow_write (struct inode *inode) 
{
  ASSERT (inode->deny_write_cnt > 0);
  ASSERT (inode->deny_write_cnt <= inode->open_cnt);
  inode->deny_write_cnt--;
}

/* Returns the length, in bytes, of INODE's data. */
off_t
inode_length (const struct inode *inode)
{ 
  struct inode_disk inode_disk;
  bc_read( inode-> sector, &inode_disk, 0, BLOCK_SECTOR_SIZE, 0);
  return inode_disk.length;
}
/*
static bool get_disk_inode( const struct inode *inode, struct inode_disk *inode_disk){
   
	return bc_read( inode->sector, inode_disk, 0, sizeof( struct inode_disk ), 0 );
   
}*/

/*static inline off_t map_table_offset( int index){
		
}*/

//새로 할당 받은 디스크 블록의 번호를 inode_disk에 업데이트
static bool register_sector( struct inode_disk *inode_disk, block_sector_t new_sector, struct sector_location sec_loc){

	block_sector_t sector_index;
	block_sector_t sector_index2;
	struct inode_indirect_block id1, id2;
	//접근방식에 따라 inode_disk업데이트하는 방식 갈림
    switch( sec_loc.directness){
      case NORMAL_DIRECT:   //direct인경우
		inode_disk -> direct_map_table[sec_loc.index1] = new_sector;   //inode_disk에 새로 할당 받은 디스크번호 업데이트
		break;
	  case INDIRECT:   //indirect인 경우
        //indriect_block_sec를 확인해서 처음 사용시 만들어줘야함
		if( inode_disk->indirect_block_sec  == 0){
		  if( free_map_allocate( 1, &sector_index))    //indirect 인덱스 블리가 할당
			inode_disk -> indirect_block_sec = sector_index;    //섹터번호에 저장
		  else
			return false;
		}
        //index 블럭의 값을  읽고 ondisk inode에 저장
		bc_read(inode_disk->indirect_block_sec, &id1, 0, BLOCK_SECTOR_SIZE,0);
		id1.map_table[sec_loc.index1] = new_sector;
		bc_write( inode_disk->indirect_block_sec, (void*)&id1, 0,BLOCK_SECTOR_SIZE,0);
	    break;
	  case DOUBLE_INDIRECT:  //double indirect인 경우
        //double indirect_sec를 확인해서 처음 사용시 만들어줌
		if( inode_disk->double_indirect_block_sec== 0){
		   if( free_map_allocate( 1, &sector_index) ==false)   //index블락 할당
			  inode_disk-> double_indirect_block_sec = sector_index;   //double indirect 섹터에 저장
		   else
			 return false;
		}
        //첫번째 index값을 읽어들음
		bc_read( inode_disk->double_indirect_block_sec, (void*)&id2, 0,BLOCK_SECTOR_SIZE,0);
        //indriect_block_sec를 확인해서 처음 사용시 만들어줘야함
        if( id1.map_table[sec_loc.index1] == 0 ){
		  id1.map_table[sec_loc.index1] = sector_index2;
		  bc_write( sector_index2, (void*)&id1, 0, BLOCK_SECTOR_SIZE, 0 );
		}
		else 
		  return false;
        // 두번째 index값을 읽고 디스크 저장
	    bc_read( id1.map_table[sec_loc.index1], &id2, 0, BLOCK_SECTOR_SIZE, 0);
		id2.map_table[sec_loc.index2] = new_sector;
		bc_write( id1.map_table[sec_loc.index1], &id2, 0, BLOCK_SECTOR_SIZE, 0 );			
		break;
	  default:
		return false;
	}
	return true;
}
