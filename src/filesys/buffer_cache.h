#ifndef _BUFFER_CACHE_H_
#define _BUFFER_CACHE_H_


#include "filesys/filesys.h"
#include "filesys/inode.h"
#include "threads/synch.h"
//#include "filesys/

	

bool bc_read( block_sector_t sector_idx, void *buffer, off_t bytes_read, int chunk_size, int sector_ofs);
bool bc_write( block_sector_t sector_idx, void *buffer, off_t bytes_written, int chunk_size, int sector_ofs);
struct buffer_head* bc_select_victim(void);
struct buffer_head* bc_lookup(block_sector_t sector);
void bc_flush_entry( struct buffer_head* p_flush_entry);
void bc_flush_all_entries(void);

void bc_term(void); 
void bc_init(void);
struct buffer_head{
		bool f_dirty;
		bool f_used;
		block_sector_t sector;
		bool clock;
		struct lock buf_lock;
		void *data;
};

#endif 
