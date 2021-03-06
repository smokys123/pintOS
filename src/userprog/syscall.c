#include "userprog/syscall.h"
#include "userprog/process.h"
#include <string.h>
#include "threads/synch.h"
#include <stdio.h>
#include <list.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "devices/shutdown.h"
#include <devices/input.h>
#include "threads/thread.h"
#include <filesys/filesys.h>
#include <filesys/file.h>
#include <stdint.h>
#include <stdio.h>

static void syscall_handler (struct intr_frame *);
void get_argument(void *esp, int *arg, int count);
void check_address(void *addr);
void shutdown_power_off(void);
void thread_exit(void);
bool filesys_create(const char *name, off_t initial_size);
bool filesys_remove(const char *name);
void halt(void);
void exit(int status);
bool create(const char *file, unsigned initial_size);
bool remove(const char *file);
tid_t exec(const char *cmd_line);
int wait(tid_t tid);
int open( const char *file);
int filesize( int fd);
int read( int fd, void *buffer, unsigned size);
int write( int fd, void *buffer, unsigned size);
void seek( int fd, unsigned position);
unsigned tell(int fd);
void close( int fd);

void syscall_init (void) 
{ 
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
  /*initialize lock*/
  lock_init( &filesys_lock);
}

static void syscall_handler (struct intr_frame *f UNUSED) 
{
  int arg[3];
  //유저의 포인터 가져오고 주소확인,syscall num을 저장
  uint32_t *esp = f->esp;
  check_address(esp);
  int syscall_num = *esp;

  //해당 시스콜 넘버에 해당하는 시스템 콜 호출
  switch(syscall_num){
  
	case SYS_HALT:
	  halt();
	  break;
    
	case SYS_EXIT:
	  //스택에 존재하는 인자값을 arg에저장
      get_argument(esp, arg, 1);
      //exit 함수 호출
	  exit((int)arg[0]);
	  break;
    
	case SYS_EXEC:
      //스택에 존재하는 인자값을 arg에저장
      get_argument(esp, arg, 1);
      //exec의 리턴값을 eax 레지스터에 저장
	  f->eax = exec((const char*)arg[0]);
	  break;

	case SYS_WAIT:
      //스택에 존재하는 인자값을 arg에저장
      get_argument(esp, arg, 1);
      //wait의 리턴 값을 eax 레지스터에 저장
      f->eax = wait((int)arg[0]);
      break;

	case SYS_CREATE:
      //스택에 존재하는 인자값을 arg에저장
	  get_argument(esp, arg, 2);
      check_address((void *)arg[0]);
      //create의 리턴 값을 eax 레지스터에 저장
	  f->eax = create((const char*)arg[0], (unsigned)arg[1]);
      break;

	case SYS_REMOVE:
      //스택에 존재하는 인자값을 arg에저장
      get_argument(esp, arg, 1);
      check_address((void *)arg[0]);
      //remove의 리턴 값을 eax 레지스터에 저장
	  f->eax = remove( (const char*)arg[0] );
      break;
    
	case SYS_OPEN:
      //스택에 존재하는 인자값을 arg에저장
	  get_argument(esp, arg, 1);
	  check_address( (void*)arg[0]);
      //open의 리턴 값을 eax 레지스터에 저장
	  f->eax = open( (const char*)arg[0]);
	break;

	case SYS_FILESIZE:
      //스택에 존재하는 인자값을 arg에저장
	  get_argument(esp, arg, 1);
      //filesize의 리턴 값을 eax 레지스터에 저장
	  f->eax = filesize( (int)arg[0]);
	break;

	case SYS_READ:
      //스택에 존재하는 인자값을 arg에저장
	  get_argument(esp, arg, 3);
	  check_address( (void*)arg[1]);
      //read의 리턴 값을 eax 레지스터에 저장
	  f->eax = read( (int)arg[0], (char*)arg[1], (unsigned)arg[2]);
	break;

	case SYS_WRITE:
      //스택에 존재하는 인자값을 arg에저장
	  get_argument( esp, arg, 3);
	  check_address( (void*)arg[1]);
      //write의 리턴 값을 eax 레지스터에 저장
	  f->eax = write( (int)arg[0], (char*)arg[1], (unsigned)arg[2]);
	break;
	
	case SYS_SEEK:
      //스택에 존재하는 인자값을 arg에저장
	  get_argument( esp, arg, 2);
	  seek( (int)arg[0], (unsigned)arg[1]);
	break;

	case SYS_TELL:
      //스택에 존재하는 인자값을 arg에저장
	  get_argument( esp, arg, 1);
      //tell의 리턴 값을 eax 레지스터에 저장
	  f->eax = tell( (int)arg[0]);
	break;

	case SYS_CLOSE:
      //스택에 존재하는 인자값을 arg에저장
	  get_argument( esp, arg, 1);
	  close( (int)arg[0]);
	break;    

  //  default:
      //printf("Error sycall!");


   }
} 

void get_argument(void *esp, int *arg, int count){
  int i;
  int *ptr;
  //esp에서 주소값을 증가 시키면서 인자값을 arg에 저장
  for(i=0; i<count;i++){
    ptr = (int *)esp + i+1;
	check_address((void*)ptr);
	arg[i] = *ptr;
  }
}

void check_address(void *addr){
    
	//유저 메모리역역이 아니면 프로그램 종료
	if((uint32_t)addr <= (uint32_t)0x8048000 || (uint32_t)addr >= (uint32_t) 0xc0000000){
         exit(-1);
	}
}

void halt(void){
    //pintos 종료
	printf("system halt\n");
	shutdown_power_off();
}

void exit(int status){
  //현재 프로세스의 디스크립터를를 받아옴
  struct thread *cur = thread_current();
  //프로세스의 종료 status저장
  cur->exit_status = status;
  printf("%s: exit(%d)\n", cur->name, status);
  //프로세스 종료
  thread_exit();
}

bool create(const char *file, unsigned initial_size){
  if( file==NULL)
      return -1;
  bool success = false;
  check_address( (void*)file);
  //파일 이름과 크기에 해당하는 파일 생성
  success = filesys_create(file,initial_size);
  //파일 생성 성공시 true 실패시 false
  return success;
}

bool remove(const char *file){
  check_address( (void*)file);
  bool success = false;
  //파일 이름에 해당하는 파일을 제거
  success = filesys_remove(file);
  //파일 제거 성공시 true 실패시 false
  return success;
}

tid_t exec(const char *cmd_line){
    //예외 처리
  if( cmd_line== NULL){
	  return -1;
  }
  check_address( (void*)cmd_line);
  //process_execute()함수를 호출해서 자식 프로세스 생성
  tid_t tid = process_execute(cmd_line);
  //생성된 자식 프로세스의 프로세스 디스크립터 검색
  struct thread *child_process = get_child_process(tid);
  if(child_process == NULL){
    return -1;
  }
  //자식프로세스의 프로그램이 load될때 까지 wait
    sema_down(&child_process->sema_load);
  
  //load  실패시 -1 리턴
  if(child_process->load_flag == FAIL_LOAD){
    return -1;
  }
    //load 성공시 자식프로세스 pid리턴
    return tid;
}

int wait(tid_t tid){
  //process_wait 실행
  return process_wait(tid);
}

int open( const char *file){
  check_address( ( void*)file);
  if( file == NULL){ //예외처리
	return -1;
  }
  //파일 오픈하기전에 락을 걸어줌
  lock_acquire( &filesys_lock);
  //파일 오픈   
  struct file *opfile = filesys_open(file);
  if( opfile == NULL){
  //해당파일이 존재하지 않을경우 락 해제,리턴 -1  
    lock_release(&filesys_lock);     
	return -1;
  }
  else{ 
   //오픈 성공시 락 해제, process_add_file 실행 
    int fd = process_add_file(opfile);
	lock_release(&filesys_lock);
    return fd;
  }
}

int filesize( int fd){
     //파일 디스크립터에 대한 파일 객체를 가져옴
      struct file *opfile = process_get_file(fd);
      if( opfile == NULL){ //파일이 존재하지 않으면 -1리턴
		  return -1;
	  }
      else{  //해당 파일의 길이를 리턴
          int length = file_length( opfile);
          return length;
      }
}


int read( int fd, void *buffer, unsigned size){
  check_address( buffer);
  int readbyte;
  unsigned i = 0 ; 
  //파일의 동시 접근을 막기위한 락        
  lock_acquire( &filesys_lock);
  //STDOUT일때 예외처리
  if( fd == STDOUT_FILENO){
	lock_release(&filesys_lock);
	return -1;
  } //STDIN일때 input_get를 이용한 키보드 입력을 버퍼에 저장, 저장한크기 리턴 
  if( fd == STDIN_FILENO){
    while (i < size ){
	  ((char*)buffer)[i++] = input_getc();
    }
	lock_release(&filesys_lock);
	return (int)size;   
  }
  //파일 디스크립터를 이용하여 파일 객체검색
  struct file* fp = process_get_file(fd);
  //파일이 없을경우 예외처리           
  if( fp == NULL){
    lock_release( &filesys_lock);
	return -1;
  }
  //파일의 데이터 크기만큼 저장 후 읽은 바이트 수 리턴
  readbyte = file_read( fp ,buffer,size);   
  //file_read 후 락해제
  lock_release(&filesys_lock);
  return readbyte;    
}

int write( int fd, void *buffer, unsigned size){
  check_address( buffer);     
  int writebyte;
  //파일에 동시접근을 막는 락 
  lock_acquire(&filesys_lock);
  //STDIIN일 경우 락 해제,예외처리		 
  if( fd == STDIN_FILENO){
	lock_release(&filesys_lock);
	return -1;
  }//SRDOUT인경우 버퍼에 저장된 값을 화면에 출력, 락 해제
  if( fd == STDOUT_FILENO){    
    putbuf( (const char*) buffer, size);  
	lock_release(&filesys_lock);
	return size;	    
  }
  //파일디스크립터를 이용한 파일 객체 검색
  struct file* fp = process_get_file(fd);
  //파일이  없을경우 락 해제			
  if( fp == NULL){
    lock_release(&filesys_lock);
	return -1;
  }
  //버퍼에 저장된 데이터 크기만큼 파일에 기록, 기록한 바이트 수를 리턴, 락해제
  writebyte = file_write( fp, buffer, size);
  lock_release(&filesys_lock);
  return writebyte;	
}

void seek( int fd, unsigned position){
  //파일 디스크립터를 이용하여 파일 객체 검색   
  struct file *opfile = process_get_file(fd);
  if( opfile == NULL)
    return;
  else{  //해당 열린파일의 offset을 position만큼 이동
	file_seek(opfile, position);
  }
}

unsigned tell(int fd){
  //파일 디스크립터를 이용한 파일객체 검색
  struct file *opfile = process_get_file(fd);
  if( opfile == NULL)  //파일이 존재하지 않을시
    return -1;
  else{  //해당 열린 파일의 위치 반환
    off_t offset = file_tell(opfile);
    return offset;
  }
}

void close( int fd ){
  //processs_close_file 호출  
  process_close_file(fd);    
}















