#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"

/*load_flag define*/
#define NO_LOAD 0
#define SUCCESS_LOAD 1
#define FAIL_LOAD 2

tid_t process_execute (const char *file_name);
int process_wait (tid_t);
void process_exit (void);
void process_activate (void);
void argument_stack(char **parse, int count, void **esp);
struct thread *get_child_process(int pid);
void remove_child_process(struct thread *cp);
int process_wait(tid_t child_tid UNUSED);
void process_close_file(int fd);
struct file *process_get_file(int fd);
int process_add_file(struct file *f);

#endif /* userprog/process.h */
