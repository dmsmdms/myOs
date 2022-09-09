#pragma once

#include <sys/wait.h>
#include <stdint.h>

extern uint16_t telnet_port;
extern char * login_argv[];

void init_telnet(char * const proc_name);
void free_session_pid(const pid_t pid);
void deinit_telnet(void);
