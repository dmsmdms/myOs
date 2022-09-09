#pragma once

#include <stdint.h>

extern uint16_t ftp_port;
extern uint16_t ftp_data_port;

void init_ftp(char * const proc_name);
void deinit_ftp(void);
