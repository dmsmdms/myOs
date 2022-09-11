#pragma once

#include <stdint.h>

extern uint16_t service_port;

void init_service(char * const proc_name);
void deinit_service(void);
