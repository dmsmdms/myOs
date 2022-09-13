#pragma once

#include "api/core.h"

#define NET_INTERFACE_NAME_LEN  8
#define CONSOLE_LOGIN_NAME_LEN  32
#define NTP_SERVER_NAME_LEN     32

typedef struct packed {
    uint32_t    net_ip;
    uint32_t    net_mask;
    uint32_t    net_broadcast;
    uint32_t    net_route;
    uint16_t    ftp_port;
    uint16_t    ftp_data_port;
    uint16_t    control_port;
    uint16_t    telnet_port;
    uint16_t    ntp_port;
    char        net_interface[NET_INTERFACE_NAME_LEN];
    char        console_login[CONSOLE_LOGIN_NAME_LEN];
    char        ntp_server[NTP_SERVER_NAME_LEN];
} config_t;

extern config_t config;

void deinit_config(void);
void load_config(void);
void save_config(void);
