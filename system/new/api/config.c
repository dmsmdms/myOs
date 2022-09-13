#include "api/net.h"
#include "config.h"

#ifndef __USE_XOPEN
#define __USE_XOPEN
#endif

#include <unistd.h>
#include <fcntl.h>

#define CONFIG_PATH_DEFAULT "/etc/config.bin"
#define CONFIG_CREATE_MODE  (S_IRUSR | S_IWUSR)

static int config_fd = INVALID_FD;

config_t config = {
    .net_ip         = MAKE_IP(192, 168, 1, 32),
    .net_mask       = MAKE_IP(255, 255, 255, 0),
    .net_broadcast  = MAKE_IP(192, 168, 1, 255),
    .net_route      = MAKE_IP(192, 168, 1, 1),
    .ftp_port       = 21,
    .ftp_data_port  = 20,
    .control_port   = 80,
    .telnet_port    = 23,
    .ntp_port       = 123,
    .net_interface  = "eth0",
    .console_login  = "/bin/bash",
    .ntp_server     = "us.pool.ntp.org",
};

void deinit_config(void) {
    try_close(config_fd);
}

void load_config(void) {
    config_fd = open(CONFIG_PATH_DEFAULT, O_RDONLY);
    sys_return_void(config_fd, "Config file %s not found. Use default config",
                    CONFIG_PATH_DEFAULT);

    int result = read(config_fd, &config, sizeof(config));
    io_assert(result, sizeof(config), NULL);

    hard_close(config_fd);
}

void save_config(void) {
    config_fd = creat(CONFIG_PATH_DEFAULT, CONFIG_CREATE_MODE);
    sys_assert(config_fd, NULL);

    int result = write(config_fd, &config, sizeof(config));
    io_assert(result, sizeof(config), NULL);

    hard_close(config_fd);
}
