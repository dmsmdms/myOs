#include "service.h"
#include "telnet.h"
#include "init.h"
#include "ftp.h"

#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/mount.h>
#include <sys/ioctl.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#ifndef __USE_MISC
#define __USE_MISC
#endif
#include <sys/time.h>
#include <arpa/inet.h>
#include <net/route.h>
#include <net/if.h>
#include <getopt.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#include <syslog.h>
#include <stdio.h>
#include <netdb.h>
#include <time.h>

#define HOME_DIR_KEY            "HOME"
#define HOME_DIR_DEFAULT        "/root"
#define TERM_KEY                "TERM"
#define TERM_DEFAULT            "xterm-256color"
#define MAX_ENV_LENGTH          128
#define MAX_LOG_SIZE            512
#define ACCESS_MODE_DEFAULT     (S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH)
#define PROC_FS_NAME            "proc"
#define PROC_FS_DIR             "/proc"
#define DEVPTS_FS_NAME          "devpts"
#define DEVPTS_FS_DIR           "/dev/pts"
#define NET_DEV_DEFAULT         "eth0"
#define IP_ADDR_DEFAULT         "192.168.1.32"
#define IP_MASK_DEFAULT         "255.255.255.0"
#define IP_ROUTE_DEFAULT        "192.168.1.1"
#define IP_BROADCAST_DEFAULT    "192.168.1.255"
#define IP_INIT_INTERVAL        (250 * 1000)
#define IP_INIT_TIMEOUT         (1000 * 1000)
#define HOSTENT_BUF_SIZE        1024
#define NTP_MODE                0x1b
#define NTP_PORT                123
#define NTP_TIMESTAMP           2208988800
#define NTP_SERVER_DEFAULT      "us.pool.ntp.org"
#define INVALID_PID             -1
#define INVALID_FD              -1

typedef struct __attribute__((packed)) {
    uint8_t li_vn_mode;
    uint8_t stratum;
    uint8_t poll;
    uint8_t precision;
    uint32_t rootDelay;
    uint32_t rootDispersion;
    uint32_t refId;
    uint32_t refTm_s;
    uint32_t refTm_f;
    uint32_t origTm_s;
    uint32_t origTm_f;
    uint32_t rxTm_s;
    uint32_t rxTm_f;
    uint32_t txTm_s;
    uint32_t txTm_f;
} ntp_block_t;

enum {
    ENV_IDX_HOME,
    ENV_IDX_TERM,
    ENV_IDX_NULL,
    ENV_IDX_MAX,
};

char * env[ENV_IDX_MAX] = { NULL };
int maxfd = STDERR_FILENO;
static const char * home_dir = HOME_DIR_DEFAULT;
static const char * term = TERM_DEFAULT;
static char * net_dev = NET_DEV_DEFAULT;
static const char * ip_addr = IP_ADDR_DEFAULT;
static const char * ip_mask = IP_MASK_DEFAULT;
static const char * ip_route = IP_ROUTE_DEFAULT;
static const char * ip_broadcast = IP_BROADCAST_DEFAULT;
static const char * ntp_server = NTP_SERVER_DEFAULT;
static int socket_fd = INVALID_FD;
static int file_fd = INVALID_FD;

static void deinit(void) {
    if (socket_fd >= 0) {
        close(socket_fd);
        socket_fd = INVALID_FD;
    }

    if (file_fd >= 0) {
        close(file_fd);
        file_fd = INVALID_FD;
    }

    closelog();
}

static void syslog_print(const char * const file, const unsigned line, const int log_level,
                         const char * const msg, va_list args)
{
    char buffer[MAX_LOG_SIZE], * buf = buffer;
    buf += sprintf(buf, "%s:%u errno - %s", file, line, strerror(errno));

    if (msg != NULL) {
        static char msg_str[] = ", msg - ";
        memcpy(buf, msg_str, sizeof(msg_str) - 1);

        buf += sizeof(msg_str) - 1;
        buf += vsprintf(buf, msg, args);
    }

    *buf++ = '\n';
    *buf++ = '\0';

    syslog(log_level, "%s", buffer);
}

void _sys_assert(const char * const file, const unsigned line, const char * const msg, ...) {
    va_list args;
    va_start(args, msg);

    syslog_print(file, line, LOG_ERR, msg, args);

    va_end(args);
    exit(EXIT_FAILURE);
}

void _sys_warning(const char * const file, const unsigned line, const char * const msg, ...) {
    va_list args;
    va_start(args, msg);

    syslog_print(file, line, LOG_WARNING, msg, args);

    va_end(args);
}

static void parse_cmdline(const int argc, char ** const argv) {
    while (true) {
        const int c = getopt(argc, argv, "h:i:a:m:r:b:n:t:l:f:d:s:");

        switch (c) {
        case 'h':
            home_dir = optarg;
        case 'i':
            net_dev = optarg;
            break;
        case 'a':
            ip_addr = optarg;
            break;
        case 'm':
            ip_mask = optarg;
            break;
        case 'r':
            ip_route = optarg;
            break;
        case 'b':
            ip_broadcast = optarg;
            break;
        case 'n':
            ntp_server = optarg;
            break;
        case 't':
            telnet_port = atoi(optarg);
            break;
        case 'l':
            login_argv[0] = optarg;
            break;
        case 'f':
            ftp_port = atoi(optarg);
            break;
        case 'd':
            ftp_data_port = atoi(optarg);
            break;
        case 's':
            service_port = atoi(optarg);
            break;
        case INVALID_FD:
            return;
        }
    }
}

#ifndef EMUL
static void mount_all(void) {
    int result = mount(PROC_FS_NAME, PROC_FS_DIR, PROC_FS_NAME, 0, NULL);
    sys_assert(result, NULL);

    result = mkdir(DEVPTS_FS_DIR, ACCESS_MODE_DEFAULT);
    sys_assert(result, NULL);

    result = mount(DEVPTS_FS_NAME, DEVPTS_FS_DIR, DEVPTS_FS_NAME, 0, NULL);
    sys_assert(result, NULL);
}

static void init_ip(void) {
    if (socket_fd < 0) {
        socket_fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        sys_assert(socket_fd, NULL);

        if (socket_fd > maxfd) {
            maxfd = socket_fd;
        }
    }

    struct ifreq ifreq = {};
    strcpy(ifreq.ifr_name, net_dev);

    for (unsigned timeout = 0; timeout < (IP_INIT_TIMEOUT / IP_INIT_INTERVAL); timeout++) {
        int result = ioctl(socket_fd, SIOCGIFFLAGS, &ifreq);
        user_break(result == EXIT_SUCCESS);

        if (errno != ENODEV) {
            sys_assert(result, NULL);
        }

        result = usleep(IP_INIT_INTERVAL);
        sys_assert(result, NULL);
    }

    ifreq.ifr_flags |= IFF_UP;
    int result = ioctl(socket_fd, SIOCSIFFLAGS, &ifreq);
    sys_assert(result, NULL);
    ifreq.ifr_flags = 0;

    struct sockaddr_in * sockaddr = (struct sockaddr_in *)&ifreq.ifr_addr;
    sockaddr->sin_family = AF_INET;

    result = inet_pton(AF_INET, ip_addr, &sockaddr->sin_addr);
    sys_assert(result, NULL);

    result = ioctl(socket_fd, SIOCSIFADDR, &ifreq);
    sys_assert(result, NULL);

    result = inet_pton(AF_INET, ip_mask, &sockaddr->sin_addr);
    sys_assert(result, NULL);

    result = ioctl(socket_fd, SIOCSIFNETMASK, &ifreq);
    sys_assert(result, NULL);

    result = inet_pton(AF_INET, ip_broadcast, &sockaddr->sin_addr);
    sys_assert(result, NULL);

    result = ioctl(socket_fd, SIOCSIFBRDADDR, &ifreq);
    sys_assert(result, NULL);

    struct rtentry rtentry = {
        .rt_dev = net_dev,
        .rt_flags = RTF_UP | RTF_GATEWAY,
    };

    sockaddr = (struct sockaddr_in *)&rtentry.rt_gateway;
    sockaddr->sin_family = AF_INET;
    result = inet_pton(AF_INET, ip_route, &sockaddr->sin_addr);
    sys_assert(result, NULL);

    sockaddr = (struct sockaddr_in *)&rtentry.rt_dst;
    sockaddr->sin_family = AF_INET;
    sockaddr->sin_addr.s_addr = INADDR_ANY;

    sockaddr = (struct sockaddr_in *)&rtentry.rt_genmask;
    sockaddr->sin_family = AF_INET;
    sockaddr->sin_addr.s_addr = INADDR_ANY;

    result = ioctl(socket_fd, SIOCADDRT, &rtentry);
    sys_assert(result, NULL);
}
#endif

static void update_time(void) {
    struct hostent hostent;
    struct hostent * hostent_ptr;
    char buffer[HOSTENT_BUF_SIZE];

    int result = gethostbyname_r(ntp_server, &hostent, buffer, sizeof(buffer), &hostent_ptr, &errno);
    sys_assert(result, NULL);

    struct sockaddr_in sockaddr = {
        .sin_family = AF_INET,
        .sin_port = htons(NTP_PORT),
        .sin_addr.s_addr = *(uint32_t *)hostent.h_addr_list[0],
    };

    if (socket_fd < 0) {
        socket_fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        sys_assert(socket_fd, NULL);

        if (socket_fd > maxfd) {
            maxfd = socket_fd;
        }
    }

    result = connect(socket_fd, (struct sockaddr *)&sockaddr, sizeof(sockaddr));
    sys_assert(result, NULL);

    ntp_block_t block = { .li_vn_mode = NTP_MODE };
    result = send(socket_fd, &block, sizeof(block), MSG_NOSIGNAL);
    sys_assert(result, NULL);

    result = recv(socket_fd, &block, sizeof(block), MSG_NOSIGNAL);
    sys_assert(result, NULL);

    close(socket_fd);
    socket_fd = INVALID_FD;

    struct timeval timeval = {
        .tv_sec = ntohl(block.txTm_s) - NTP_TIMESTAMP,
        .tv_usec = 0,
    };

#ifndef EMUL
    result = settimeofday(&timeval, NULL);
    sys_assert(result, NULL);
#else
    _sys_warning(__FILE__, __LINE__, "%s", ctime(&timeval.tv_sec));
#endif
}

_Noreturn static void exit_handler(const int code __attribute__((unused))) {
    exit(EXIT_FAILURE);
}

static void sigchild_handler(const int code __attribute__((unused))) {
    while (true) {
        const pid_t pid = waitpid(INVALID_PID, NULL, WNOHANG);

        if (pid >= 0) {
            free_session_pid(pid);
        } else {
            break;
        }
    }
}

#ifndef EMUL
static void init_env(void) {
    static char home_env[MAX_ENV_LENGTH];
    snprintf(home_env, sizeof(home_env), "%s=%s", HOME_DIR_KEY, home_dir);
    env[ENV_IDX_HOME] = home_env;

    static char term_env[MAX_ENV_LENGTH];
    snprintf(term_env, sizeof(term_env), "%s=%s", TERM_KEY, term);
    env[ENV_IDX_TERM] = term_env;
}
#endif

void set_proc_name(char * const proc_name, const char * const name) {
    memset(proc_name, '\0', strlen(proc_name));
    strcpy(proc_name, name);
}

static void syslog_open(const char * const proc_name) {
    openlog(proc_name, LOG_CONS, LOG_DAEMON);
}

static void init_app(char * const proc_name) {
    syslog_open(proc_name);

    int result = fclose(stderr);
    sys_assert(result, NULL);

    maxfd = STDOUT_FILENO;
    stderr = NULL;

    result = atexit(deinit);
    sys_assert(result, NULL);

    result = atexit(deinit_service);
    sys_assert(result, NULL);

    result = atexit(deinit_telnet);
    sys_assert(result, NULL);

    result = atexit(deinit_ftp);
    sys_assert(result, NULL);

    __sighandler_t sig_result = signal(SIGSEGV, exit_handler);
    sig_assert(sig_result, NULL);

    sig_result = signal(SIGTERM, exit_handler);
    sig_assert(sig_result, NULL);

    sig_result = signal(SIGHUP, exit_handler);
    sig_assert(sig_result, NULL);

    sig_result = signal(SIGCHLD, sigchild_handler);
    sig_assert(sig_result, NULL);
}

pid_t do_fork(char * const proc_name, const char * const name) {
    const pid_t pid = fork();
    sys_assert(pid, NULL);

    if (pid == EXIT_SUCCESS) {
        for(int fd = 0; fd <= maxfd; fd++) {
            close(fd);
        }

        set_proc_name(proc_name, name);
        syslog_open(proc_name);

        const int result = prctl(PR_SET_PDEATHSIG, SIGHUP);
        sys_assert(result, NULL);
    }

    return pid;
}

int main(const int argc, char ** const argv) {
    init_app(argv[0]);
    parse_cmdline(argc, argv);

#ifndef EMUL
    mount_all();
    init_env();
    init_ip();
#endif

    update_time();
    deinit();

    init_service(argv[0]);
    return EXIT_SUCCESS;
}

