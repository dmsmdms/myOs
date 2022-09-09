#include "telnet.h"
#include "init.h"

#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <arpa/telnet.h>
#include <arpa/inet.h>
#include <termios.h>
#include <string.h>
#include <unistd.h>
#ifndef __USE_GNU
#define __USE_GNU
#endif
#ifndef __USE_XOPEN_EXTENDED
#define __USE_XOPEN_EXTENDED
#endif
#include <stdlib.h>
#include <fcntl.h>
#include <ctype.h>
#include <errno.h>

#define TELNET_SERVICE_NAME "telnet.service"
#define LOGIN_PATH_DEFAULT  "/bin/bash"
#define TELNET_BUFFER_SIZE  4072
#define TELNET_PORT_DEFAULT 23
#define TELNET_LISTEN_SIZE  1
#define TTY_NAME_SIZE       32
#define INVALID_RESULT      -1
#define INVALID_PID         -1
#define INVALID_FD          -1

typedef struct session {
    struct session * next;
    char buf1[TELNET_BUFFER_SIZE];
    char buf2[TELNET_BUFFER_SIZE];
    pid_t shell_pid;
    int socket_fd;
    int pty_fd;
    int rdidx1;
    int wridx1;
    int size1;
    int rdidx2;
    int wridx2;
    int size2;
} session_t;

uint16_t telnet_port = TELNET_PORT_DEFAULT;
char * login_argv[] = { LOGIN_PATH_DEFAULT, NULL };
static session_t * sessions = NULL;
static fd_set rdfdset = { 0 };
static fd_set wrfdset = { 0 };
static int master_fd = INVALID_FD;
static int client_fd = INVALID_FD;
static int maxfd = 0;

static void real_free_session(session_t * const restrict session) {
    const pid_t shell_pid = session->shell_pid;
    const int socket_fd = session->socket_fd;
    const int pty_fd = session->pty_fd;

    if (shell_pid >= 0) {
        kill(shell_pid, SIGKILL);
        session->shell_pid = INVALID_PID;
    }

    if (socket_fd >= 0) {
        close(socket_fd);
        FD_CLR(socket_fd, &rdfdset);
        FD_CLR(socket_fd, &wrfdset);
        session->socket_fd = INVALID_FD;
    }

    if (pty_fd >= 0) {
        close(pty_fd);
        FD_CLR(pty_fd, &rdfdset);
        FD_CLR(pty_fd, &wrfdset);
        session->pty_fd = INVALID_FD;
    }

    if (pty_fd == maxfd || socket_fd == maxfd) {
        maxfd--;
    }

    if (pty_fd == maxfd || socket_fd == maxfd) {
        maxfd--;
    }

    free(session);
}

void deinit_telnet(void) {
    if (master_fd >= 0) {
        close(master_fd);
        master_fd = INVALID_FD;
    }

    if (client_fd >= 0) {
        close(client_fd);
        client_fd = INVALID_FD;
    }

    for (session_t * restrict session = sessions, * next; session != NULL; session = next) {
        next = session->next;
        real_free_session(session);
    }

    sessions = NULL;
}

static int min(const int a, const int b) {
    return (a < b ? a : b);
}

static char * remove_iacs(uint8_t * const buffer, const unsigned length, int * const processed, int * const totty_ptr) {
    uint8_t * restrict ptr = buffer;
    uint8_t * restrict totty = buffer;
    uint8_t * const end = buffer + length;

    while (ptr < end) {
        if (*ptr != IAC) {
            *totty++ = *ptr++;
        } else {
            if ((ptr + 2) < end) {
                ptr += 3;
            } else {
                break;
            }
        }
    }

    const unsigned totty_number = totty - buffer;
    *processed = ptr - buffer;
    *totty_ptr = totty_number;

    return memmove(ptr - totty_number, buffer, totty_number);
}

static void getpty(int * const restrict pty_fd, char * const buffer, const unsigned length) {
    const int pt = getpt();
    sys_assert(pt, NULL);
    *pty_fd = pt;

    int result = grantpt(pt);
    sys_assert(result, NULL);

    result = unlockpt(pt);
    sys_assert(result, NULL);

    ptsname_r(pt, buffer, length);
}

static void send_iac(session_t * const restrict session,
    const uint8_t command, const uint8_t option)
{
    uint8_t * restrict buffer = (uint8_t *)session->buf2 +
        session->rdidx2;
    *buffer++ = IAC;
    *buffer++ = command;
    *buffer++ = option;
    session->rdidx2 += 3;
    session->size2 += 3;
}

static void make_new_session(const int socket_fd) {
    if (socket_fd > maxfd) {
        maxfd = socket_fd;
    }

    session_t * const restrict session = malloc(sizeof(session_t));
    mem_assert(session, NULL);

    session->shell_pid = INVALID_PID;
    session->socket_fd = socket_fd;
    session->pty_fd = INVALID_FD;
    session->rdidx1 = 0;
    session->wridx1 = 0;
    session->size1 = 0;
    session->rdidx2 = 0;
    session->wridx2 = 0;
    session->size2 = 0;

    session->next = sessions;
    sessions = session;

    char tty_name[TTY_NAME_SIZE];
    getpty(&session->pty_fd, tty_name, sizeof(tty_name));

    if (session->pty_fd > maxfd) {
        maxfd = session->pty_fd;
    }

    send_iac(session, DO, TELOPT_ECHO);
    send_iac(session, DO, TELOPT_LFLOW);
    send_iac(session, WILL, TELOPT_ECHO);
    send_iac(session, WILL, TELOPT_SGA);

    session->shell_pid = fork();
    sys_assert(session->shell_pid, NULL);

    if (session->shell_pid == 0) {
        for(int fd = 0; fd <= maxfd; fd++) {
            close(fd);
        }

        int result = setsid();
        sys_assert(result, NULL);

        const int tty_fd = open(tty_name, O_RDWR | O_NOCTTY);
        sys_assert(tty_fd, NULL);

        const int tty_in = dup(STDIN_FILENO);
        sys_assert(tty_in, NULL);

        const int tty_out = dup(STDOUT_FILENO);
        sys_assert(tty_out, NULL);

        //result = tcsetpgrp(0, getpid());
        //sys_assert(result, NULL);

        result = ioctl(tty_fd, TIOCSCTTY, NULL);
        sys_assert(result, NULL);

        struct termios termbuf;
        result = tcgetattr(tty_fd, &termbuf);
        sys_assert(result, NULL);

        termbuf.c_lflag |= ECHO;
        termbuf.c_oflag |= XTABS;
        termbuf.c_iflag &= ~INLCR;
        termbuf.c_iflag &= ~IXOFF;

        result = tcsetattr(tty_fd, TCSANOW, &termbuf);
        sys_assert(tty_fd, NULL);

        result = execve(login_argv[0], login_argv, env);
        sys_assert(result, NULL);
    }
}

void free_session_pid(const pid_t pid) {
    session_t ** restrict last_session = &sessions;
    session_t * restrict session = sessions;

    while (session != NULL) {
        if (session->shell_pid == pid) {
            break;
        }

        last_session = &session->next;
        session = session->next;
    }

    if (session != NULL) {
        *last_session = session->next;
        real_free_session(session);
    }
}

static void free_session(session_t * const restrict cur_session) {
    session_t ** restrict last_session = &sessions;
    session_t * restrict session = sessions;

    while (session != NULL) {
        if (session == cur_session) {
            break;
        }

        last_session = &session->next;
        session = session->next;
    }

    if (session != NULL) {
        *last_session = session->next;
        real_free_session(session);
    }
}

void init_telnet(char * const proc_name) {
    const pid_t pid = do_fork(proc_name, TELNET_SERVICE_NAME);
    user_return(pid != EXIT_SUCCESS, (void)pid);

    master_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    sys_assert(master_fd, NULL);
    maxfd = master_fd;

    struct sockaddr_in sockaddr = {
        .sin_family = AF_INET,
        .sin_port = htons(telnet_port),
        .sin_addr.s_addr = htonl(INADDR_ANY),
    };

    int result = bind(master_fd, (struct sockaddr *)&sockaddr, sizeof(sockaddr));
    sys_assert(result, NULL);

    const int reuse_addr = true;
    result = setsockopt(master_fd, SOL_SOCKET, SO_REUSEADDR, &reuse_addr, sizeof(reuse_addr));
    sys_assert(result, NULL);

    result = listen(master_fd, TELNET_LISTEN_SIZE);
    sys_assert(result, NULL);

    while (true) {
        FD_ZERO(&rdfdset);
        FD_ZERO(&wrfdset);

        for (session_t * restrict session = sessions; session != NULL; session = session->next) {
            if (session->size1 > 0) {
                FD_SET(session->pty_fd, &wrfdset);
            }

            if (session->size1 < (int)sizeof(session->buf1)) {
                FD_SET(session->socket_fd, &rdfdset);
            }

            if (session->size2 > 0) {
                FD_SET(session->socket_fd, &wrfdset);
            }

            if (session->size2 < (int)sizeof(session->buf2)) {
                FD_SET(session->pty_fd, &rdfdset);
            }
        }

        FD_SET(master_fd, &rdfdset);
        result = select(maxfd + 1, &rdfdset, &wrfdset, NULL, NULL);
        if (result < 0 && errno != EINTR) {
            sys_assert(INVALID_RESULT, NULL);
        }

        if (FD_ISSET(master_fd, &rdfdset)) {
            client_fd = accept(master_fd, NULL, NULL);
            sys_goto(client_fd, skip_session, NULL);

            make_new_session(client_fd);
        skip_session:
            client_fd = INVALID_FD;
        }

        for (session_t * restrict session = sessions, * next; session != NULL; session = next) {
            next = session->next;

            if (session->size1 > 0 && FD_ISSET(session->pty_fd, &wrfdset)) {
                const int minlen = min((int)sizeof(session->buf1) - session->wridx1, session->size1);

                int processed, num_totty;
                char * restrict ptr = remove_iacs((uint8_t *)session->buf1 + session->wridx1,
                    minlen, &processed, &num_totty);

                if (ptr[num_totty - 1] == '\n' && ptr[num_totty - 2] == '\r') {
                    ptr[num_totty - 1] = '\0';
                    num_totty -= 1;
                }

                session->wridx1 += processed - num_totty;
                session->size1 -= processed - num_totty;

                int result = write(session->pty_fd, ptr, num_totty);
                sys_goto(result, free_session, NULL);

                session->wridx1 += result;
                session->size1 -= result;

                if (session->wridx1 == sizeof(session->buf1)) {
                    session->wridx1 = 0;
                }
            }

            if (session->size2 > 0 && FD_ISSET(session->socket_fd, &wrfdset)) {
                const int minlen = min((int)sizeof(session->buf2) - session->wridx2, session->size2);

                int result = send(session->socket_fd, session->buf2 + session->wridx2, minlen, MSG_NOSIGNAL);
                sys_goto(result, free_session, NULL);

                session->wridx2 += result;
                session->size2 -= result;

                if (session->wridx2 == (int)sizeof(session->buf2)) {
                    session->wridx2 = 0;
                }
            }

            if (session->size1 < (int)sizeof(session->buf1) && FD_ISSET(session->socket_fd, &rdfdset)) {
                const int minlen = min((int)sizeof(session->buf1) - session->rdidx1,
                    (int)sizeof(session->buf1) - session->size1);

                int result = recv(session->socket_fd, session->buf1 + session->rdidx1, minlen, MSG_NOSIGNAL);
                if (result == 0 || (result < 0 && errno != EINTR)) {
                    sys_goto(INVALID_RESULT, free_session, NULL);
                }

                const char * restrict ptr = session->buf1 + session->rdidx1 + result - 1;
                if (*ptr == '\0') {
                    result--;
                    if (result == 0) {
                        continue;
                    }
                }

                session->rdidx1 += result;
                session->size1 += result;

                if (session->rdidx1 == (int)sizeof(session->buf1)) {
                    session->rdidx1 = 0;
                }
            }

            if (session->size2 < (int)sizeof(session->buf2) && FD_ISSET(session->pty_fd, &rdfdset)) {
                const int minlen = min((int)sizeof(session->buf2) - session->rdidx2,
                    (int)sizeof(session->buf2) - session->size2);

                int result = read(session->pty_fd, session->buf2 + session->rdidx2, minlen);
                if (result == 0 || (result < 0 && errno != EINTR)) {
                    sys_goto(INVALID_RESULT, free_session, NULL);
                }

                session->rdidx2 += result;
                session->size2 += result;

                if (session->rdidx2 == (int)sizeof(session->buf2)) {
                    session->rdidx2 = 0;
                }
            }

            if (session->size1 == 0) {
                session->rdidx1 = 0;
                session->wridx1 = 0;
            }

            if (session->size2 == 0) {
                session->rdidx2 = 0;
                session->wridx2 = 0;
            }

            continue;
        free_session:
            free_session(session);
        }
    }
}
