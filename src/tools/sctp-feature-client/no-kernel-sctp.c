/* Linux-only test shim: deny SCTP socket creation in this process.
 * No kernel configuration or network namespace changes are made.
 * cc -shared -fPIC no-kernel-sctp.c -ldl -o /tmp/no-kernel-sctp.so
 * LD_PRELOAD=/tmp/no-kernel-sctp.so <test executable>
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <netinet/in.h>
#include <sys/socket.h>

int socket(int domain, int type, int protocol)
{
    if ((domain == AF_INET || domain == AF_INET6) && protocol == IPPROTO_SCTP) {
        errno = EPROTONOSUPPORT;
        return -1;
    }
    int (*real_socket)(int, int, int) = dlsym(RTLD_NEXT, "socket");
    if (real_socket == 0) {
        errno = ENOSYS;
        return -1;
    }
    return real_socket(domain, type, protocol);
}
