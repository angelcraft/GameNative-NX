#include "android_compat.hpp"

#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

extern "C" int gn_android_socket(
    int domain,
    int type,
    int protocol
) {
    return ::socket(domain, type, protocol);
}

extern "C" int gn_android_bind(
    int sockfd,
    const struct sockaddr* addr,
    socklen_t addrlen
) {
    return ::bind(sockfd, addr, addrlen);
}

extern "C" int gn_android_listen(
    int sockfd,
    int backlog
) {
    return ::listen(sockfd, backlog);
}

extern "C" int gn_android_accept(
    int sockfd,
    struct sockaddr* addr,
    socklen_t* addrlen
) {
    return ::accept(sockfd, addr, addrlen);
}

extern "C" int gn_android_poll(
    struct pollfd* fds,
    nfds_t nfds,
    int timeout
) {
    return ::poll(fds, nfds, timeout);
}

extern "C" int gn_android_unlink(
    const char* path
) {
    return ::unlink(path);
}

extern "C" int gn_android_ftruncate(
    int fd,
    off_t length
) {
    return ::ftruncate(fd, length);
}

static const solder_export_t kAndroidCompatExports[] = {
    SOLDER_EXPORT("socket",    (void*)&gn_android_socket),
    SOLDER_EXPORT("bind",      (void*)&gn_android_bind),
    SOLDER_EXPORT("listen",    (void*)&gn_android_listen),
    SOLDER_EXPORT("accept",    (void*)&gn_android_accept),
    SOLDER_EXPORT("poll",      (void*)&gn_android_poll),
    SOLDER_EXPORT("unlink",    (void*)&gn_android_unlink),
    SOLDER_EXPORT("ftruncate", (void*)&gn_android_ftruncate),
};

const solder_export_t* android_compat_exports(int* count) {
    if (count) {
        *count =
            static_cast<int>(
                sizeof(kAndroidCompatExports) /
                sizeof(kAndroidCompatExports[0])
            );
    }

    return kAndroidCompatExports;
}

bool android_compat_has_export(
    const std::string& name
) {
    int count = 0;

    const solder_export_t* exports =
        android_compat_exports(&count);

    for (int i = 0; i < count; ++i) {
        if (!exports[i].name)
            continue;

        if (name == exports[i].name)
            return true;
    }

    return false;
}
