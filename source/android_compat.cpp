#include "android_compat.hpp"

#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cerrno>
#include <cstdint>
#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cwchar>

namespace {

constexpr int kMaxEpollInstances = 8;
constexpr int kMaxEpollWatches = 64;

// Android/Bionic epoll constants.
constexpr uint32_t GN_EPOLLIN       = 0x00000001;
constexpr uint32_t GN_EPOLLPRI      = 0x00000002;
constexpr uint32_t GN_EPOLLOUT      = 0x00000004;
constexpr uint32_t GN_EPOLLERR      = 0x00000008;
constexpr uint32_t GN_EPOLLHUP      = 0x00000010;
constexpr uint32_t GN_EPOLLRDNORM   = 0x00000040;
constexpr uint32_t GN_EPOLLRDBAND   = 0x00000080;
constexpr uint32_t GN_EPOLLWRNORM   = 0x00000100;
constexpr uint32_t GN_EPOLLWRBAND   = 0x00000200;
constexpr uint32_t GN_EPOLLRDHUP    = 0x00002000;
constexpr uint32_t GN_EPOLLWAKEUP   = 0x20000000;
constexpr uint32_t GN_EPOLLONESHOT  = 0x40000000;
constexpr uint32_t GN_EPOLLET       = 0x80000000;

constexpr int GN_EPOLL_CTL_ADD = 1;
constexpr int GN_EPOLL_CTL_DEL = 2;
constexpr int GN_EPOLL_CTL_MOD = 3;

// ABI-compatible with Android's AArch64 epoll_event.
struct gn_epoll_event {
    uint32_t events;

    union {
        void* ptr;
        int fd;
        uint32_t u32;
        uint64_t u64;
    } data;
};

struct EpollWatch {
    bool used = false;
    int fd = -1;
    uint32_t events = 0;
    gn_epoll_event user_event{};
};

struct EpollInstance {
    bool used = false;

    // Real OS fd used as a unique epoll handle.
    // The implementation itself uses poll() on the watched fds.
    int handle_fd = -1;

    EpollWatch watches[kMaxEpollWatches];
};

EpollInstance g_epolls[kMaxEpollInstances];

EpollInstance* find_epoll(int epfd) {
    for (int i = 0; i < kMaxEpollInstances; ++i) {
        if (g_epolls[i].used &&
            g_epolls[i].handle_fd == epfd) {

            return &g_epolls[i];
        }
    }

    return nullptr;
}

EpollWatch* find_watch(
    EpollInstance* ep,
    int fd
) {
    if (!ep)
        return nullptr;

    for (int i = 0; i < kMaxEpollWatches; ++i) {
        if (ep->watches[i].used &&
            ep->watches[i].fd == fd) {

            return &ep->watches[i];
        }
    }

    return nullptr;
}

EpollWatch* allocate_watch(EpollInstance* ep) {
    if (!ep)
        return nullptr;

    for (int i = 0; i < kMaxEpollWatches; ++i) {
        if (!ep->watches[i].used)
            return &ep->watches[i];
    }

    return nullptr;
}

short epoll_to_poll_events(uint32_t events) {
    short result = 0;

    if (events & (
            GN_EPOLLIN |
            GN_EPOLLRDNORM)) {

        result |= POLLIN;
    }

    if (events & (
            GN_EPOLLOUT |
            GN_EPOLLWRNORM)) {

        result |= POLLOUT;
    }

    if (events & GN_EPOLLPRI)
        result |= POLLPRI;

    return result;
}

uint32_t poll_to_epoll_events(
    short revents
) {
    uint32_t result = 0;

    if (revents & POLLIN)
        result |= GN_EPOLLIN;

    if (revents & POLLOUT)
        result |= GN_EPOLLOUT;

    if (revents & POLLPRI)
        result |= GN_EPOLLPRI;

    if (revents & POLLERR)
        result |= GN_EPOLLERR;

    if (revents & POLLHUP)
        result |= GN_EPOLLHUP;

#ifdef POLLRDHUP
    if (revents & POLLRDHUP)
        result |= GN_EPOLLRDHUP;
#endif

    return result;
}

} // namespace


// ============================================================================
// Basic POSIX compatibility
// ============================================================================

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


// ============================================================================
// New libc / POSIX compatibility functions
// ============================================================================

extern "C" ssize_t gn_android_read_chk(
    int fd,
    void* buf,
    size_t count,
    size_t /*buflen*/
) {
    return ::read(
        fd,
        buf,
        count
    );
}

extern "C" ssize_t gn_android_write_chk(
    int fd,
    const void* buf,
    size_t count,
    size_t /*buflen*/
) {
    return ::write(
        fd,
        buf,
        count
    );
}

extern "C" int gn_android_vsprintf_chk(
    char* dst,
    int /*flag*/,
    size_t dst_len,
    const char* fmt,
    va_list ap
) {
    if (!dst || !fmt) {
        errno = EINVAL;
        return -1;
    }

    if (dst_len == 0) {
        errno = ERANGE;
        return -1;
    }

    return std::vsnprintf(
        dst,
        dst_len,
        fmt,
        ap
    );
}

extern "C" void* gn_android_mmap(
    void* addr,
    size_t length,
    int prot,
    int flags,
    int fd,
    off_t offset
) {
    return ::mmap(
        addr,
        length,
        prot,
        flags,
        fd,
        offset
    );
}

extern "C" int gn_android_munmap(
    void* addr,
    size_t length
) {
    return ::munmap(
        addr,
        length
    );
}

extern "C" char* gn_android_strdup(
    const char* src
) {
    if (!src) {
        errno = EINVAL;
        return nullptr;
    }

    return ::strdup(src);
}

extern "C" void gn_android_qsort(
    void* base,
    size_t nmemb,
    size_t size,
    int (*compar)(
        const void*,
        const void*
    )
) {
    ::qsort(
        base,
        nmemb,
        size,
        compar
    );
}

extern "C" wchar_t* gn_android_fgetws(
    wchar_t* ws,
    int n,
    FILE* stream
) {
    return ::fgetws(
        ws,
        n,
        stream
    );
}

extern "C" ssize_t gn_android_sendmsg(
    int sockfd,
    const struct msghdr* msg,
    int flags
) {
    return ::sendmsg(
        sockfd,
        msg,
        flags
    );
}

extern "C" ssize_t gn_android_recvmsg(
    int sockfd,
    struct msghdr* msg,
    int flags
) {
    return ::recvmsg(
        sockfd,
        msg,
        flags
    );
}

extern "C" struct cmsghdr* gn_android_cmsg_nxthdr(
    struct msghdr* msg,
    struct cmsghdr* cmsg
) {
    if (!msg)
        return nullptr;

    if (!cmsg) {
        if (!msg->msg_control ||
            msg->msg_controllen <
                sizeof(struct cmsghdr)) {

            return nullptr;
        }

        return reinterpret_cast<struct cmsghdr*>(
            msg->msg_control
        );
    }

    unsigned char* base =
        static_cast<unsigned char*>(
            msg->msg_control
        );

    unsigned char* end =
        base +
        msg->msg_controllen;

    unsigned char* next =
        reinterpret_cast<unsigned char*>(
            cmsg
        ) +
        CMSG_ALIGN(cmsg->cmsg_len);

    if (next +
            sizeof(struct cmsghdr) >
        end) {

        return nullptr;
    }

    struct cmsghdr* next_hdr =
        reinterpret_cast<struct cmsghdr*>(
            next
        );

    if (next +
            CMSG_ALIGN(
                next_hdr->cmsg_len
            ) >
        end) {

        return nullptr;
    }

    return next_hdr;
}


// ============================================================================
// syscall compatibility
// ============================================================================
//
// Linux syscall numbers do not map directly to Horizon.
// We deliberately do NOT translate them blindly yet.
//
// Returning ENOSYS is safer until we know the exact syscall numbers that
// libwinlator actually invokes.
//
// This export exists so that the dynamic symbol is present, but any call to
// it currently reports "function not implemented".
//

extern "C" long gn_android_syscall(
    long /*number*/,
    ...
) {
    errno = ENOSYS;
    return -1;
}


// ============================================================================
// epoll compatibility layer
// ============================================================================
//
// First-pass implementation:
//
//   epoll_ctl() stores the requested watches.
//   epoll_wait() translates those watches into poll().
//   EPOLLET / EPOLLONESHOT semantics are not implemented yet.
//

extern "C" int gn_android_epoll_create(
    int size
) {
    if (size <= 0) {
        errno = EINVAL;
        return -1;
    }

    for (int i = 0;
         i < kMaxEpollInstances;
         ++i) {

        if (g_epolls[i].used)
            continue;

        // Use a real descriptor as a unique handle.
        // The descriptor itself is not used for waiting.
        const int handle =
            ::socket(
                AF_INET,
                SOCK_STREAM,
                0
            );

        if (handle < 0)
            return -1;

        g_epolls[i] = {};
        g_epolls[i].used = true;
        g_epolls[i].handle_fd = handle;

        return handle;
    }

    errno = EMFILE;
    return -1;
}

extern "C" int gn_android_epoll_ctl(
    int epfd,
    int op,
    int fd,
    void* event_ptr
) {
    EpollInstance* ep =
        find_epoll(epfd);

    if (!ep || fd < 0) {
        errno = EBADF;
        return -1;
    }

    if (op == GN_EPOLL_CTL_ADD) {
        if (!event_ptr) {
            errno = EFAULT;
            return -1;
        }

        if (find_watch(ep, fd)) {
            errno = EEXIST;
            return -1;
        }

        EpollWatch* watch =
            allocate_watch(ep);

        if (!watch) {
            errno = ENOSPC;
            return -1;
        }

        const gn_epoll_event* src =
            static_cast<const gn_epoll_event*>(
                event_ptr
            );

        watch->used = true;
        watch->fd = fd;
        watch->events = src->events;
        watch->user_event = *src;

        return 0;
    }

    if (op == GN_EPOLL_CTL_MOD) {
        if (!event_ptr) {
            errno = EFAULT;
            return -1;
        }

        EpollWatch* watch =
            find_watch(
                ep,
                fd
            );

        if (!watch) {
            errno = ENOENT;
            return -1;
        }

        const gn_epoll_event* src =
            static_cast<const gn_epoll_event*>(
                event_ptr
            );

        watch->events =
            src->events;

        watch->user_event =
            *src;

        return 0;
    }

    if (op == GN_EPOLL_CTL_DEL) {
        EpollWatch* watch =
            find_watch(
                ep,
                fd
            );

        if (!watch) {
            errno = ENOENT;
            return -1;
        }

        *watch = {};
        return 0;
    }

    errno = EINVAL;
    return -1;
}

extern "C" int gn_android_epoll_wait(
    int epfd,
    void* events_ptr,
    int maxevents,
    int timeout
) {
    if (!events_ptr ||
        maxevents <= 0) {

        errno = EINVAL;
        return -1;
    }

    EpollInstance* ep =
        find_epoll(epfd);

    if (!ep) {
        errno = EBADF;
        return -1;
    }

    pollfd poll_fds[
        kMaxEpollWatches
    ];

    EpollWatch* watch_map[
        kMaxEpollWatches
    ];

    int poll_count = 0;

    for (int i = 0;
         i < kMaxEpollWatches;
         ++i) {

        EpollWatch& watch =
            ep->watches[i];

        if (!watch.used)
            continue;

        if (poll_count >=
            kMaxEpollWatches) {

            break;
        }

        poll_fds[poll_count] = {};

        poll_fds[poll_count].fd =
            watch.fd;

        poll_fds[poll_count].events =
            epoll_to_poll_events(
                watch.events
            );

        watch_map[poll_count] =
            &watch;

        ++poll_count;
    }

    if (poll_count == 0) {
        return ::poll(
            nullptr,
            0,
            timeout
        );
    }

    const int ready =
        ::poll(
            poll_fds,
            static_cast<nfds_t>(
                poll_count
            ),
            timeout
        );

    if (ready <= 0)
        return ready;

    gn_epoll_event* out_events =
        static_cast<gn_epoll_event*>(
            events_ptr
        );

    int output_count = 0;

    for (int i = 0;
         i < poll_count &&
         output_count < maxevents;
         ++i) {

        if (!poll_fds[i].revents)
            continue;

        EpollWatch* watch =
            watch_map[i];

        gn_epoll_event out =
            watch->user_event;

        out.events =
            poll_to_epoll_events(
                poll_fds[i].revents
            );

        out_events[
            output_count
        ] = out;

        ++output_count;
    }

    return output_count;
}


// ============================================================================
// Export table
// ============================================================================

static const solder_export_t kAndroidCompatExports[] = {

    // Existing socket / filesystem compatibility.
    SOLDER_EXPORT(
        "socket",
        (void*)&gn_android_socket
    ),

    SOLDER_EXPORT(
        "bind",
        (void*)&gn_android_bind
    ),

    SOLDER_EXPORT(
        "listen",
        (void*)&gn_android_listen
    ),

    SOLDER_EXPORT(
        "accept",
        (void*)&gn_android_accept
    ),

    SOLDER_EXPORT(
        "poll",
        (void*)&gn_android_poll
    ),

    SOLDER_EXPORT(
        "unlink",
        (void*)&gn_android_unlink
    ),

    SOLDER_EXPORT(
        "ftruncate",
        (void*)&gn_android_ftruncate
    ),

    // epoll.
    SOLDER_EXPORT(
        "epoll_create",
        (void*)&gn_android_epoll_create
    ),

    SOLDER_EXPORT(
        "epoll_ctl",
        (void*)&gn_android_epoll_ctl
    ),

    SOLDER_EXPORT(
        "epoll_wait",
        (void*)&gn_android_epoll_wait
    ),

    // Checked libc functions.
    SOLDER_EXPORT(
        "__read_chk",
        (void*)&gn_android_read_chk
    ),

    SOLDER_EXPORT(
        "__write_chk",
        (void*)&gn_android_write_chk
    ),

    SOLDER_EXPORT(
        "__vsprintf_chk",
        (void*)&gn_android_vsprintf_chk
    ),

    // Memory.
    SOLDER_EXPORT(
        "mmap",
        (void*)&gn_android_mmap
    ),

    SOLDER_EXPORT(
        "munmap",
        (void*)&gn_android_munmap
    ),

    // libc helpers.
    SOLDER_EXPORT(
        "strdup",
        (void*)&gn_android_strdup
    ),

    SOLDER_EXPORT(
        "qsort",
        (void*)&gn_android_qsort
    ),

    SOLDER_EXPORT(
        "fgetws",
        (void*)&gn_android_fgetws
    ),

    // Socket message APIs.
    SOLDER_EXPORT(
        "sendmsg",
        (void*)&gn_android_sendmsg
    ),

    SOLDER_EXPORT(
        "recvmsg",
        (void*)&gn_android_recvmsg
    ),

    SOLDER_EXPORT(
        "__cmsg_nxthdr",
        (void*)&gn_android_cmsg_nxthdr
    ),

    // Linux syscall entry point.
    SOLDER_EXPORT(
        "syscall",
        (void*)&gn_android_syscall
    ),
};


// ============================================================================
// Public compatibility API
// ============================================================================

const solder_export_t* android_compat_exports(
    int* count
) {
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
        android_compat_exports(
            &count
        );

    for (int i = 0;
         i < count;
         ++i) {

        if (!exports[i].name)
            continue;

        if (name == exports[i].name)
            return true;
    }

    return false;
}
