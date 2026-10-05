#include "android_compat.hpp"
#include <switch.h>

#include <poll.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/time.h>
#include <unistd.h>

#include <dirent.h>
#include <fcntl.h>
#include <locale.h>
#include <signal.h>
#include <pthread.h>
#include <time.h>
#include <wctype.h>

#include <cerrno>
#include <cstdint>
#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cwchar>
#include <cmath>

#ifndef GN_CMSG_ALIGN
#define GN_CMSG_ALIGN(len) \
    (((len) + sizeof(size_t) - 1) & ~(sizeof(size_t) - 1))
#endif

namespace {

void gn_eventfd_diag(const char* fmt, ...) {
    FILE* f = std::fopen("sdmc:/switch/gamenative_nx/debug.log", "a");
    va_list ap;
    va_start(ap, fmt);
    std::vprintf(fmt, ap);
    va_end(ap);

    if (!f)
        return;

    va_start(ap, fmt);
    std::vfprintf(f, fmt, ap);
    va_end(ap);
    std::fclose(f);
}

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

extern "C" ssize_t gn_android_eventfd_read(
    int fd,
    void* buf,
    size_t count
);

extern "C" ssize_t gn_android_eventfd_write(
    int fd,
    const void* buf,
    size_t count
);

extern "C" ssize_t gn_android_read_chk(
    int fd,
    void* buf,
    size_t count,
    size_t /*buflen*/
) {
    return gn_android_eventfd_read(fd, buf, count);
}

extern "C" ssize_t gn_android_write_chk(
    int fd,
    const void* buf,
    size_t count,
    size_t /*buflen*/
) {
    return gn_android_eventfd_write(fd, buf, count);
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
    if (!msg || !msg->msg_control)
        return nullptr;

    const size_t alignment = sizeof(size_t);

    auto align_len = [alignment](size_t len) -> size_t {
        return (len + alignment - 1) &
               ~(alignment - 1);
    };

    unsigned char* base =
        static_cast<unsigned char*>(
            msg->msg_control
        );

    unsigned char* end =
        base + msg->msg_controllen;

    if (!cmsg) {
        if (base + sizeof(struct cmsghdr) > end)
            return nullptr;

        return reinterpret_cast<struct cmsghdr*>(base);
    }

    unsigned char* current =
        reinterpret_cast<unsigned char*>(cmsg);

    if (current < base ||
        current + sizeof(struct cmsghdr) > end) {

        return nullptr;
    }

    if (cmsg->cmsg_len < sizeof(struct cmsghdr))
        return nullptr;

    unsigned char* next =
        current + align_len(cmsg->cmsg_len);

    if (next + sizeof(struct cmsghdr) > end)
        return nullptr;

    struct cmsghdr* next_hdr =
        reinterpret_cast<struct cmsghdr*>(next);

    if (next_hdr->cmsg_len < sizeof(struct cmsghdr))
        return nullptr;

    if (next + next_hdr->cmsg_len > end)
        return nullptr;

    return next_hdr;
}



// ============================================================================
// mmap / munmap / eventfd compatibility
// ============================================================================
//
// mmap/munmap are still resolution-only placeholders.
//
// eventfd cannot be implemented with Linux's eventfd syscall on Switch, and
// libnx's socketpair(AF_UNIX, ...) is not available in the current runtime
// (DIAG_V7 observed errno 88 / ENOTSOCK).  Instead we use a small in-process
// eventfd shim with synthetic positive descriptors.
//
// The synthetic descriptors are handled by:
//   - eventfd()          -> allocates a shim and returns a fake fd
//   - read/write         -> operate on the shim's 64-bit counter
//   - close()            -> releases the shim
//   - epoll_wait()       -> treats a non-zero counter as EPOLLIN
//
// This is intentionally a compatibility bridge.  It implements the parts
// needed by Winlator's synchronization paths without pretending to be a
// kernel-perfect Linux eventfd implementation.
//

// Vortek's RingBuffer uses mmap(MAP_SHARED) only as backing storage for
// producer/consumer state. In the current GameNative-NX architecture both
// endpoints are inside the same Horizon process, so an aligned heap allocation
// is sufficient and avoids requiring a Linux mmap syscall.
struct GnCompatMapping {
    void* base = nullptr;
    size_t size = 0;
};

constexpr size_t kMaxGnCompatMappings = 128;
static GnCompatMapping g_gn_compat_mappings[kMaxGnCompatMappings];
static pthread_mutex_t g_gn_compat_mmap_mutex = PTHREAD_MUTEX_INITIALIZER;

static size_t gn_align_page(size_t n) {
    constexpr size_t page = 0x1000;
    if (n > SIZE_MAX - (page - 1))
        return 0;
    return (n + page - 1) & ~(page - 1);
}

extern "C" void* gn_android_mmap(
    void* /*addr*/,
    size_t length,
    int /*prot*/,
    int /*flags*/,
    int /*fd*/,
    int64_t offset
) {
    if (length == 0 || offset < 0 || static_cast<uint64_t>(offset) > SIZE_MAX - length) {
        errno = EINVAL;
        return reinterpret_cast<void*>(-1);
    }

    const size_t total = gn_align_page(length + static_cast<size_t>(offset));
    if (total == 0) {
        errno = EOVERFLOW;
        return reinterpret_cast<void*>(-1);
    }

    void* memory = nullptr;
    const int rc = ::posix_memalign(&memory, 0x1000, total);
    if (rc != 0 || !memory) {
        errno = ENOMEM;
        return reinterpret_cast<void*>(-1);
    }

    std::memset(memory, 0, total);

    pthread_mutex_lock(&g_gn_compat_mmap_mutex);
    for (size_t i = 0; i < kMaxGnCompatMappings; ++i) {
        if (!g_gn_compat_mappings[i].base) {
            g_gn_compat_mappings[i].base = memory;
            g_gn_compat_mappings[i].size = total;
            pthread_mutex_unlock(&g_gn_compat_mmap_mutex);
            return static_cast<uint8_t*>(memory) + static_cast<size_t>(offset);
        }
    }
    pthread_mutex_unlock(&g_gn_compat_mmap_mutex);

    ::free(memory);
    errno = ENOMEM;
    return reinterpret_cast<void*>(-1);
}

extern "C" int gn_android_munmap(
    void* addr,
    size_t length
) {
    (void)length;
    if (!addr) {
        errno = EINVAL;
        return -1;
    }

    pthread_mutex_lock(&g_gn_compat_mmap_mutex);
    for (size_t i = 0; i < kMaxGnCompatMappings; ++i) {
        GnCompatMapping& mapping = g_gn_compat_mappings[i];
        if (!mapping.base)
            continue;

        const uintptr_t begin = reinterpret_cast<uintptr_t>(mapping.base);
        const uintptr_t end = begin + mapping.size;
        const uintptr_t p = reinterpret_cast<uintptr_t>(addr);

        if (p >= begin && p < end) {
            ::free(mapping.base);
            mapping = {};
            pthread_mutex_unlock(&g_gn_compat_mmap_mutex);
            return 0;
        }
    }
    pthread_mutex_unlock(&g_gn_compat_mmap_mutex);

    errno = EINVAL;
    return -1;
}

constexpr size_t kMaxEventFdShims = 16;
constexpr int kAndroidEfdNonblock = 0x00000800;
constexpr int kAndroidEfdSemaphore = 0x00000001;
constexpr uint64_t kEventFdMax = UINT64_MAX - 1;

// Keep synthetic descriptors well outside the normal libnx fd range.
constexpr int kFirstSyntheticEventFd = 0x40000000;

struct EventFdShim {
    bool used = false;
    int fake_fd = -1;
    uint64_t counter = 0;
    int flags = 0;
};

static EventFdShim g_eventfd_shims[kMaxEventFdShims];
static pthread_mutex_t g_eventfd_mutex = PTHREAD_MUTEX_INITIALIZER;

EventFdShim* find_eventfd_shim(int fd) {
    for (size_t i = 0; i < kMaxEventFdShims; ++i) {
        if (g_eventfd_shims[i].used &&
            g_eventfd_shims[i].fake_fd == fd) {
            return &g_eventfd_shims[i];
        }
    }

    return nullptr;
}

EventFdShim* allocate_eventfd_shim() {
    for (size_t i = 0; i < kMaxEventFdShims; ++i) {
        if (!g_eventfd_shims[i].used)
            return &g_eventfd_shims[i];
    }

    return nullptr;
}

int eventfd_synthetic_fd(size_t index) {
    return kFirstSyntheticEventFd + static_cast<int>(index);
}

extern "C" int gn_android_eventfd(
    unsigned int initval,
    int flags
) {
    gn_eventfd_diag(
        "[GameNative NX] eventfd: DIAG_V8 enter initval=%u flags=0x%x\n",
        initval,
        static_cast<unsigned int>(flags)
    );

    if (flags &
        ~(kAndroidEfdNonblock | kAndroidEfdSemaphore)) {

        gn_eventfd_diag(
            "[GameNative NX] eventfd: unsupported flags=0x%x\n",
            static_cast<unsigned int>(flags)
        );
        errno = EINVAL;
        return -1;
    }

    pthread_mutex_lock(&g_eventfd_mutex);

    EventFdShim* shim = allocate_eventfd_shim();
    if (!shim) {
        pthread_mutex_unlock(&g_eventfd_mutex);
        gn_eventfd_diag(
            "[GameNative NX] eventfd: no free shim slots\n"
        );
        errno = EMFILE;
        return -1;
    }

    const size_t index =
        static_cast<size_t>(shim - g_eventfd_shims);

    shim->used = true;
    shim->fake_fd = eventfd_synthetic_fd(index);
    shim->counter = initval;
    shim->flags = flags;

    const int result_fd = shim->fake_fd;

    pthread_mutex_unlock(&g_eventfd_mutex);

    gn_eventfd_diag(
        "[GameNative NX] eventfd: SUCCESS synthetic_fd=%d counter=%llu\n",
        result_fd,
        static_cast<unsigned long long>(initval)
    );

    return result_fd;
}

extern "C" ssize_t gn_android_eventfd_read(
    int fd,
    void* buf,
    size_t count
) {
    if (!buf) {
        errno = EFAULT;
        return -1;
    }

    pthread_mutex_lock(&g_eventfd_mutex);

    EventFdShim* shim = find_eventfd_shim(fd);
    if (!shim) {
        pthread_mutex_unlock(&g_eventfd_mutex);
        return ::read(fd, buf, count);
    }

    if (count != sizeof(uint64_t)) {
        pthread_mutex_unlock(&g_eventfd_mutex);
        errno = EINVAL;
        return -1;
    }

    if (shim->counter == 0) {
        const bool nonblock =
            (shim->flags & kAndroidEfdNonblock) != 0;
        pthread_mutex_unlock(&g_eventfd_mutex);

        // Blocking eventfd reads are not yet backed by a wait queue.  Return
        // EAGAIN for both modes so a caller cannot hang the Switch process.
        (void)nonblock;
        errno = EAGAIN;
        return -1;
    }

    uint64_t value;
    if (shim->flags & kAndroidEfdSemaphore) {
        value = 1;
        --shim->counter;
    } else {
        value = shim->counter;
        shim->counter = 0;
    }

    pthread_mutex_unlock(&g_eventfd_mutex);

    std::memcpy(buf, &value, sizeof(value));
    return static_cast<ssize_t>(sizeof(value));
}

extern "C" ssize_t gn_android_eventfd_write(
    int fd,
    const void* buf,
    size_t count
) {
    if (!buf) {
        errno = EFAULT;
        return -1;
    }

    pthread_mutex_lock(&g_eventfd_mutex);

    EventFdShim* shim = find_eventfd_shim(fd);
    if (!shim) {
        pthread_mutex_unlock(&g_eventfd_mutex);
        return ::write(fd, buf, count);
    }

    if (count != sizeof(uint64_t)) {
        pthread_mutex_unlock(&g_eventfd_mutex);
        errno = EINVAL;
        return -1;
    }

    uint64_t value;
    std::memcpy(&value, buf, sizeof(value));

    if (value == UINT64_MAX ||
        shim->counter > (kEventFdMax - value)) {

        pthread_mutex_unlock(&g_eventfd_mutex);
        errno = EAGAIN;
        return -1;
    }

    shim->counter += value;

    pthread_mutex_unlock(&g_eventfd_mutex);

    return static_cast<ssize_t>(sizeof(value));
}

extern "C" int gn_android_close(
    int fd
) {
    pthread_mutex_lock(&g_eventfd_mutex);

    EventFdShim* shim = find_eventfd_shim(fd);
    if (!shim) {
        pthread_mutex_unlock(&g_eventfd_mutex);
        return ::close(fd);
    }

    *shim = {};
    pthread_mutex_unlock(&g_eventfd_mutex);

    return 0;
}

// ============================================================================
// Dynamic-loader compatibility
// ============================================================================
//
// Android code expects the POSIX/Bionic dlopen/dlsym/dlclose API.  On Switch,
// libsolder is the loader we use for the imported ARM64 ELF objects, so these
// wrappers translate the familiar API onto libsolder rather than attempting
// to use a host/Android libdl implementation.
//
// We deliberately use SOLDER_NO_AUTOLOAD here.  The Android system libraries
// referenced by the APK are represented by our main export table instead of
// real .so files on the SD card.  Preventing automatic dependency loading
// keeps that model consistent while still allowing bundled GameNative .so
// files to be opened explicitly.
//
extern "C" void* gn_android_dlopen(
    const char* filename,
    int flags
) {
    if (!filename) {
        errno = EINVAL;
        return nullptr;
    }

    int solder_flags = SOLDER_NO_AUTOLOAD;

    // RTLD_LAZY == 0x1 on the Android/Linux ABI.
    if (flags & 0x1)
        solder_flags |= SOLDER_LAZY;

    return solder_dlopen(
        filename,
        solder_flags
    );
}

extern "C" void* gn_android_dlsym(
    void* handle,
    const char* symbol
) {
    if (!handle || !symbol) {
        errno = EINVAL;
        return nullptr;
    }

    return solder_dlsym(
        handle,
        symbol
    );
}

extern "C" int gn_android_dlclose(
    void* handle
) {
    if (!handle) {
        errno = EINVAL;
        return -1;
    }

    return solder_dlclose(handle);
}

extern "C" const char* gn_android_dlerror() {
    return solder_dlerror();
}


// ============================================================================
// Additional libc compatibility
// ============================================================================

extern "C" long gn_android_strtol(
    const char* nptr,
    char** endptr,
    int base
) {
    return std::strtol(
        nptr,
        endptr,
        base
    );
}

extern "C" size_t gn_android_strlen_chk(
    const char* str,
    size_t /*maxlen*/
) {
    if (!str) {
        errno = EINVAL;
        return 0;
    }

    return std::strlen(str);
}

extern "C" size_t gn_android_fwrite_chk(
    const void* ptr,
    size_t size,
    size_t count,
    FILE* stream,
    size_t /*buflen*/
) {
    if (!stream) {
        errno = EINVAL;
        return 0;
    }

    return std::fwrite(
        ptr,
        size,
        count,
        stream
    );
}


// ============================================================================
// pthread compatibility
// ============================================================================

extern "C" int gn_android_pthread_create(
    pthread_t* thread,
    const pthread_attr_t* attr,
    void* (*start_routine)(void*),
    void* arg
) {
    return ::pthread_create(
        thread,
        attr,
        start_routine,
        arg
    );
}

extern "C" int gn_android_pthread_join(
    pthread_t thread,
    void** retval
) {
    return ::pthread_join(
        thread,
        retval
    );
}

extern "C" pthread_t gn_android_pthread_self() {
    return ::pthread_self();
}



// ============================================================================
// Android logging compatibility
// ============================================================================
//
// __android_log_print() is used by libxconnectorpatch.so during its
// initialization/relocation path. For now we keep it side-effect free on
// Switch and only consume the arguments so the Android log import is valid.
//
// Later this can be redirected to debug.log with Android-style priorities.

extern "C" int gn_android_log_print(
    int /*priority*/,
    const char* /*tag*/,
    const char* /*fmt*/,
    ...
) {
    return 0;
}


// ============================================================================
// Batch libc / POSIX compatibility
// ============================================================================

extern "C" char* gn_android_getenv(const char* name) {
    if (!name) { errno = EINVAL; return nullptr; }
    return std::getenv(name);
}

extern "C" int gn_android_setenv(const char* name, const char* value, int overwrite) {
    if (!name || !value) { errno = EINVAL; return -1; }
    return ::setenv(name, value, overwrite);
}

extern "C" int gn_android_unsetenv(const char* name) {
    if (!name) { errno = EINVAL; return -1; }
    return ::unsetenv(name);
}

extern "C" int gn_android_system_property_get(const char* name, char* value) {
    if (!name || !value) {
        errno = EINVAL;
        return 0;
    }

    value[0] = '\0';

    // These properties describe the architecture we are actually exposing
    // from this Switch port.  Unknown Android properties are treated as absent
    // instead of inventing device/build information.
    if (std::strcmp(name, "ro.product.cpu.abi") == 0 ||
        std::strcmp(name, "ro.product.cpu.abilist64") == 0 ||
        std::strcmp(name, "ro.product.cpu.abilist") == 0) {
        std::strcpy(value, "arm64-v8a");
        return 9;
    }

    return 0;
}

extern "C" unsigned long gn_android_getauxval(unsigned long type) {
    constexpr unsigned long AT_PAGESZ = 6;
    constexpr unsigned long AT_HWCAP = 16;
    constexpr unsigned long AT_HWCAP2 = 26;
    constexpr unsigned long AT_SECURE = 23;
    switch (type) {
        case AT_PAGESZ: return 0x1000UL;
        case AT_HWCAP:
        case AT_HWCAP2:
        case AT_SECURE:
        default: return 0;
    }
}

extern "C" int gn_android_getpagesize() { return 0x1000; }

extern "C" int gn_android_mprotect(void* addr, size_t length, int prot) {
    if (!addr || length == 0) {
        errno = EINVAL;
        return -1;
    }

    constexpr int PROT_READ_GN = 0x1;
    constexpr int PROT_WRITE_GN = 0x2;
    constexpr int PROT_EXEC_GN = 0x4;

    if (prot & PROT_EXEC_GN) {
        // Horizon's process memory permission syscall does not allow X here.
        errno = ENOTSUP;
        return -1;
    }

    constexpr uintptr_t kPageMask = 0xFFF;
    uintptr_t start = reinterpret_cast<uintptr_t>(addr);
    uintptr_t page_start = start & ~kPageMask;
    uintptr_t page_end = (start + length + kPageMask) & ~kPageMask;
    if (page_end < page_start) {
        errno = EOVERFLOW;
        return -1;
    }

    u32 permission = Perm_None;
    if (prot & PROT_READ_GN)
        permission |= Perm_R;
    if (prot & PROT_WRITE_GN)
        permission |= Perm_W;

    Result rc = svcSetMemoryPermission(
        reinterpret_cast<void*>(page_start),
        static_cast<u64>(page_end - page_start),
        permission
    );

    if (R_FAILED(rc)) {
        errno = EACCES;
        return -1;
    }

    return 0;
}

extern "C" long gn_android_sysconf(int name) {
#ifdef _SC_PAGESIZE
    if (name == _SC_PAGESIZE) return 0x1000;
#endif
#ifdef _SC_PAGE_SIZE
    if (name == _SC_PAGE_SIZE) return 0x1000;
#endif
#ifdef _SC_NPROCESSORS_ONLN
    if (name == _SC_NPROCESSORS_ONLN) return 4;
#endif
#ifdef _SC_NPROCESSORS_CONF
    if (name == _SC_NPROCESSORS_CONF) return 4;
#endif
#ifdef _SC_CLK_TCK
    if (name == _SC_CLK_TCK) return 100;
#endif
    errno = EINVAL;
    return -1;
}

extern "C" int gn_android_getpid() { return 1; }
extern "C" unsigned int gn_android_getuid() { return 0; }
extern "C" unsigned int gn_android_getgid() { return 0; }

extern "C" int gn_android_open_2(const char* path, int flags) {
    return ::open(path, flags, 0666);
}

extern "C" int gn_android_openat(int dirfd, const char* path, int flags, ...) {
    // newlib/libnx does not provide openat(2).  Support the common Android
    // case (AT_FDCWD) by falling back to open(2); reject true dirfd-relative
    // paths until we have a dedicated path translation layer.
    if (dirfd != AT_FDCWD) {
        errno = ENOSYS;
        return -1;
    }

    mode_t mode = 0666;
    if (flags & O_CREAT) {
        va_list ap;
        va_start(ap, flags);
        mode = static_cast<mode_t>(va_arg(ap, int));
        va_end(ap);
    }
    return ::open(path, flags, mode);
}

extern "C" int gn_android_fcntl(int fd, int cmd, ...) {
    va_list ap;
    va_start(ap, cmd);
    long arg = 0;
    // Commands that do not consume a third argument are common in Android
    // code.  Passing no third argument would require command-by-command
    // knowledge, so we conservatively provide a zero-sized slot; on AArch64
    // the ABI uses the same general-purpose register width for the vararg.
    arg = va_arg(ap, long);
    va_end(ap);
    return ::fcntl(fd, cmd, arg);
}

extern "C" int gn_android_access(const char* path, int mode) {
    return ::access(path, mode);
}
extern "C" int gn_android_mkdir(const char* path, mode_t mode) {
    return ::mkdir(path, mode);
}
extern "C" int gn_android_rename(const char* old_path, const char* new_path) {
    return ::rename(old_path, new_path);
}
extern "C" int gn_android_remove(const char* path) {
    return ::remove(path);
}
extern "C" int gn_android_fchmod(int fd, mode_t mode) {
    return ::fchmod(fd, mode);
}
extern "C" int gn_android_fchmodat(int dirfd, const char* path, mode_t mode, int flags) {
    if (dirfd != AT_FDCWD || flags != 0) {
        errno = ENOSYS;
        return -1;
    }
    return ::chmod(path, mode);
}
extern "C" int gn_android_unlinkat(int dirfd, const char* path, int flags) {
    if (dirfd != AT_FDCWD || flags != 0) {
        errno = ENOSYS;
        return -1;
    }
    return ::unlink(path);
}
extern "C" int gn_android_truncate(const char* path, off_t length) {
    return ::truncate(path, length);
}
extern "C" int gn_android_utimensat(int dirfd, const char* path, const struct timespec times[2], int flags) {
    (void)dirfd;
    (void)path;
    (void)times;
    (void)flags;
    errno = ENOSYS;
    return -1;
}
extern "C" long gn_android_pathconf(const char* path, int name) {
    return ::pathconf(path, name);
}
extern "C" ssize_t gn_android_readlink(const char* path, char* buf, size_t size) {
    return ::readlink(path, buf, size);
}
extern "C" int gn_android_symlink(const char* target, const char* linkpath) {
    return ::symlink(target, linkpath);
}
extern "C" int gn_android_link(const char* oldpath, const char* newpath) {
    return ::link(oldpath, newpath);
}
extern "C" char* gn_android_realpath(const char* path, char* resolved) {
    return ::realpath(path, resolved);
}
extern "C" DIR* gn_android_opendir(const char* path) { return ::opendir(path); }
extern "C" struct dirent* gn_android_readdir(DIR* dir) { return ::readdir(dir); }
extern "C" int gn_android_closedir(DIR* dir) { return ::closedir(dir); }
extern "C" DIR* gn_android_fdopendir(int /*fd*/) {
    errno = ENOSYS;
    return nullptr;
}

extern "C" int gn_android_fseeko(FILE* stream, off_t offset, int whence) {
    return ::fseeko(stream, offset, whence);
}
extern "C" off_t gn_android_ftello(FILE* stream) { return ::ftello(stream); }
extern "C" int gn_android_ferror(FILE* stream) { return std::ferror(stream); }
extern "C" int gn_android_feof(FILE* stream) { return std::feof(stream); }
extern "C" int gn_android_putchar(int c) { return std::putchar(c); }

extern "C" int gn_android_strerror_r(int errnum, char* buf, size_t buflen) {
    if (!buf || !buflen) { errno = EINVAL; return EINVAL; }
    const char* s = ::strerror(errnum);
    if (!s) s = "Unknown error";
    int n = std::snprintf(buf, buflen, "%s", s);
    if (n < 0) return EINVAL;
    if (static_cast<size_t>(n) >= buflen) return ERANGE;
    return 0;
}

extern "C" int gn_android_dprintf(int fd, const char* fmt, ...) {
    if (!fmt) { errno = EINVAL; return -1; }
    va_list ap;
    va_start(ap, fmt);
    va_list copy;
    va_copy(copy, ap);
    int needed = std::vsnprintf(nullptr, 0, fmt, copy);
    va_end(copy);
    if (needed < 0) { va_end(ap); return -1; }
    size_t size = static_cast<size_t>(needed) + 1;
    char* buf = static_cast<char*>(std::malloc(size));
    if (!buf) { va_end(ap); errno = ENOMEM; return -1; }
    std::vsnprintf(buf, size, fmt, ap);
    va_end(ap);
    ssize_t n = ::write(fd, buf, static_cast<size_t>(needed));
    std::free(buf);
    return n < 0 ? -1 : static_cast<int>(n);
}

extern "C" int gn_android_vsnprintf_chk(char* dst, size_t dst_size, int, size_t obj_size,
                                          const char* fmt, va_list ap) {
    if (!dst || !fmt) { errno = EINVAL; return -1; }
    if (obj_size != static_cast<size_t>(-1) && obj_size < dst_size) dst_size = obj_size;
    if (!dst_size) { errno = ERANGE; return -1; }
    return std::vsnprintf(dst, dst_size, fmt, ap);
}

extern "C" void* gn_android_memcpy_chk(void* dst, const void* src, size_t n, size_t dst_size) {
    if (!dst || !src || n > dst_size) { errno = ERANGE; return nullptr; }
    return std::memcpy(dst, src, n);
}
extern "C" void* gn_android_memset_chk(void* dst, int c, size_t n, size_t dst_size) {
    if (!dst || n > dst_size) { errno = ERANGE; return nullptr; }
    return std::memset(dst, c, n);
}
extern "C" void* gn_android_memmove_chk(void* dst, const void* src, size_t n, size_t dst_size) {
    if (!dst || !src || n > dst_size) { errno = ERANGE; return nullptr; }
    return std::memmove(dst, src, n);
}
extern "C" char* gn_android_strcat_chk(char* dst, const char* src, size_t dst_size) {
    if (!dst || !src) { errno = EINVAL; return nullptr; }
    size_t dl = std::strlen(dst), sl = std::strlen(src);
    if (dl >= dst_size || sl > dst_size - dl - 1) { errno = ERANGE; return nullptr; }
    return std::strcat(dst, src);
}
extern "C" char* gn_android_strchr_chk(const char* str, int ch, size_t maxlen) {
    if (!str) { errno = EINVAL; return nullptr; }
    for (size_t i = 0; i < maxlen; ++i) {
        if (str[i] == static_cast<char>(ch)) return const_cast<char*>(str + i);
        if (str[i] == '\0') break;
    }
    return nullptr;
}
extern "C" char* gn_android_strncpy_chk2(
    char* dst, const char* src, size_t count, size_t dst_size, size_t src_size
) {
    if (!dst || !src || count > dst_size) { errno = ERANGE; return nullptr; }
    if (src_size != static_cast<size_t>(-1)) {
        size_t copy_limit = count < src_size ? count : src_size;
        size_t i = 0;
        for (; i < copy_limit; ++i) {
            dst[i] = src[i];
            if (src[i] == '\0') break;
        }
        if (i == src_size && count > src_size) { errno = ERANGE; return nullptr; }
        for (++i; i < count; ++i) dst[i] = '\0';
        return dst;
    }
    return std::strncpy(dst, src, count);
}

extern "C" const char* gn_android_strstr(const char* a, const char* b) { return std::strstr(a, b); }
extern "C" char* gn_android_strchr2(const char* a, int b) { return const_cast<char*>(std::strchr(a, b)); }
extern "C" char* gn_android_strrchr2(const char* a, int b) { return const_cast<char*>(std::strrchr(a, b)); }
extern "C" size_t gn_android_strcspn(const char* a, const char* b) { return std::strcspn(a, b); }

extern "C" int gn_android_posix_memalign(void** memptr, size_t alignment, size_t size) {
    // Keep this as a resolution-only compatibility shim for now.  libnx's
    // internal aligned allocator has a different ownership/freeing contract,
    // so do not return memory that a normal free() cannot safely release.
    if (!memptr || alignment < sizeof(void*) || (alignment & (alignment - 1)) != 0)
        return EINVAL;
    *memptr = nullptr;
    (void)size;
    return ENOSYS;
}
extern "C" int gn_android_gettimeofday(struct timeval* tv, void* tz) {
    return ::gettimeofday(tv, static_cast<struct timezone*>(tz));
}
extern "C" int gn_android_nanosleep(const struct timespec* req, struct timespec* rem) {
    return ::nanosleep(req, rem);
}

extern "C" long long gn_android_strtoll64(const char* s, char** e, int b) {
    return static_cast<long long>(std::strtol(s, e, b));
}
extern "C" unsigned long long gn_android_strtoull(const char* s, char** e, int b) {
    return static_cast<unsigned long long>(std::strtoul(s, e, b));
}
extern "C" long double gn_android_strtold(const char* s, char** e) {
    return static_cast<long double>(std::strtod(s, e));
}
extern "C" intmax_t gn_android_strtoimax(const char* s, char** e, int b) {
    return static_cast<intmax_t>(std::strtol(s, e, b));
}
extern "C" uintmax_t gn_android_strtoumax(const char* s, char** e, int b) {
    return static_cast<uintmax_t>(std::strtoul(s, e, b));
}
extern "C" long gn_android_wcstol(const wchar_t* s, wchar_t** e, int b) { return ::wcstol(s, e, b); }
extern "C" unsigned long gn_android_wcstoul(const wchar_t* s, wchar_t** e, int b) { return ::wcstoul(s, e, b); }
extern "C" long long gn_android_wcstoll(const wchar_t* s, wchar_t** e, int b) { return static_cast<long long>(::wcstol(s, e, b)); }
extern "C" unsigned long long gn_android_wcstoull(const wchar_t* s, wchar_t** e, int b) { return static_cast<unsigned long long>(::wcstoul(s, e, b)); }
extern "C" long double gn_android_wcstold(const wchar_t* s, wchar_t** e) { return static_cast<long double>(::wcstod(s, e)); }
extern "C" long long gn_android_strtoll_l(const char* s, char** e, int b, locale_t) {
    return gn_android_strtoll64(s, e, b);
}
extern "C" unsigned long long gn_android_strtoull_l(const char* s, char** e, int b, locale_t) {
    return gn_android_strtoull(s, e, b);
}
extern "C" long double gn_android_strtold_l(const char* s, char** e, locale_t) {
    return gn_android_strtold(s, e);
}
extern "C" long long gn_android_wcstoll_l(const wchar_t* s, wchar_t** e, int b, locale_t) {
    return gn_android_wcstoll(s, e, b);
}
extern "C" unsigned long long gn_android_wcstoull_l(const wchar_t* s, wchar_t** e, int b, locale_t) {
    return gn_android_wcstoull(s, e, b);
}
extern "C" long double gn_android_wcstold_l(const wchar_t* s, wchar_t** e, locale_t) {
    return gn_android_wcstold(s, e);
}

extern "C" int gn_android_swprintf(wchar_t* dst, size_t count, const wchar_t* fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    int r = ::vswprintf(dst, count, fmt, ap);
    va_end(ap);
    return r;
}

extern "C" int gn_android_vasprintf(char** out, const char* fmt, va_list ap) {
    if (!out || !fmt) { errno = EINVAL; return -1; }
    va_list copy;
    va_copy(copy, ap);
    int needed = std::vsnprintf(nullptr, 0, fmt, copy);
    va_end(copy);
    if (needed < 0) return -1;
    char* buf = static_cast<char*>(std::malloc(static_cast<size_t>(needed) + 1));
    if (!buf) { errno = ENOMEM; return -1; }
    std::vsnprintf(buf, static_cast<size_t>(needed) + 1, fmt, ap);
    *out = buf;
    return needed;
}

extern "C" int gn_android_asprintf(char** out, const char* fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    int r = gn_android_vasprintf(out, fmt, ap);
    va_end(ap);
    return r;
}

extern "C" void* gn_android_android_dlopen_ext(const char* filename, int flags, const void*) {
    return gn_android_dlopen(filename, flags);
}
extern "C" void gn_android_set_abort_message(const char*) {}
extern "C" void gn_android_openlog(const char*, int, int) {}
extern "C" void gn_android_closelog() {}
extern "C" void gn_android_syslog(int, const char*, ...) {}
extern "C" void gn_android_assert2(const char*, int, const char*, const char*) { std::abort(); }
extern "C" int gn_android_cxa_thread_atexit_impl(void (*)(void*), void*, void*) { return 0; }

static int g_dummy_locale_storage = 0;
static thread_local locale_t g_current_locale = nullptr;
extern "C" locale_t gn_android_newlocale(int, const char*, locale_t) {
    return reinterpret_cast<locale_t>(&g_dummy_locale_storage);
}
extern "C" locale_t gn_android_uselocale(locale_t loc) {
    locale_t prev = g_current_locale;
    if (loc) g_current_locale = loc;
    return prev;
}
extern "C" void gn_android_freelocale(locale_t) {}
extern "C" int gn_android_strcoll_l(const char* a, const char* b, locale_t) { return std::strcmp(a, b); }
extern "C" size_t gn_android_strxfrm_l(char* d, const char* s, size_t n, locale_t) {
    size_t len = std::strlen(s);
    if (n) { size_t c = len < n - 1 ? len : n - 1; std::memcpy(d, s, c); d[c] = '\0'; }
    return len;
}
extern "C" int gn_android_wcscoll_l(const wchar_t* a, const wchar_t* b, locale_t) { return std::wcscmp(a, b); }
extern "C" size_t gn_android_wcsxfrm_l(wchar_t* d, const wchar_t* s, size_t n, locale_t) {
    size_t len = std::wcslen(s);
    if (n) { size_t c = len < n - 1 ? len : n - 1; std::wmemcpy(d, s, c); d[c] = L'\0'; }
    return len;
}
extern "C" size_t gn_android_strftime_l(char* d, size_t n, const char* f, const struct tm* t, locale_t) { return ::strftime(d, n, f, t); }
extern "C" int gn_android_iswalpha_l(wint_t c, locale_t) { return ::iswalpha(c); }
extern "C" int gn_android_iswblank_l(wint_t c, locale_t) { return ::iswblank(c); }
extern "C" int gn_android_iswcntrl_l(wint_t c, locale_t) { return ::iswcntrl(c); }
extern "C" int gn_android_iswdigit_l(wint_t c, locale_t) { return ::iswdigit(c); }
extern "C" int gn_android_iswlower_l(wint_t c, locale_t) { return ::iswlower(c); }
extern "C" int gn_android_iswprint_l(wint_t c, locale_t) { return ::iswprint(c); }
extern "C" int gn_android_iswpunct_l(wint_t c, locale_t) { return ::iswpunct(c); }
extern "C" int gn_android_iswspace_l(wint_t c, locale_t) { return ::iswspace(c); }
extern "C" int gn_android_iswupper_l(wint_t c, locale_t) { return ::iswupper(c); }
extern "C" int gn_android_iswxdigit_l(wint_t c, locale_t) { return ::iswxdigit(c); }
extern "C" wint_t gn_android_towupper_l(wint_t c, locale_t) { return ::towupper(c); }
extern "C" wint_t gn_android_towlower_l(wint_t c, locale_t) { return ::towlower(c); }
extern "C" size_t gn_android_mbrlen(const char* s, size_t n, mbstate_t* ps) { return ::mbrlen(s, n, ps); }
extern "C" size_t gn_android_mbsrtowcs(wchar_t* d, const char** s, size_t n, mbstate_t* ps) { return ::mbsrtowcs(d, s, n, ps); }
extern "C" size_t gn_android_mbsnrtowcs(wchar_t* d, const char** s, size_t m, size_t n, mbstate_t* ps) { return ::mbsnrtowcs(d, s, m, n, ps); }
extern "C" size_t gn_android_wcsnrtombs(char* d, const wchar_t** s, size_t m, size_t n, mbstate_t* ps) { return ::wcsnrtombs(d, s, m, n, ps); }
extern "C" size_t gn_android_mbtowc(wchar_t* d, const char* s, size_t n) { return ::mbtowc(d, s, n); }
extern "C" size_t gn_android_ctype_get_mb_cur_max() { return 1; }
extern "C" struct lconv* gn_android_localeconv() { return ::localeconv(); }

extern "C" int gn_android_pthread_mutex_init(pthread_mutex_t* m, const pthread_mutexattr_t* a) { return ::pthread_mutex_init(m, a); }
extern "C" int gn_android_pthread_mutex_destroy(pthread_mutex_t* m) { return ::pthread_mutex_destroy(m); }
extern "C" int gn_android_pthread_mutex_trylock(pthread_mutex_t* m) { return ::pthread_mutex_trylock(m); }
extern "C" int gn_android_pthread_mutexattr_init(pthread_mutexattr_t* a) { return ::pthread_mutexattr_init(a); }
extern "C" int gn_android_pthread_mutexattr_settype(pthread_mutexattr_t* a, int t) { return ::pthread_mutexattr_settype(a, t); }
extern "C" int gn_android_pthread_mutexattr_destroy(pthread_mutexattr_t* a) { return ::pthread_mutexattr_destroy(a); }
extern "C" int gn_android_pthread_cond_init(pthread_cond_t* c, const pthread_condattr_t* a) { return ::pthread_cond_init(c, a); }
extern "C" int gn_android_pthread_cond_destroy(pthread_cond_t* c) { return ::pthread_cond_destroy(c); }
extern "C" int gn_android_pthread_cond_signal(pthread_cond_t* c) { return ::pthread_cond_signal(c); }
extern "C" int gn_android_pthread_cond_timedwait(pthread_cond_t* c, pthread_mutex_t* m, const struct timespec* t) { return ::pthread_cond_timedwait(c, m, t); }
extern "C" int gn_android_pthread_condattr_init(pthread_condattr_t* a) { return ::pthread_condattr_init(a); }
extern "C" int gn_android_pthread_condattr_setclock(pthread_condattr_t* a, clockid_t id) { return ::pthread_condattr_setclock(a, id); }
extern "C" int gn_android_pthread_condattr_destroy(pthread_condattr_t* a) { return ::pthread_condattr_destroy(a); }
extern "C" int gn_android_pthread_detach(pthread_t t) { return ::pthread_detach(t); }
extern "C" int gn_android_pthread_rwlock_init(pthread_rwlock_t* l, const pthread_rwlockattr_t* a) { return ::pthread_rwlock_init(l, a); }
extern "C" int gn_android_pthread_rwlock_destroy(pthread_rwlock_t* l) { return ::pthread_rwlock_destroy(l); }
extern "C" int gn_android_pthread_rwlock_rdlock(pthread_rwlock_t* l) { return ::pthread_rwlock_rdlock(l); }
extern "C" int gn_android_pthread_rwlock_wrlock(pthread_rwlock_t* l) { return ::pthread_rwlock_wrlock(l); }
extern "C" int gn_android_pthread_rwlock_unlock(pthread_rwlock_t* l) { return ::pthread_rwlock_unlock(l); }
extern "C" int gn_android_vfprintf(FILE* f, const char* fmt, va_list ap) { return ::vfprintf(f, fmt, ap); }
extern "C" int gn_android_vsscanf(const char* s, const char* fmt, va_list ap) { return ::vsscanf(s, fmt, ap); }


// ============================================================================
// Resolution-only placeholders for remaining Android/system imports
// ============================================================================
//
// IMPORTANT:
// These functions only make the ELF imports resolve during the static
// compatibility pass. They are NOT real implementations of the Android,
// EGL/GLES, Vulkan, or C++ runtime APIs.
//
// Do not call them yet. A later step will replace these with real shims.
//
// ============================================================================
// Additional libc compatibility symbols discovered by relocation smoke tests.
// ============================================================================

extern "C" int gn_android_alphasort(
    const struct dirent** a,
    const struct dirent** b
) {
    if (!a || !b || !*a || !*b) {
        errno = EINVAL;
        return 0;
    }
    return std::strcmp((*a)->d_name, (*b)->d_name);
}

extern "C" int gn_android_sigaction(
    int /*signum*/,
    const struct sigaction* /*act*/,
    struct sigaction* /*oldact*/
) {
    errno = ENOSYS;
    return -1;
}

extern "C" void gn_android_sincos(
    double x,
    double* s,
    double* c
) {
    if (s)
        *s = std::sin(x);
    if (c)
        *c = std::cos(x);
}

// Android/Bionic exports optarg as an OBJECT.
extern "C" char* gn_android_optarg = nullptr;

// Resolution-only compatibility object for Bionic's __sF FILE array.
extern "C" FILE gn_android_sF[3] = {};



// Additional libc imports surfaced by the latest relocation smoke test.
// These are intentionally conservative compatibility shims for now.
extern "C" int gn_android_fork() {
    errno = ENOSYS;
    return -1;
}

extern "C" char* gn_android_ctime_r(const time_t* t, char* buf) {
    if (!t || !buf) {
        errno = EINVAL;
        return nullptr;
    }

    const char* text = ::ctime(t);
    if (!text)
        return nullptr;

    std::memcpy(buf, text, 26);
    buf[26] = '\0';
    return buf;
}

extern "C" int gn_android_optind = 1;

// Resolution-only compatibility object for libc's stderr variable.
// Keep it valid enough for relocation; runtime stdio semantics come later.
extern "C" FILE* gn_android_stderr = nullptr;

extern "C" int gn_android_ioctl(int /*fd*/, unsigned long /*request*/, ...) {
    errno = ENOSYS;
    return -1;
}

extern "C" char* gn_android_basename(char* path) {
    if (!path || !*path)
        return path;

    char* end = path + std::strlen(path);
    while (end > path && end[-1] == '/')
        --end;

    if (end == path)
        return path;

    char* p = end;
    while (p > path && p[-1] != '/')
        --p;

    return p;
}


// More libc imports surfaced by the relocation smoke test.
// These start as conservative compatibility shims so relocation can proceed.
extern "C" char** gn_android_environ = nullptr;
extern "C" FILE* gn_android_stdout = nullptr;

extern "C" pid_t gn_android_waitpid(pid_t /*pid*/, int* /*status*/, int /*options*/) {
    errno = ENOSYS;
    return -1;
}

extern "C" int gn_android_ppoll(
    struct pollfd* fds,
    nfds_t nfds,
    const struct timespec* timeout,
    const sigset_t* /*sigmask*/
) {
    int timeout_ms = -1;
    if (timeout) {
        if (timeout->tv_sec < 0 || timeout->tv_nsec < 0 || timeout->tv_nsec >= 1000000000L) {
            errno = EINVAL;
            return -1;
        }
        long long ms = static_cast<long long>(timeout->tv_sec) * 1000LL;
        ms += (timeout->tv_nsec + 999999L) / 1000000L;
        if (ms > 2147483647LL)
            timeout_ms = 2147483647;
        else
            timeout_ms = static_cast<int>(ms);
    }
    return ::poll(fds, nfds, timeout_ms);
}

extern "C" float gn_android_wcstof(const wchar_t* nptr, wchar_t** endptr) {
    if (!nptr) {
        errno = EINVAL;
        return 0.0f;
    }
    return static_cast<float>(std::wcstod(nptr, endptr));
}

extern "C" char* gn_android_dirname(char* path) {
    if (!path || !*path)
        return path;

    char* end = path + std::strlen(path);
    while (end > path && end[-1] == '/')
        --end;

    if (end == path)
        return path;

    char* p = end;
    while (p > path && p[-1] != '/')
        --p;

    if (p == path)
        return path;

    char* slash_end = p - 1;
    while (slash_end > path && slash_end[-1] == '/')
        --slash_end;

    *slash_end = '\0';
    return path;
}

extern "C" uintptr_t gn_android_unimplemented(...) {
    errno = ENOSYS;
    return 0;
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

    // The epoll shim uses native poll() for real descriptors, but synthetic
    // eventfd descriptors are handled entirely in-process.
    pollfd poll_fds[kMaxEpollWatches];
    EpollWatch* watch_map[kMaxEpollWatches];

    for (;;) {
        gn_epoll_event* out_events =
            static_cast<gn_epoll_event*>(events_ptr);

        int output_count = 0;
        int poll_count = 0;

        for (int i = 0;
             i < kMaxEpollWatches;
             ++i) {

            EpollWatch& watch =
                ep->watches[i];

            if (!watch.used)
                continue;

            if (find_eventfd_shim(watch.fd)) {
                bool ready = false;

                pthread_mutex_lock(&g_eventfd_mutex);
                EventFdShim* shim =
                    find_eventfd_shim(watch.fd);

                if (shim &&
                    shim->counter != 0 &&
                    (watch.events & (
                        GN_EPOLLIN |
                        GN_EPOLLRDNORM |
                        GN_EPOLLPRI))) {
                    ready = true;
                }

                pthread_mutex_unlock(&g_eventfd_mutex);

                if (ready &&
                    output_count < maxevents) {

                    gn_epoll_event out =
                        watch.user_event;

                    out.events = 0;
                    if (watch.events & (
                            GN_EPOLLIN |
                            GN_EPOLLRDNORM)) {
                        out.events |= GN_EPOLLIN;
                    }
                    if (watch.events & GN_EPOLLPRI) {
                        out.events |= GN_EPOLLPRI;
                    }

                    out_events[output_count++] =
                        out;
                }

                continue;
            }

            if (poll_count >= kMaxEpollWatches)
                break;

            poll_fds[poll_count] = {};
            poll_fds[poll_count].fd = watch.fd;
            poll_fds[poll_count].events =
                epoll_to_poll_events(watch.events);
            watch_map[poll_count] = &watch;
            ++poll_count;
        }

        if (output_count > 0)
            return output_count;

        int slice_ms = 0;

        if (timeout < 0) {
            slice_ms = 10;
        } else if (timeout == 0) {
            slice_ms = 0;
        } else {
            slice_ms = timeout < 10 ? timeout : 10;
        }

        const int ready =
            ::poll(
                poll_count > 0 ? poll_fds : nullptr,
                static_cast<nfds_t>(poll_count),
                slice_ms
            );

        if (ready < 0)
            return -1;

        if (ready > 0) {
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

                out_events[output_count++] =
                    out;
            }

            if (output_count > 0)
                return output_count;
        }

        if (timeout == 0)
            return 0;

        if (timeout > 0) {
            timeout -= slice_ms;
            if (timeout <= 0)
                return 0;
        }
    }
}


// ============================================================================
// Bulk resolution placeholders discovered by the complete symbol inventory.
//
// IMPORTANT: these exports are for the relocation/inventory phase only. They
// make symbols visible to libsolder so we can move from one-missing-symbol-at-a
// time to targeted runtime testing. Functions that are actually exercised by
// GameNative must later be replaced with real Switch-compatible implementations.
// ============================================================================

extern "C" unsigned char gn_android_in6addr_any[16] = {0};
extern "C" unsigned char gn_android_in6addr_loopback[16] = {
    0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 1
};

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
        "close",
        (void*)&gn_android_close
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
        "read",
        (void*)&gn_android_eventfd_read
    ),

    SOLDER_EXPORT(
        "write",
        (void*)&gn_android_eventfd_write
    ),

    SOLDER_EXPORT(
        "__vsprintf_chk",
        (void*)&gn_android_vsprintf_chk
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

    // Relocation-discovered libc symbols.
    SOLDER_EXPORT("alphasort", (void*)&gn_android_alphasort),
    SOLDER_EXPORT("sigaction", (void*)&gn_android_sigaction),
    SOLDER_EXPORT("sincos", (void*)&gn_android_sincos),
    SOLDER_EXPORT("optarg", (void*)&gn_android_optarg),
    SOLDER_EXPORT("__sF", (void*)gn_android_sF),
    SOLDER_EXPORT("stderr", (void*)&gn_android_stderr),
    SOLDER_EXPORT("fork", (void*)&gn_android_fork),
    SOLDER_EXPORT("ctime_r", (void*)&gn_android_ctime_r),
    SOLDER_EXPORT("optind", (void*)&gn_android_optind),
    SOLDER_EXPORT("ioctl", (void*)&gn_android_ioctl),
    SOLDER_EXPORT("basename", (void*)&gn_android_basename),
    SOLDER_EXPORT("environ", (void*)&gn_android_environ),
    SOLDER_EXPORT("waitpid", (void*)&gn_android_waitpid),
    SOLDER_EXPORT("ppoll", (void*)&gn_android_ppoll),
    SOLDER_EXPORT("stdout", (void*)&gn_android_stdout),
    SOLDER_EXPORT("wcstof", (void*)&gn_android_wcstof),
    SOLDER_EXPORT("dirname", (void*)&gn_android_dirname),

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


    // mmap / munmap / eventfd are required by libwinlator.so as well.
    SOLDER_EXPORT("mmap", (void*)&gn_android_mmap),
    SOLDER_EXPORT("munmap", (void*)&gn_android_munmap),
    SOLDER_EXPORT("eventfd", (void*)&gn_android_eventfd),

    // Dynamic loader API used by libwinlator_11.so.
    SOLDER_EXPORT("dlopen", (void*)&gn_android_dlopen),
    SOLDER_EXPORT("dlsym", (void*)&gn_android_dlsym),
    SOLDER_EXPORT("dlclose", (void*)&gn_android_dlclose),
    SOLDER_EXPORT("dlerror", (void*)&gn_android_dlerror),

    // Additional libc / fortify helpers used by libwinlator_11.so.
    SOLDER_EXPORT("strtol", (void*)&gn_android_strtol),
    SOLDER_EXPORT("__strlen_chk", (void*)&gn_android_strlen_chk),
    SOLDER_EXPORT("__fwrite_chk", (void*)&gn_android_fwrite_chk),

    // pthread entry points used by libwinlator_11.so.
    SOLDER_EXPORT("pthread_create", (void*)&gn_android_pthread_create),
    SOLDER_EXPORT("pthread_join", (void*)&gn_android_pthread_join),
    SOLDER_EXPORT("pthread_self", (void*)&gn_android_pthread_self),

    SOLDER_EXPORT("__android_log_print", (void*)&gn_android_log_print),
    SOLDER_EXPORT("__system_property_get", (void*)&gn_android_system_property_get),
    SOLDER_EXPORT("__open_2", (void*)&gn_android_open_2),
    SOLDER_EXPORT("openat", (void*)&gn_android_openat),
    SOLDER_EXPORT("fcntl", (void*)&gn_android_fcntl),
    SOLDER_EXPORT("mprotect", (void*)&gn_android_mprotect),
    SOLDER_EXPORT("strtoimax", (void*)&gn_android_strtoimax),
    SOLDER_EXPORT("strtoumax", (void*)&gn_android_strtoumax),
    SOLDER_EXPORT("strtoll_l", (void*)&gn_android_strtoll_l),
    SOLDER_EXPORT("strtoull_l", (void*)&gn_android_strtoull_l),
    SOLDER_EXPORT("strtold_l", (void*)&gn_android_strtold_l),
    SOLDER_EXPORT("wcstoll_l", (void*)&gn_android_wcstoll_l),
    SOLDER_EXPORT("wcstoull_l", (void*)&gn_android_wcstoull_l),
    SOLDER_EXPORT("wcstold_l", (void*)&gn_android_wcstold_l),

    // Batch libc / POSIX compatibility.
    SOLDER_EXPORT("getenv", (void*)&gn_android_getenv),
    SOLDER_EXPORT("setenv", (void*)&gn_android_setenv),
    SOLDER_EXPORT("unsetenv", (void*)&gn_android_unsetenv),
    SOLDER_EXPORT("getauxval", (void*)&gn_android_getauxval),
    SOLDER_EXPORT("getpagesize", (void*)&gn_android_getpagesize),
    SOLDER_EXPORT("sysconf", (void*)&gn_android_sysconf),
    SOLDER_EXPORT("getpid", (void*)&gn_android_getpid),
    SOLDER_EXPORT("getuid", (void*)&gn_android_getuid),
    SOLDER_EXPORT("getgid", (void*)&gn_android_getgid),
    SOLDER_EXPORT("access", (void*)&gn_android_access),
    SOLDER_EXPORT("mkdir", (void*)&gn_android_mkdir),
    SOLDER_EXPORT("rename", (void*)&gn_android_rename),
    SOLDER_EXPORT("remove", (void*)&gn_android_remove),
    SOLDER_EXPORT("fchmod", (void*)&gn_android_fchmod),
    SOLDER_EXPORT("fchmodat", (void*)&gn_android_fchmodat),
    SOLDER_EXPORT("unlinkat", (void*)&gn_android_unlinkat),
    SOLDER_EXPORT("truncate", (void*)&gn_android_truncate),
    SOLDER_EXPORT("utimensat", (void*)&gn_android_utimensat),
    SOLDER_EXPORT("pathconf", (void*)&gn_android_pathconf),
    SOLDER_EXPORT("readlink", (void*)&gn_android_readlink),
    SOLDER_EXPORT("symlink", (void*)&gn_android_symlink),
    SOLDER_EXPORT("link", (void*)&gn_android_link),
    SOLDER_EXPORT("realpath", (void*)&gn_android_realpath),
    SOLDER_EXPORT("opendir", (void*)&gn_android_opendir),
    SOLDER_EXPORT("readdir", (void*)&gn_android_readdir),
    SOLDER_EXPORT("closedir", (void*)&gn_android_closedir),
    SOLDER_EXPORT("fdopendir", (void*)&gn_android_fdopendir),
    SOLDER_EXPORT("fseeko", (void*)&gn_android_fseeko),
    SOLDER_EXPORT("ftello", (void*)&gn_android_ftello),
    SOLDER_EXPORT("ferror", (void*)&gn_android_ferror),
    SOLDER_EXPORT("feof", (void*)&gn_android_feof),
    SOLDER_EXPORT("putchar", (void*)&gn_android_putchar),
    SOLDER_EXPORT("strerror_r", (void*)&gn_android_strerror_r),
    SOLDER_EXPORT("dprintf", (void*)&gn_android_dprintf),
    SOLDER_EXPORT("__vsnprintf_chk", (void*)&gn_android_vsnprintf_chk),
    SOLDER_EXPORT("__memcpy_chk", (void*)&gn_android_memcpy_chk),
    SOLDER_EXPORT("__memset_chk", (void*)&gn_android_memset_chk),
    SOLDER_EXPORT("__memmove_chk", (void*)&gn_android_memmove_chk),
    SOLDER_EXPORT("__strcat_chk", (void*)&gn_android_strcat_chk),
    SOLDER_EXPORT("__strchr_chk", (void*)&gn_android_strchr_chk),
    SOLDER_EXPORT("__strncpy_chk2", (void*)&gn_android_strncpy_chk2),
    SOLDER_EXPORT("strstr", (void*)&gn_android_strstr),
    SOLDER_EXPORT("strchr", (void*)&gn_android_strchr2),
    SOLDER_EXPORT("strrchr", (void*)&gn_android_strrchr2),
    SOLDER_EXPORT("strcspn", (void*)&gn_android_strcspn),
    SOLDER_EXPORT("posix_memalign", (void*)&gn_android_posix_memalign),
    SOLDER_EXPORT("gettimeofday", (void*)&gn_android_gettimeofday),
    SOLDER_EXPORT("nanosleep", (void*)&gn_android_nanosleep),
    SOLDER_EXPORT("strtoll", (void*)&gn_android_strtoll64),
    SOLDER_EXPORT("strtoull", (void*)&gn_android_strtoull),
    SOLDER_EXPORT("strtold", (void*)&gn_android_strtold),
    SOLDER_EXPORT("wcstol", (void*)&gn_android_wcstol),
    SOLDER_EXPORT("wcstoul", (void*)&gn_android_wcstoul),
    SOLDER_EXPORT("wcstoll", (void*)&gn_android_wcstoll),
    SOLDER_EXPORT("wcstoull", (void*)&gn_android_wcstoull),
    SOLDER_EXPORT("wcstold", (void*)&gn_android_wcstold),
    SOLDER_EXPORT("swprintf", (void*)&gn_android_swprintf),
    SOLDER_EXPORT("vasprintf", (void*)&gn_android_vasprintf),
    SOLDER_EXPORT("asprintf", (void*)&gn_android_asprintf),
    SOLDER_EXPORT("vfprintf", (void*)&gn_android_vfprintf),
    SOLDER_EXPORT("vsscanf", (void*)&gn_android_vsscanf),
    SOLDER_EXPORT("android_dlopen_ext", (void*)&gn_android_android_dlopen_ext),
    SOLDER_EXPORT("android_set_abort_message", (void*)&gn_android_set_abort_message),
    SOLDER_EXPORT("openlog", (void*)&gn_android_openlog),
    SOLDER_EXPORT("syslog", (void*)&gn_android_syslog),
    SOLDER_EXPORT("closelog", (void*)&gn_android_closelog),
    SOLDER_EXPORT("__assert2", (void*)&gn_android_assert2),
    SOLDER_EXPORT("__cxa_thread_atexit_impl", (void*)&gn_android_cxa_thread_atexit_impl),
    SOLDER_EXPORT("newlocale", (void*)&gn_android_newlocale),
    SOLDER_EXPORT("uselocale", (void*)&gn_android_uselocale),
    SOLDER_EXPORT("freelocale", (void*)&gn_android_freelocale),
    SOLDER_EXPORT("strcoll_l", (void*)&gn_android_strcoll_l),
    SOLDER_EXPORT("strxfrm_l", (void*)&gn_android_strxfrm_l),
    SOLDER_EXPORT("wcscoll_l", (void*)&gn_android_wcscoll_l),
    SOLDER_EXPORT("wcsxfrm_l", (void*)&gn_android_wcsxfrm_l),
    SOLDER_EXPORT("strftime_l", (void*)&gn_android_strftime_l),
    SOLDER_EXPORT("iswalpha_l", (void*)&gn_android_iswalpha_l),
    SOLDER_EXPORT("iswblank_l", (void*)&gn_android_iswblank_l),
    SOLDER_EXPORT("iswcntrl_l", (void*)&gn_android_iswcntrl_l),
    SOLDER_EXPORT("iswdigit_l", (void*)&gn_android_iswdigit_l),
    SOLDER_EXPORT("iswlower_l", (void*)&gn_android_iswlower_l),
    SOLDER_EXPORT("iswprint_l", (void*)&gn_android_iswprint_l),
    SOLDER_EXPORT("iswpunct_l", (void*)&gn_android_iswpunct_l),
    SOLDER_EXPORT("iswspace_l", (void*)&gn_android_iswspace_l),
    SOLDER_EXPORT("iswupper_l", (void*)&gn_android_iswupper_l),
    SOLDER_EXPORT("iswxdigit_l", (void*)&gn_android_iswxdigit_l),
    SOLDER_EXPORT("towupper_l", (void*)&gn_android_towupper_l),
    SOLDER_EXPORT("towlower_l", (void*)&gn_android_towlower_l),
    SOLDER_EXPORT("mbrlen", (void*)&gn_android_mbrlen),
    SOLDER_EXPORT("mbsrtowcs", (void*)&gn_android_mbsrtowcs),
    SOLDER_EXPORT("mbsnrtowcs", (void*)&gn_android_mbsnrtowcs),
    SOLDER_EXPORT("wcsnrtombs", (void*)&gn_android_wcsnrtombs),
    SOLDER_EXPORT("mbtowc", (void*)&gn_android_mbtowc),
    SOLDER_EXPORT("__ctype_get_mb_cur_max", (void*)&gn_android_ctype_get_mb_cur_max),
    SOLDER_EXPORT("localeconv", (void*)&gn_android_localeconv),
    SOLDER_EXPORT("pthread_mutex_init", (void*)&gn_android_pthread_mutex_init),
    SOLDER_EXPORT("pthread_mutex_destroy", (void*)&gn_android_pthread_mutex_destroy),
    SOLDER_EXPORT("pthread_mutex_trylock", (void*)&gn_android_pthread_mutex_trylock),
    SOLDER_EXPORT("pthread_mutexattr_init", (void*)&gn_android_pthread_mutexattr_init),
    SOLDER_EXPORT("pthread_mutexattr_settype", (void*)&gn_android_pthread_mutexattr_settype),
    SOLDER_EXPORT("pthread_mutexattr_destroy", (void*)&gn_android_pthread_mutexattr_destroy),
    SOLDER_EXPORT("pthread_cond_init", (void*)&gn_android_pthread_cond_init),
    SOLDER_EXPORT("pthread_cond_destroy", (void*)&gn_android_pthread_cond_destroy),
    SOLDER_EXPORT("pthread_cond_signal", (void*)&gn_android_pthread_cond_signal),
    SOLDER_EXPORT("pthread_cond_timedwait", (void*)&gn_android_pthread_cond_timedwait),
    SOLDER_EXPORT("pthread_condattr_init", (void*)&gn_android_pthread_condattr_init),
    SOLDER_EXPORT("pthread_condattr_setclock", (void*)&gn_android_pthread_condattr_setclock),
    SOLDER_EXPORT("pthread_condattr_destroy", (void*)&gn_android_pthread_condattr_destroy),
    SOLDER_EXPORT("pthread_detach", (void*)&gn_android_pthread_detach),
    SOLDER_EXPORT("pthread_rwlock_init", (void*)&gn_android_pthread_rwlock_init),
    SOLDER_EXPORT("pthread_rwlock_destroy", (void*)&gn_android_pthread_rwlock_destroy),
    SOLDER_EXPORT("pthread_rwlock_rdlock", (void*)&gn_android_pthread_rwlock_rdlock),
    SOLDER_EXPORT("pthread_rwlock_wrlock", (void*)&gn_android_pthread_rwlock_wrlock),
    SOLDER_EXPORT("pthread_rwlock_unlock", (void*)&gn_android_pthread_rwlock_unlock),

    // ------------------------------------------------------------------------
    // Resolution-only Android / C++ runtime / graphics placeholders.
    // ------------------------------------------------------------------------
    SOLDER_EXPORT("__cxa_finalize", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("__cxa_atexit", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("__register_atfork", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("__stack_chk_fail", (void*)&gn_android_unimplemented),

    SOLDER_EXPORT("AndroidBitmap_getInfo", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("AndroidBitmap_lockPixels", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("AndroidBitmap_unlockPixels", (void*)&gn_android_unimplemented),

    SOLDER_EXPORT("AHardwareBuffer_getNativeHandle", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("AHardwareBuffer_acquire", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("AHardwareBuffer_allocate", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("AHardwareBuffer_describe", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("AHardwareBuffer_unlock", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("AHardwareBuffer_release", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("AHardwareBuffer_lock", (void*)&gn_android_unimplemented),

    SOLDER_EXPORT("ASharedMemory_create", (void*)&gn_android_unimplemented),

    SOLDER_EXPORT("eglGetNativeClientBufferANDROID", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("eglGetDisplay", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("eglCreateImageKHR", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("eglDestroyImageKHR", (void*)&gn_android_unimplemented),

    SOLDER_EXPORT("glBindTexture", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("glEGLImageTargetTexture2DOES", (void*)&gn_android_unimplemented),

    SOLDER_EXPORT("vkCreateInstance", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("vkEnumeratePhysicalDevices", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("vkEnumerateDeviceExtensionProperties", (void*)&gn_android_unimplemented),

    // Bulk resolution-only exports from complete inventory.
    SOLDER_EXPORT("AAssetDir_close", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("AAssetDir_getNextFileName", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("AAssetManager_fromJava", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("AAssetManager_open", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("AAssetManager_openDir", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("AAsset_close", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("AAsset_getBuffer", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("AAsset_getLength", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("AHardwareBuffer_recvHandleFromUnixSocket", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("ANativeWindow_fromSurface", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("ANativeWindow_release", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("ZSTD_trace_compress_begin", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("ZSTD_trace_compress_end", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("ZSTD_trace_decompress_begin", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("ZSTD_trace_decompress_end", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("__android_log_write", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("__fread_chk", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("__getcwd_chk", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("__gnu_strerror_r", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("__libc_current_sigrtmax", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("__libc_current_sigrtmin", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("__libc_init", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("__readlink_chk", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("__strcpy_chk", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("__strncat_chk", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("__strncpy_chk", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("__strrchr_chk", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("__umask_chk", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("_exit", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("accept4", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("arc4random_buf", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("atof", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("bsearch", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("cbrt", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("chmod", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("clock_getres", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("connect", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("cos", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("dirfd", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("dl_iterate_phdr", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("dladdr", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("dup", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("dup2", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("eglBindAPI", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("eglChooseConfig", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("eglCreateContext", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("eglCreatePbufferSurface", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("eglDestroyContext", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("eglDestroySurface", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("eglGetCurrentContext", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("eglGetCurrentDisplay", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("eglGetError", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("eglGetProcAddress", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("eglInitialize", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("eglMakeCurrent", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("eglQueryString", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("eglTerminate", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("execl", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("execv", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("execvp", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("fchown", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("fmod", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("fpathconf", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("freeaddrinfo", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("frexp", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("fstat64", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("fsync", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("getaddrinfo", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("getegid", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("geteuid", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("getgrgid_r", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("getgrnam", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("getgrnam_r", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("getgroups", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("gethostname", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("getopt_long", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("getpeername", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("getppid", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("getpwnam", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("getpwnam_r", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("getpwuid_r", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("getrlimit", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("getrusage", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("getsockname", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("getsockopt", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("glActiveTexture", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("glAttachShader", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("glBeginQuery", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("glBeginTransformFeedback", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("glBindAttribLocation", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("glBindBuffer", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("glBindBufferBase", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("glBindBufferRange", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("glBindFramebuffer", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("glBindImageTexture", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("glBindSampler", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("glBindTransformFeedback", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("glBindVertexArray", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("glBindVertexBuffer", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("glBlendColor", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("glBlendEquationSeparate", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("glBlendEquationSeparatei", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("glBlendFuncSeparate", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("glBlendFuncSeparatei", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("glBlitFramebuffer", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("glBufferData", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("glBufferSubData", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("glCheckFramebufferStatus", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("glClear", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("glClearBufferfv", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("glClearBufferiv", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("glClearBufferuiv", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("glClearColor", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("glClearDepthf", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("glClearStencil", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("glClientWaitSync", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("glColorMask", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("glColorMaski", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("glCompileShader", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("glCompressedTexSubImage2D", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("glCompressedTexSubImage3D", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("glCopyBufferSubData", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("glCopyImageSubData", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("glCreateProgram", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("glCreateShader", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("glCullFace", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("glDeleteBuffers", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("glDeleteFramebuffers", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("glDeleteProgram", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("glDeleteQueries", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("glDeleteSamplers", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("glDeleteShader", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("glDeleteSync", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("glDeleteTextures", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("glDeleteTransformFeedbacks", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("glDeleteVertexArrays", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("glDepthFunc", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("glDepthMask", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("glDepthRangef", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("glDisable", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("glDisableVertexAttribArray", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("glDisablei", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("glDispatchCompute", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("glDispatchComputeIndirect", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("glDrawArrays", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("glDrawArraysIndirect", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("glDrawArraysInstanced", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("glDrawBuffers", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("glDrawElements", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("glDrawElementsBaseVertex", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("glDrawElementsIndirect", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("glDrawElementsInstanced", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("glDrawElementsInstancedBaseVertex", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("glDrawRangeElements", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("glDrawRangeElementsBaseVertex", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("glEnable", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("glEnableVertexAttribArray", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("glEnablei", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("glEndQuery", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("glEndTransformFeedback", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("glFenceSync", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("glFinish", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("glFlush", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("glFramebufferParameteri", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("glFramebufferTexture", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("glFramebufferTexture2D", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("glFramebufferTextureLayer", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("glFrontFace", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("glGenBuffers", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("glGenFramebuffers", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("glGenQueries", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("glGenSamplers", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("glGenTextures", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("glGenTransformFeedbacks", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("glGenVertexArrays", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("glGetAttribLocation", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("glGetError", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("glGetFloatv", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("glGetIntegeri_v", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("glGetIntegerv", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("glGetMultisamplefv", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("glGetProgramInfoLog", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("glGetProgramResourceIndex", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("glGetProgramiv", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("glGetQueryObjectuiv", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("glGetShaderInfoLog", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("glGetShaderiv", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("glGetString", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("glGetStringi", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("glGetUniformBlockIndex", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("glGetUniformLocation", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("glInvalidateFramebuffer", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("glLineWidth", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("glLinkProgram", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("glMapBufferRange", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("glMemoryBarrier", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("glMinSampleShading", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("glPatchParameteri", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("glPauseTransformFeedback", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("glPixelStorei", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("glPolygonOffset", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("glReadBuffer", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("glReadPixels", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("glResumeTransformFeedback", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("glSampleMaski", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("glSamplerParameterIuiv", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("glSamplerParameterf", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("glSamplerParameteri", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("glScissor", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("glShaderSource", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("glStencilFunc", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("glStencilFuncSeparate", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("glStencilMask", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("glStencilMaskSeparate", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("glStencilOp", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("glStencilOpSeparate", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("glTexBuffer", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("glTexBufferRange", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("glTexImage2D", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("glTexImage3D", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("glTexParameterIuiv", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("glTexParameterf", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("glTexParameteri", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("glTexStorage2D", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("glTexStorage2DMultisample", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("glTexStorage3D", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("glTexStorage3DMultisample", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("glTexSubImage2D", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("glTexSubImage3D", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("glUniform1f", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("glUniform1i", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("glUniform4f", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("glUniform4fv", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("glUniform4uiv", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("glUniformBlockBinding", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("glUnmapBuffer", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("glUseProgram", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("glVertexAttrib1fv", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("glVertexAttrib2fv", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("glVertexAttrib3fv", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("glVertexAttrib4fv", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("glVertexAttribBinding", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("glVertexAttribDivisor", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("glVertexAttribFormat", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("glVertexAttribIFormat", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("glVertexAttribIPointer", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("glVertexAttribPointer", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("glVertexBindingDivisor", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("glViewport", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("gmtime_r", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("inet_ntop", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("inet_pton", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("initgroups", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("isatty", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("isdigit_l", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("islower_l", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("isupper_l", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("isxdigit_l", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("kill", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("ldexp", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("lldiv", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("localtime_r", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("log10", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("log2", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("lseek", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("lseek64", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("lstat64", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("madvise", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("memfd_create", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("mkstemp64", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("mlock", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("modf", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("munlock", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("nl_langinfo", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("perror", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("pipe", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("pipe2", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("posix_fadvise", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("posix_madvise", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("pow", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("prctl", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("pthread_equal", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("pthread_setschedparam", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("pthread_sigmask", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("raise", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("regcomp", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("regexec", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("regfree", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("rmdir", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("scandir", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("sched_get_priority_max", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("sched_get_priority_min", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("sched_yield", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("sem_destroy", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("sem_init", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("sem_post", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("sem_wait", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("sendfile", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("sendto", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("setpriority", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("setresgid", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("setresuid", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("setrlimit", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("setsid", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("setsockopt", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("sigaddset", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("sigdelset", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("sigemptyset", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("sigfillset", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("sigismember", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("signal", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("sigprocmask", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("sin", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("sleep", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("statvfs", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("strcasecmp", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("strlcpy", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("strncasecmp", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("strnlen", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("strpbrk", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("strtod_l", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("timegm", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("tolower_l", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("toupper_l", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("tzset", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("uname", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("usleep", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("vfork", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("vkCmdCopyBufferToImage", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("vkEnumerateInstanceLayerProperties", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("vkMapMemory", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("vkUnmapMemory", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("wcschr", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("wcscpy", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("wcstod", (void*)&gn_android_unimplemented),
    SOLDER_EXPORT("in6addr_any", (void*)gn_android_in6addr_any),
    SOLDER_EXPORT("in6addr_loopback", (void*)gn_android_in6addr_loopback),
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
