#pragma once

#include <solder.h>
#include <string>
#include <pthread.h>

const solder_export_t* android_compat_exports(int* count);

bool android_compat_has_export(const std::string& name);

extern "C" void* gn_android_mmap(void* addr, size_t length, int prot, int flags, int fd, int64_t offset);
extern "C" int gn_android_munmap(void* addr, size_t length);

// Android compatibility wrappers used directly by the V35 bootstrap probe.
// Their definitions remain in android_compat.cpp and use C linkage.
extern "C" int gn_android_pthread_detach(pthread_t thread);
extern "C" int gn_android_pthread_mutex_init(pthread_mutex_t* mutex, const pthread_mutexattr_t* attr);
extern "C" int gn_android_pthread_cond_init(pthread_cond_t* cond, const pthread_condattr_t* attr);
