#pragma once

#include <solder.h>
#include <string>

const solder_export_t* android_compat_exports(int* count);

bool android_compat_has_export(const std::string& name);

extern "C" void* gn_android_mmap(void* addr, size_t length, int prot, int flags, int fd, int64_t offset);
extern "C" int gn_android_munmap(void* addr, size_t length);
