#pragma once

#include <solder.h>
#include <string>

const solder_export_t* android_compat_exports(int* count);

bool android_compat_has_export(const std::string& name);
