#include <switch.h>
#include <solder.h>

#include <cstdio>
#include <cstring>
#include <dirent.h>
#include <sys/stat.h>
#include <string>

namespace {
constexpr const char* kRoot = "sdmc:/switch/gamenative_nx";
constexpr const char* kNativeDir = "sdmc:/switch/gamenative_nx/native/arm64-v8a";
constexpr const char* kRuntimeDir = "sdmc:/switch/gamenative_nx/runtime";
constexpr const char* kGamesDir = "sdmc:/switch/gamenative_nx/games";
constexpr const char* kLog = "sdmc:/switch/gamenative_nx/debug.log";

bool exists(const char* path) {
    struct stat st{};
    return stat(path, &st) == 0;
}

size_t count_entries(const char* dir_path, const char* suffix) {
    DIR* dir = opendir(dir_path);
    if (!dir) return 0;

    size_t count = 0;
    while (dirent* e = readdir(dir)) {
        if (e->d_type != DT_REG) continue;
        const char* dot = std::strrchr(e->d_name, '.');
        if (dot && std::strcmp(dot, suffix) == 0) ++count;
    }

    closedir(dir);
    return count;
}

void append_log(const char* message) {
    FILE* f = std::fopen(kLog, "a");
    if (!f) return;
    std::fprintf(f, "%s\n", message);
    std::fclose(f);
}

void append_logf(const char* fmt, const char* a) {
    FILE* f = std::fopen(kLog, "a");
    if (!f) return;
    std::fprintf(f, fmt, a);
    std::fprintf(f, "\n");
    std::fclose(f);
}

void draw_header() {
    std::printf("\x1b[1;1H\x1b[2J");
    std::printf("============================================================\n");
    std::printf("                 GameNative NX 0.2.0                        \n");
    std::printf("============================================================\n\n");
}

bool init_solder() {
    // Use libsolder's built-in libc/newlib export table for the first
    // compatibility pass. Android/Bionic exports will be added later.
    const int flags = SOLDER_NO_NRO_EXPORTS;
    if (solder_init(flags) != 0) {
        append_log("libsolder: initialization failed");
        return false;
    }

    if (solder_set_main_exports(solder_default_exports, solder_num_default_exports) != 0) {
        append_log("libsolder: failed to install default exports");
        solder_quit();
        return false;
    }

    // libsolder searches paths in reverse order. A single explicit path
    // keeps the first probe deterministic.
    if (solder_add_search_path(kNativeDir) != 0) {
        append_log("libsolder: failed to add native search path");
        solder_quit();
        return false;
    }

    append_log("libsolder: initialized");
    return true;
}

void probe_winlator() {
    std::printf("\n[ A ] Probing libwinlator.so with libsolder...\n");

    // LAZY is intentional: we want to prove that the ELF loader can ingest
    // the Android AArch64 shared object without running its Android-dependent
    // initializers yet. We do not pretend this makes it executable on Switch.
    void* handle = solder_dlopen("libwinlator.so", SOLDER_LAZY);
    const char* err = solder_dlerror();

    if (!handle) {
        std::printf("      LOAD FAILED\n");
        std::printf("      %s\n", err ? err : "(no error text)");
        append_logf("libwinlator.so probe failed: %s", err ? err : "(no error text)");
        return;
    }

    void* base = solder_get_base_addr(handle);
    void* text = solder_get_text_addr(handle);

    std::printf("      ELF LOAD OK\n");
    std::printf("      base: %p\n", base);
    std::printf("      text: %p\n", text);
    append_log("libwinlator.so probe: ELF load succeeded (lazy mode)");

    solder_dlclose(handle);
    const char* close_err = solder_dlerror();
    if (close_err) append_logf("libwinlator.so close: %s", close_err);
}
}

int main(int /*argc*/, char** /*argv*/) {
    consoleInit(nullptr);
    socketInitializeDefault();

    mkdir(kRoot, 0777);
    append_log("GameNative NX 0.2.0 started");

    const bool solder_ok = init_solder();

    PadState pad;
    padConfigureInput(1, HidNpadStyleSet_NpadStandard);
    padInitializeDefault(&pad);
    bool probed = false;
    while (appletMainLoop()) {
        draw_header();

        std::printf("This build adds the FIRST REAL loader stage.\n");
        std::printf("It uses libsolder to inspect the original Android ARM64 .so.\n\n");

        std::printf("[1] Project root     : %s\n", exists(kRoot) ? "FOUND" : "MISSING");
        std::printf("[2] ARM64 native dir : %s\n", exists(kNativeDir) ? "FOUND" : "MISSING");
        std::printf("[3] Runtime dir      : %s\n", exists(kRuntimeDir) ? "FOUND" : "MISSING");
        std::printf("[4] Games dir        : %s\n", exists(kGamesDir) ? "FOUND" : "MISSING");
        std::printf("[5] Android .so      : %zu file(s)\n", count_entries(kNativeDir, ".so"));
        std::printf("[6] libsolder        : %s\n", solder_ok ? "READY" : "FAILED");

        std::printf("\n------------------------------------------------------------\n");
        std::printf("Controls:\n");
        std::printf("  A      Probe libwinlator.so (lazy ELF load)\n");
        std::printf("  +      Exit\n");
        std::printf("------------------------------------------------------------\n");

        if (solder_ok && !probed) {
            std::printf("\nPut libwinlator.so in:\n%s\n", kNativeDir);
            std::printf("then press A.\n");
        }

        consoleUpdate(nullptr);

        padUpdate(&pad);
        const u64 buttons = padGetButtonsDown(&pad);

        if ((buttons & HidNpadButton_Plus) != 0) break;
        if ((buttons & HidNpadButton_A) != 0 && solder_ok) {
            probe_winlator();
            probed = true;
            svcSleepThread(500'000'000ULL);
        }

        svcSleepThread(16'000'000ULL);
    }

    if (solder_ok) solder_quit();
    socketExit();
    consoleExit(nullptr);
    return 0;
}
