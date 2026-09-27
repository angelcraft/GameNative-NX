#include <switch.h>
#include <solder.h>

#include <cstdio>
#include <cstring>
#include <dirent.h>
#include <sys/stat.h>
#include <string>
#include <elf.h>
#include <cstdint>

namespace {

constexpr const char* kRoot =
    "sdmc:/switch/gamenative_nx";

constexpr const char* kNativeDir =
    "sdmc:/switch/gamenative_nx/native/arm64-v8a";

constexpr const char* kRuntimeDir =
    "sdmc:/switch/gamenative_nx/runtime";

constexpr const char* kGamesDir =
    "sdmc:/switch/gamenative_nx/games";

constexpr const char* kLog =
    "sdmc:/switch/gamenative_nx/debug.log";

bool exists(const char* path) {
    struct stat st{};
    return stat(path, &st) == 0;
}

size_t count_entries(const char* dir_path, const char* suffix) {
    DIR* dir = opendir(dir_path);
    if (!dir)
        return 0;

    size_t count = 0;

    while (dirent* e = readdir(dir)) {
        if (e->d_type != DT_REG)
            continue;

        const char* dot = std::strrchr(e->d_name, '.');

        if (dot && std::strcmp(dot, suffix) == 0)
            ++count;
    }

    closedir(dir);
    return count;
}

void append_log(const char* message) {
    FILE* f = std::fopen(kLog, "a");
    if (!f)
        return;

    std::fprintf(f, "%s\n", message);
    std::fclose(f);
}

void append_logf(const char* fmt, const char* a) {
    FILE* f = std::fopen(kLog, "a");
    if (!f)
        return;

    std::fprintf(f, fmt, a);
    std::fprintf(f, "\n");
    std::fclose(f);
}

std::string hex_addr(void* ptr) {
    char buffer[32];

    std::snprintf(
        buffer,
        sizeof(buffer),
        "0x%llx",
        static_cast<unsigned long long>(
            reinterpret_cast<uintptr_t>(ptr)
        )
    );

    return std::string(buffer);
}

void draw_header() {
    std::printf("\x1b[1;1H\x1b[2J");

    std::printf(
        "============================================================\n"
    );

    std::printf(
        "                 GameNative NX 0.2.0                        \n"
    );

    std::printf(
        "============================================================\n\n"
    );
}

bool init_solder() {
    const int flags = SOLDER_NO_NRO_EXPORTS;

    if (solder_init(flags) != 0) {
        append_log("libsolder: initialization failed");
        return false;
    }

    if (solder_set_main_exports(
            solder_default_exports,
            solder_num_default_exports) != 0) {

        append_log(
            "libsolder: failed to install default exports"
        );

        solder_quit();
        return false;
    }

    if (solder_add_search_path(kNativeDir) != 0) {
        append_log(
            "libsolder: failed to add native search path"
        );

        solder_quit();
        return false;
    }

    append_log("libsolder: initialized");
    return true;
}

bool inspect_needed(
    const char* path,
    std::string& result
) {
    result.clear();

    FILE* fp = std::fopen(path, "rb");

    if (!fp) {
        result = "FILE OPEN FAILED";
        return false;
    }

    Elf64_Ehdr ehdr{};

    if (std::fread(
            &ehdr,
            1,
            sizeof(ehdr),
            fp) != sizeof(ehdr)) {

        std::fclose(fp);
        result = "ELF HEADER READ FAILED";
        return false;
    }

    if (ehdr.e_ident[EI_MAG0] != ELFMAG0 ||
        ehdr.e_ident[EI_MAG1] != ELFMAG1 ||
        ehdr.e_ident[EI_MAG2] != ELFMAG2 ||
        ehdr.e_ident[EI_MAG3] != ELFMAG3) {

        std::fclose(fp);
        result = "NOT AN ELF FILE";
        return false;
    }

    if (ehdr.e_ident[EI_CLASS] != ELFCLASS64) {
        std::fclose(fp);
        result = "NOT ELF64";
        return false;
    }

    if (ehdr.e_machine != EM_AARCH64) {
        std::fclose(fp);
        result = "NOT AARCH64";
        return false;
    }

    if (ehdr.e_phnum == 0) {
        std::fclose(fp);
        result = "NO PROGRAM HEADERS";
        return false;
    }

    Elf64_Phdr* phdrs =
        new Elf64_Phdr[ehdr.e_phnum];

    if (std::fseek(
            fp,
            static_cast<long>(ehdr.e_phoff),
            SEEK_SET) != 0) {

        delete[] phdrs;
        std::fclose(fp);
        result = "PROGRAM HEADER SEEK FAILED";
        return false;
    }

    if (std::fread(
            phdrs,
            sizeof(Elf64_Phdr),
            ehdr.e_phnum,
            fp) != ehdr.e_phnum) {

        delete[] phdrs;
        std::fclose(fp);
        result = "PROGRAM HEADER READ FAILED";
        return false;
    }

    Elf64_Dyn* dynamic = nullptr;
    size_t dynamic_count = 0;

    for (int i = 0; i < ehdr.e_phnum; ++i) {
        if (phdrs[i].p_type != PT_DYNAMIC)
            continue;

        dynamic_count =
            phdrs[i].p_filesz / sizeof(Elf64_Dyn);

        if (dynamic_count == 0)
            break;

        dynamic =
            new Elf64_Dyn[dynamic_count];

        if (std::fseek(
                fp,
                static_cast<long>(phdrs[i].p_offset),
                SEEK_SET) != 0) {

            delete[] dynamic;
            delete[] phdrs;
            std::fclose(fp);

            result =
                "DYNAMIC SECTION SEEK FAILED";

            return false;
        }

        if (std::fread(
                dynamic,
                sizeof(Elf64_Dyn),
                dynamic_count,
                fp) != dynamic_count) {

            delete[] dynamic;
            delete[] phdrs;
            std::fclose(fp);

            result =
                "DYNAMIC SECTION READ FAILED";

            return false;
        }

        break;
    }

    if (!dynamic) {
        delete[] phdrs;
        std::fclose(fp);

        result = "NO PT_DYNAMIC";
        return false;
    }

    Elf64_Addr strtab_va = 0;
    size_t needed_count = 0;

    for (size_t i = 0; i < dynamic_count; ++i) {
        if (dynamic[i].d_tag == DT_STRTAB) {
            strtab_va =
                dynamic[i].d_un.d_ptr;
        }
        else if (dynamic[i].d_tag == DT_NEEDED) {
            ++needed_count;
        }
    }

    if (!strtab_va) {
        delete[] dynamic;
        delete[] phdrs;
        std::fclose(fp);

        result = "DT_STRTAB NOT FOUND";
        return false;
    }

    auto va_to_offset =
        [&](Elf64_Addr va, Elf64_Off& out) -> bool {

        for (int i = 0; i < ehdr.e_phnum; ++i) {
            const Elf64_Phdr& ph =
                phdrs[i];

            if (ph.p_type != PT_LOAD)
                continue;

            if (va >= ph.p_vaddr &&
                va < ph.p_vaddr + ph.p_filesz) {

                out =
                    ph.p_offset +
                    (va - ph.p_vaddr);

                return true;
            }
        }

        return false;
    };

    Elf64_Off strtab_offset = 0;

    if (!va_to_offset(
            strtab_va,
            strtab_offset)) {

        delete[] dynamic;
        delete[] phdrs;
        std::fclose(fp);

        result =
            "CANNOT MAP DT_STRTAB";

        return false;
    }

    result +=
        "DT_NEEDED (" +
        std::to_string(needed_count) +
        "):\n";

    for (size_t i = 0;
         i < dynamic_count;
         ++i) {

        if (dynamic[i].d_tag != DT_NEEDED)
            continue;

        Elf64_Off name_offset =
            strtab_offset +
            dynamic[i].d_un.d_val;

        if (std::fseek(
                fp,
                static_cast<long>(name_offset),
                SEEK_SET) != 0) {

            result +=
                "  <seek failed>\n";

            continue;
        }

        std::string name;
        char c = 0;

        while (
            name.size() < 1024 &&
            std::fread(&c, 1, 1, fp) == 1 &&
            c != '\0') {

            name += c;
        }

        result += "  ";

        if (name.empty())
            result += "<empty>";
        else
            result += name;

        result += "\n";
    }

    delete[] dynamic;
    delete[] phdrs;
    std::fclose(fp);

    return true;
}

void probe_winlator(std::string& result) {
    result.clear();

    std::printf(
        "\nProbing libwinlator.so...\n"
    );

    consoleUpdate(nullptr);

    const int flags =
        SOLDER_LAZY |
        SOLDER_NO_AUTOLOAD;

    void* handle =
        solder_dlopen(
            "libwinlator.so",
            flags
        );

    const char* err =
        solder_dlerror();

    if (!handle) {
        result =
            "LOAD FAILED\n";

        result +=
            err
                ? err
                : "(no error text)";

        append_logf(
            "libwinlator.so probe failed: %s",
            err
                ? err
                : "(no error text)"
        );

        return;
    }

    void* base =
        solder_get_base_addr(handle);

    void* text =
        solder_get_text_addr(handle);

    result +=
        "ELF LOAD OK\n";

    result +=
        "base: " +
        hex_addr(base) +
        "\n";

    result +=
        "text: " +
        hex_addr(text) +
        "\n\n";

    std::string needed;

    const bool needed_ok =
        inspect_needed(
            "sdmc:/switch/gamenative_nx/native/arm64-v8a/libwinlator.so",
            needed
        );

    if (needed_ok) {
        result += needed;

        append_log(
            "libwinlator.so dependencies:"
        );

        append_log(
            needed.c_str()
        );
    }
    else {
        result +=
            "DEPENDENCY INSPECTION FAILED\n";

        result += needed;

        append_logf(
            "libwinlator.so dependency inspection failed: %s",
            needed.c_str()
        );
    }

    append_log(
        "libwinlator.so probe: "
        "ELF load succeeded (lazy/no-autoload)"
    );

    solder_dlclose(handle);

    const char* close_err =
        solder_dlerror();

    if (close_err) {
        result +=
            "\nclose: ";

        result += close_err;

        append_logf(
            "libwinlator.so close: %s",
            close_err
        );
    }
}

} // namespace

int main(int /*argc*/, char** /*argv*/) {
    consoleInit(nullptr);
    socketInitializeDefault();

    mkdir(kRoot, 0777);

    append_log(
        "GameNative NX 0.2.0 started"
    );

    const bool solder_ok =
        init_solder();

    PadState pad;

    padConfigureInput(
        1,
        HidNpadStyleSet_NpadStandard
    );

    padInitializeDefault(&pad);

    bool probed = false;
    std::string probe_result;

    while (appletMainLoop()) {
        draw_header();

        std::printf(
            "This build adds the FIRST REAL loader stage.\n"
        );

        std::printf(
            "It uses libsolder to inspect the original "
            "Android ARM64 .so.\n\n"
        );

        std::printf(
            "[1] Project root     : %s\n",
            exists(kRoot)
                ? "FOUND"
                : "MISSING"
        );

        std::printf(
            "[2] ARM64 native dir : %s\n",
            exists(kNativeDir)
                ? "FOUND"
                : "MISSING"
        );

        std::printf(
            "[3] Runtime dir      : %s\n",
            exists(kRuntimeDir)
                ? "FOUND"
                : "MISSING"
        );

        std::printf(
            "[4] Games dir        : %s\n",
            exists(kGamesDir)
                ? "FOUND"
                : "MISSING"
        );

        std::printf(
            "[5] Android .so      : %zu file(s)\n",
            count_entries(
                kNativeDir,
                ".so"
            )
        );

        std::printf(
            "[6] libsolder        : %s\n",
            solder_ok
                ? "READY"
                : "FAILED"
        );

        std::printf(
            "\n------------------------------------------------------------\n"
        );

        std::printf(
            "Controls:\n"
        );

        std::printf(
            "  A      Probe libwinlator.so (lazy ELF load)\n"
        );

        std::printf(
            "  +      Exit\n"
        );

        std::printf(
            "------------------------------------------------------------\n"
        );

        if (solder_ok && !probed) {
            std::printf(
                "\nPut libwinlator.so in:\n%s\n",
                kNativeDir
            );

            std::printf(
                "then press A.\n"
            );
        }

        if (probed) {
            std::printf(
                "\n============================================================\n"
            );

            std::printf(
                "                    PROBE RESULT\n"
            );

            std::printf(
                "============================================================\n"
            );

            std::printf(
                "%s\n",
                probe_result.c_str()
            );
        }

        consoleUpdate(nullptr);

        padUpdate(&pad);

        const u64 buttons =
            padGetButtonsDown(&pad);

        if ((buttons & HidNpadButton_Plus) != 0)
            break;

        if ((buttons & HidNpadButton_A) != 0 &&
            solder_ok &&
            !probed) {

            probe_winlator(probe_result);
            probed = true;
        }

        svcSleepThread(
            16'000'000ULL
        );
    }

    if (solder_ok)
        solder_quit();

    socketExit();
    consoleExit(nullptr);

    return 0;
}
