#include <switch.h>
#include <solder.h>
#include "android_compat.hpp"

#include <cstdio>
#include <cstring>
#include <dirent.h>
#include <sys/stat.h>
#include <string>
#include <elf.h>
#include <cstdint>
#include <vector>
#include <algorithm>

namespace {

// No-op constructor target used by solder_hook_offset() during diagnosis.
// Keep C linkage-free and plain void() so it can replace a .init_array entry.
static void gn_ctor_noop() {}

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

constexpr size_t kScreenSymbolLimit = 40;

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
constexpr int kMaxMainExports = 4096;

static solder_export_t g_main_exports[kMaxMainExports];
static int g_main_export_count = 0;

bool main_export_exists(const char* name) {
    if (!name)
        return false;

    for (int i = 0; i < g_main_export_count; ++i) {
        if (!g_main_exports[i].name)
            continue;

        if (std::strcmp(name, g_main_exports[i].name) == 0)
            return true;
    }

    return false;
}

bool has_available_export(const std::string& name) {
    return main_export_exists(name.c_str());
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

    // Build ONE export table containing:
    //   1) libsolder's normal Switch/libc exports
    //   2) our Android/POSIX compatibility exports
    //
    // solder_set_main_exports() turns this table into the main module's
    // dynamic symbol table. Relocations in loaded DSOs resolve through this
    // global table.
    g_main_export_count = 0;

    for (int i = 0;
         i < solder_num_default_exports &&
         g_main_export_count < kMaxMainExports;
         ++i) {

        const solder_export_t& exp =
            solder_default_exports[i];

        if (!exp.name || !exp.addr_rx)
            continue;

        if (main_export_exists(exp.name))
            continue;

        g_main_exports[g_main_export_count++] =
            exp;
    }

    int compat_count = 0;

    const solder_export_t* compat_table =
        android_compat_exports(
            &compat_count
        );

    for (int i = 0;
         i < compat_count &&
         g_main_export_count < kMaxMainExports;
         ++i) {

        const solder_export_t& exp =
            compat_table[i];

        if (!exp.name || !exp.addr_rx)
            continue;

        // Keep the first definition if a compatibility name happens to
        // overlap an existing Switch/default export.
        if (main_export_exists(exp.name))
            continue;

        g_main_exports[g_main_export_count++] =
            exp;
    }

    if (g_main_export_count <= 0) {
        append_log(
            "libsolder: combined export table is empty"
        );

        solder_quit();
        return false;
    }

    if (solder_set_main_exports(
            g_main_exports,
            g_main_export_count) != 0) {

        append_log(
            "libsolder: failed to install combined main exports"
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

    char export_log[96];
    std::snprintf(
        export_log,
        sizeof(export_log),
        "libsolder: combined main exports installed: %d",
        g_main_export_count
    );
    append_log(export_log);

    append_log("libsolder: initialized");
    return true;
}

// Translate an ELF virtual address into a file offset.
bool va_to_offset(
    const Elf64_Ehdr& ehdr,
    const Elf64_Phdr* phdrs,
    Elf64_Addr va,
    Elf64_Off& out
) {
    for (int i = 0; i < ehdr.e_phnum; ++i) {
        const Elf64_Phdr& ph = phdrs[i];

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

    Elf64_Off strtab_offset = 0;

    if (!va_to_offset(
            ehdr,
            phdrs,
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

            result += "  <seek failed>\n";
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

bool get_dynamic_info(
    FILE* fp,
    const Elf64_Ehdr& ehdr,
    const Elf64_Phdr* phdrs,
    Elf64_Addr& symtab_va,
    Elf64_Addr& strtab_va,
    Elf64_Addr& hash_va,
    Elf64_Addr& gnu_hash_va,
    Elf64_Xword& syment,
    Elf64_Xword& strsz
) {
    symtab_va = 0;
    strtab_va = 0;
    hash_va = 0;
    gnu_hash_va = 0;
    syment = 0;
    strsz = 0;

    Elf64_Phdr dynamic_ph{};

    bool found_dynamic = false;

    for (int i = 0; i < ehdr.e_phnum; ++i) {
        if (phdrs[i].p_type == PT_DYNAMIC) {
            dynamic_ph = phdrs[i];
            found_dynamic = true;
            break;
        }
    }

    if (!found_dynamic)
        return false;

    const size_t dynamic_count =
        dynamic_ph.p_filesz / sizeof(Elf64_Dyn);

    if (dynamic_count == 0)
        return false;

    if (std::fseek(
            fp,
            static_cast<long>(dynamic_ph.p_offset),
            SEEK_SET) != 0) {

        return false;
    }

    for (size_t i = 0;
         i < dynamic_count;
         ++i) {

        Elf64_Dyn d{};

        if (std::fread(
                &d,
                sizeof(d),
                1,
                fp) != 1) {

            return false;
        }

        switch (d.d_tag) {
            case DT_SYMTAB:
                symtab_va = d.d_un.d_ptr;
                break;

            case DT_STRTAB:
                strtab_va = d.d_un.d_ptr;
                break;

            case DT_HASH:
                hash_va = d.d_un.d_ptr;
                break;

            case DT_GNU_HASH:
                gnu_hash_va = d.d_un.d_ptr;
                break;

            case DT_SYMENT:
                syment = d.d_un.d_val;
                break;

            case DT_STRSZ:
                strsz = d.d_un.d_val;
                break;

            default:
                break;
        }
    }

    return
        symtab_va != 0 &&
        strtab_va != 0 &&
        syment != 0;
}

bool get_sysv_hash_count(
    FILE* fp,
    const Elf64_Ehdr& ehdr,
    const Elf64_Phdr* phdrs,
    Elf64_Addr hash_va,
    size_t& count
) {
    count = 0;

    if (!hash_va)
        return false;

    Elf64_Off hash_offset = 0;

    if (!va_to_offset(
            ehdr,
            phdrs,
            hash_va,
            hash_offset)) {

        return false;
    }

    if (std::fseek(
            fp,
            static_cast<long>(hash_offset),
            SEEK_SET) != 0) {

        return false;
    }

    uint32_t nbucket = 0;
    uint32_t nchain = 0;

    if (std::fread(&nbucket, sizeof(nbucket), 1, fp) != 1 ||
        std::fread(&nchain, sizeof(nchain), 1, fp) != 1) {

        return false;
    }

    if (nbucket == 0 || nchain == 0)
        return false;

    count = nchain;
    return true;
}

bool get_gnu_hash_count(
    FILE* fp,
    const Elf64_Ehdr& ehdr,
    const Elf64_Phdr* phdrs,
    Elf64_Addr gnu_hash_va,
    size_t& count
) {
    count = 0;

    if (!gnu_hash_va)
        return false;

    Elf64_Off hash_offset = 0;

    if (!va_to_offset(
            ehdr,
            phdrs,
            gnu_hash_va,
            hash_offset)) {

        return false;
    }

    if (std::fseek(
            fp,
            static_cast<long>(hash_offset),
            SEEK_SET) != 0) {

        return false;
    }

    uint32_t nbuckets = 0;
    uint32_t symoffset = 0;
    uint32_t bloom_size = 0;
    uint32_t bloom_shift = 0;

    if (std::fread(&nbuckets, sizeof(nbuckets), 1, fp) != 1 ||
        std::fread(&symoffset, sizeof(symoffset), 1, fp) != 1 ||
        std::fread(&bloom_size, sizeof(bloom_size), 1, fp) != 1 ||
        std::fread(&bloom_shift, sizeof(bloom_shift), 1, fp) != 1) {

        return false;
    }

    (void)bloom_shift;

    if (nbuckets == 0 || bloom_size == 0)
        return false;

    // GNU hash bloom filter is 64-bit on ELF64.
    const Elf64_Off buckets_offset =
        hash_offset +
        16 +
        static_cast<Elf64_Off>(bloom_size) * 8;

    if (std::fseek(
            fp,
            static_cast<long>(buckets_offset),
            SEEK_SET) != 0) {

        return false;
    }

    uint32_t max_symbol = 0;

    for (uint32_t i = 0;
         i < nbuckets;
         ++i) {

        uint32_t bucket = 0;

        if (std::fread(
                &bucket,
                sizeof(bucket),
                1,
                fp) != 1) {

            return false;
        }

        if (bucket < symoffset)
            continue;

        if (bucket > max_symbol)
            max_symbol = bucket;
    }

    if (max_symbol < symoffset)
        return true;

    const Elf64_Off chain_offset =
        buckets_offset +
        static_cast<Elf64_Off>(nbuckets) * 4 +
        static_cast<Elf64_Off>(max_symbol - symoffset) * 4;

    if (std::fseek(
            fp,
            static_cast<long>(chain_offset),
            SEEK_SET) != 0) {

        return false;
    }

    uint32_t index = max_symbol;

    for (;;) {
        uint32_t chain = 0;

        if (std::fread(
                &chain,
                sizeof(chain),
                1,
                fp) != 1) {

            return false;
        }

        if (index == UINT32_MAX)
            return false;

        ++index;

        if (chain & 1u)
            break;
    }

    count = index;
    return true;
}

bool get_section_dynsym_count(
    FILE* fp,
    const Elf64_Ehdr& ehdr,
    size_t& count
) {
    count = 0;

    if (ehdr.e_shoff == 0 ||
        ehdr.e_shnum == 0 ||
        ehdr.e_shentsize != sizeof(Elf64_Shdr)) {

        return false;
    }

    if (std::fseek(
            fp,
            static_cast<long>(ehdr.e_shoff),
            SEEK_SET) != 0) {

        return false;
    }

    for (uint16_t i = 0;
         i < ehdr.e_shnum;
         ++i) {

        Elf64_Shdr sh{};

        if (std::fread(
                &sh,
                sizeof(sh),
                1,
                fp) != 1) {

            return false;
        }

        if (sh.sh_type == SHT_DYNSYM &&
            sh.sh_entsize != 0) {

            count =
                static_cast<size_t>(
                    sh.sh_size / sh.sh_entsize
                );

            return count != 0;
        }
    }

    return false;
}

bool inspect_undefined_symbols(
    const char* path,
    std::string& screen_result,
    std::string& full_result
) {
    screen_result.clear();
    full_result.clear();

    FILE* fp = std::fopen(path, "rb");

    if (!fp) {
        screen_result = "SYMBOL FILE OPEN FAILED";
        full_result = screen_result;
        return false;
    }

    Elf64_Ehdr ehdr{};

    if (std::fread(
            &ehdr,
            1,
            sizeof(ehdr),
            fp) != sizeof(ehdr)) {

        std::fclose(fp);
        screen_result = "SYMBOL ELF HEADER READ FAILED";
        full_result = screen_result;
        return false;
    }

    if (ehdr.e_ident[EI_MAG0] != ELFMAG0 ||
        ehdr.e_ident[EI_MAG1] != ELFMAG1 ||
        ehdr.e_ident[EI_MAG2] != ELFMAG2 ||
        ehdr.e_ident[EI_MAG3] != ELFMAG3 ||
        ehdr.e_ident[EI_CLASS] != ELFCLASS64 ||
        ehdr.e_machine != EM_AARCH64) {

        std::fclose(fp);
        screen_result = "SYMBOL ELF FORMAT INVALID";
        full_result = screen_result;
        return false;
    }

    if (ehdr.e_phnum == 0) {
        std::fclose(fp);
        screen_result = "SYMBOL ELF HAS NO PROGRAM HEADERS";
        full_result = screen_result;
        return false;
    }

    Elf64_Phdr* phdrs =
        new Elf64_Phdr[ehdr.e_phnum];

    if (std::fseek(
            fp,
            static_cast<long>(ehdr.e_phoff),
            SEEK_SET) != 0 ||
        std::fread(
            phdrs,
            sizeof(Elf64_Phdr),
            ehdr.e_phnum,
            fp) != ehdr.e_phnum) {

        delete[] phdrs;
        std::fclose(fp);

        screen_result =
            "SYMBOL PROGRAM HEADER READ FAILED";

        full_result = screen_result;
        return false;
    }

    Elf64_Addr symtab_va = 0;
    Elf64_Addr strtab_va = 0;
    Elf64_Addr hash_va = 0;
    Elf64_Addr gnu_hash_va = 0;
    Elf64_Xword syment = 0;
    Elf64_Xword strsz = 0;

    if (!get_dynamic_info(
            fp,
            ehdr,
            phdrs,
            symtab_va,
            strtab_va,
            hash_va,
            gnu_hash_va,
            syment,
            strsz)) {

        delete[] phdrs;
        std::fclose(fp);

        screen_result =
            "DYNAMIC SYMBOL INFO NOT FOUND";

        full_result = screen_result;
        return false;
    }

    if (syment != sizeof(Elf64_Sym)) {
        delete[] phdrs;
        std::fclose(fp);

        screen_result =
            "UNEXPECTED DT_SYMENT";

        full_result = screen_result;
        return false;
    }

    Elf64_Off symtab_offset = 0;
    Elf64_Off strtab_offset = 0;

    if (!va_to_offset(
            ehdr,
            phdrs,
            symtab_va,
            symtab_offset)) {

        delete[] phdrs;
        std::fclose(fp);

        screen_result =
            "CANNOT MAP DT_SYMTAB";

        full_result = screen_result;
        return false;
    }

    if (!va_to_offset(
            ehdr,
            phdrs,
            strtab_va,
            strtab_offset)) {

        delete[] phdrs;
        std::fclose(fp);

        screen_result =
            "CANNOT MAP DT_STRTAB";

        full_result = screen_result;
        return false;
    }

    // Determine dynamic-symbol count.
    size_t symbol_count = 0;

    if (!get_sysv_hash_count(
            fp,
            ehdr,
            phdrs,
            hash_va,
            symbol_count)) {

        get_gnu_hash_count(
            fp,
            ehdr,
            phdrs,
            gnu_hash_va,
            symbol_count
        );
    }

    if (symbol_count == 0) {
        get_section_dynsym_count(
            fp,
            ehdr,
            symbol_count
        );
    }

    if (symbol_count == 0) {
        delete[] phdrs;
        std::fclose(fp);

        screen_result =
            "CANNOT DETERMINE DYNSYM COUNT";

        full_result = screen_result;
        return false;
    }

    size_t undefined_count = 0;
    size_t shown_count = 0;

    full_result =
        "DYNSYM COUNT: " +
        std::to_string(symbol_count) +
        "\n";

    full_result +=
        "UNDEFINED SYMBOLS:\n";

    screen_result =
        "DYNSYM COUNT: " +
        std::to_string(symbol_count) +
        "\n";

    screen_result +=
        "UNDEFINED SYMBOLS:\n";

    for (size_t i = 0;
         i < symbol_count;
         ++i) {

        const Elf64_Off symbol_offset =
            symtab_offset +
            static_cast<Elf64_Off>(i) *
                sizeof(Elf64_Sym);

        if (std::fseek(
                fp,
                static_cast<long>(symbol_offset),
                SEEK_SET) != 0) {

            break;
        }

        Elf64_Sym sym{};

        if (std::fread(
                &sym,
                sizeof(sym),
                1,
                fp) != 1) {

            break;
        }

        if (sym.st_shndx != SHN_UNDEF)
            continue;

        const uint32_t name_offset =
            sym.st_name;

        if (name_offset >= strsz &&
            strsz != 0) {

            continue;
        }

        if (std::fseek(
                fp,
                static_cast<long>(
                    strtab_offset + name_offset
                ),
                SEEK_SET) != 0) {

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

        if (name.empty())
            continue;

        ++undefined_count;

        const unsigned bind =
            ELF64_ST_BIND(sym.st_info);

        const char* bind_name = "OTHER";

        if (bind == STB_GLOBAL)
            bind_name = "GLOBAL";
        else if (bind == STB_WEAK)
            bind_name = "WEAK";
const bool provided =
    has_available_export(name);

std::string line =
    "  [" +
    std::string(bind_name) +
    "] " +
    name +
    "    ";

if (provided)
    line += "DEFAULT";
else
    line += "MISSING";

line += "\n";

        full_result += line;

        if (shown_count < kScreenSymbolLimit) {
            screen_result += line;
            ++shown_count;
        }
    }

    if (undefined_count > kScreenSymbolLimit) {
        screen_result +=
            "  ... ";
        screen_result +=
            std::to_string(
                undefined_count -
                kScreenSymbolLimit
            );
        screen_result +=
            " more in debug.log\n";
    }

    screen_result =
        "UNDEFINED COUNT: " +
        std::to_string(undefined_count) +
        "\n" +
        screen_result;

    full_result =
        "UNDEFINED COUNT: " +
        std::to_string(undefined_count) +
        "\n" +
        full_result;

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

    // IMPORTANT:
    // Keep this probe lazy and do not recursively load dependencies.
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

    // ------------------------------------------------------------
    // DT_NEEDED
    // ------------------------------------------------------------

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

    // ------------------------------------------------------------
    // STATIC UNDEFINED SYMBOL INSPECTION
    // ------------------------------------------------------------

    result += "\n";
    result +=
        "STATIC SYMBOL INSPECTION:\n";

    std::string symbol_screen;
    std::string symbol_full;

    const bool symbols_ok =
        inspect_undefined_symbols(
            "sdmc:/switch/gamenative_nx/native/arm64-v8a/libwinlator.so",
            symbol_screen,
            symbol_full
        );

    if (symbols_ok) {
        result += symbol_screen;

        append_log(
            "libwinlator.so static undefined symbols:"
        );

        append_log(
            symbol_full.c_str()
        );
    }
    else {
        result += symbol_screen;

        append_log(
            "libwinlator.so static symbol inspection failed:"
        );

        append_log(
            symbol_full.c_str()
        );
    }

    append_log(
        "libwinlator.so probe: "
        "ELF load succeeded (lazy/no-autoload)"
    );

    // ------------------------------------------------------------
    // CONTROLLED REAL RELOCATION TEST
    // ------------------------------------------------------------
    //
    // solder_dlsym() on a lazy module forces libsolder to relocate the
    // object and run its initialization code. We deliberately do NOT
    // call the returned function. The exported symbol below is a real
    // function from libwinlator.so and is only used as the trigger.
    //
    append_log(
        "libwinlator.so relocation test: "
        "calling solder_dlsym(createMemoryFd)"
    );

    result +=
        "\nRELOCATION TEST: createMemoryFd\n";

    void* resolved =
        solder_dlsym(
            handle,
            "createMemoryFd"
        );

    const char* dlsym_err =
        solder_dlerror();

    if (resolved) {
        const std::string resolved_text =
            hex_addr(resolved);

        result +=
            "dlsym: SUCCESS\n";

        result +=
            "address: " +
            resolved_text +
            "\n";

        append_logf(
            "libwinlator.so relocation test: "
            "SUCCESS, createMemoryFd=%s",
            resolved_text.c_str()
        );

        // Keep the relocated module alive for this diagnostic run.
        // We intentionally do not dlclose() it immediately, so a
        // successful relocation is not mixed with destructor/fini code.
        return;
    }

    result +=
        "dlsym: FAILED\n";

    result +=
        "error: ";

    result +=
        dlsym_err
            ? dlsym_err
            : "(no error text)";

    result += "\n";

    append_logf(
        "libwinlator.so relocation test: FAILED: %s",
        dlsym_err
            ? dlsym_err
            : "(no error text)"
    );

    // Return to the previously stable state after a clean failure.
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


void probe_winlator_11(std::string& result) {
    result += "\n\n================ LIBWINLATOR_11 ================\n";

    append_log("libvirglrenderer.so probe: starting");

    const int flags =
        SOLDER_LAZY |
        SOLDER_NO_AUTOLOAD;

    void* handle =
        solder_dlopen(
            "libvirglrenderer.so",
            flags
        );

    const char* err = solder_dlerror();

    if (!handle) {
        result += "LOAD FAILED\n";
        result += err ? err : "(no error text)";
        result += "\n";

        append_logf(
            "libvirglrenderer.so probe failed: %s",
            err ? err : "(no error text)"
        );
        return;
    }

    result += "ELF LOAD OK\n";
    result +=
        "base: " +
        hex_addr(solder_get_base_addr(handle)) +
        "\n";
    result +=
        "text: " +
        hex_addr(solder_get_text_addr(handle)) +
        "\n\n";

    std::string needed;
    const bool needed_ok = inspect_needed(
        "sdmc:/switch/gamenative_nx/native/arm64-v8a/libvirglrenderer.so",
        needed
    );

    if (needed_ok) {
        result += needed;
        append_log("libvirglrenderer.so dependencies:");
        append_log(needed.c_str());
    } else {
        result += "DEPENDENCY INSPECTION FAILED\n";
        result += needed;
        append_logf(
            "libvirglrenderer.so dependency inspection failed: %s",
            needed.c_str()
        );
    }

    std::string symbol_screen;
    std::string symbol_full;

    const bool symbols_ok = inspect_undefined_symbols(
        "sdmc:/switch/gamenative_nx/native/arm64-v8a/libvirglrenderer.so",
        symbol_screen,
        symbol_full
    );

    result += "\nSTATIC SYMBOL INSPECTION:\n";
    result += symbol_screen;

    append_log("libvirglrenderer.so static undefined symbols:");
    append_log(symbol_full.c_str());

    append_log(
        "libvirglrenderer.so probe: "
        "ELF load succeeded (lazy/no-autoload)"
    );

    result += "\nRELOCATION TEST: createMemoryFd\n";
    append_log(
        "libvirglrenderer.so relocation test: "
        "calling solder_dlsym(createMemoryFd)"
    );

    void* resolved = solder_dlsym(
        handle,
        "createMemoryFd"
    );

    const char* dlsym_err = solder_dlerror();

    if (resolved) {
        const std::string resolved_text = hex_addr(resolved);

        result += "dlsym: SUCCESS\n";
        result += "address: " + resolved_text + "\n";

        append_logf(
            "libvirglrenderer.so relocation test: "
            "SUCCESS, createMemoryFd=%s",
            resolved_text.c_str()
        );

        // Keep the relocated module alive for diagnostics.
        return;
    }

    result += "dlsym: FAILED\n";
    result += "error: ";
    result += dlsym_err ? dlsym_err : "(no error text)";
    result += "\n";

    append_logf(
        "libvirglrenderer.so relocation test: FAILED: %s",
        dlsym_err ? dlsym_err : "(no error text)"
    );

    solder_dlclose(handle);
}


void probe_xconnector(std::string& result) {
    result += "\n\n================ LIBXCONNECTORPATCH ================\n";

    append_log("libxconnectorpatch.so probe: starting");

    const int flags =
        SOLDER_LAZY |
        SOLDER_NO_AUTOLOAD;

    void* handle =
        solder_dlopen(
            "libxconnectorpatch.so",
            flags
        );

    const char* err = solder_dlerror();

    if (!handle) {
        result += "LOAD FAILED\n";
        result += err ? err : "(no error text)";
        result += "\n";

        append_logf(
            "libxconnectorpatch.so probe failed: %s",
            err ? err : "(no error text)"
        );
        return;
    }

    result += "ELF LOAD OK\n";
    result +=
        "base: " +
        hex_addr(solder_get_base_addr(handle)) +
        "\n";
    result +=
        "text: " +
        hex_addr(solder_get_text_addr(handle)) +
        "\n\n";

    std::string needed;
    const bool needed_ok = inspect_needed(
        "sdmc:/switch/gamenative_nx/native/arm64-v8a/libxconnectorpatch.so",
        needed
    );

    if (needed_ok) {
        result += needed;
        append_log("libxconnectorpatch.so dependencies:");
        append_log(needed.c_str());
    } else {
        result += "DEPENDENCY INSPECTION FAILED\n";
        result += needed;
        append_logf(
            "libxconnectorpatch.so dependency inspection failed: %s",
            needed.c_str()
        );
    }

    std::string symbol_screen;
    std::string symbol_full;

    const bool symbols_ok = inspect_undefined_symbols(
        "sdmc:/switch/gamenative_nx/native/arm64-v8a/libxconnectorpatch.so",
        symbol_screen,
        symbol_full
    );

    result += "\nSTATIC SYMBOL INSPECTION:\n";
    result += symbol_screen;

    append_log("libxconnectorpatch.so static undefined symbols:");
    append_log(symbol_full.c_str());

    append_log(
        "libxconnectorpatch.so probe: "
        "ELF load succeeded (lazy/no-autoload)"
    );

    result +=
        "\nRELOCATION TEST: "
        "Java_com_winlator_xconnector_XConnectorEpollNative_createEpollFd\n";

    append_log(
        "libxconnectorpatch.so relocation test: "
        "calling solder_dlsym("
        "Java_com_winlator_xconnector_XConnectorEpollNative_createEpollFd)"
    );

    void* resolved = solder_dlsym(
        handle,
        "Java_com_winlator_xconnector_XConnectorEpollNative_createEpollFd"
    );

    const char* dlsym_err = solder_dlerror();

    if (resolved) {
        const std::string resolved_text = hex_addr(resolved);

        result += "dlsym: SUCCESS\n";
        result += "address: " + resolved_text + "\n";

        append_logf(
            "libxconnectorpatch.so relocation test: "
            "SUCCESS, createEpollFd=%s",
            resolved_text.c_str()
        );

        // First real execution test. The JNI wrapper ignores the first two
        // arguments and directly calls epoll_create(10). We pass null JNI
        // placeholders because no Java VM is present in GameNative NX.
        using CreateEpollFdFn = int (*)(void*, void*);
        using CreateEventFdFn = int (*)(void*, void*);
        using AddFdToEpollFn = int (*)(void*, void*, int, int);
        using RemoveFdFromEpollFn = void (*)(void*, void*, int, int);
        using CloseFdFn = int (*)(void*, void*, int);

        auto create_epoll_fd =
            reinterpret_cast<CreateEpollFdFn>(resolved);

        int epoll_fd = create_epoll_fd(nullptr, nullptr);

        {
            char line[128];
            std::snprintf(
                line,
                sizeof(line),
                "libxconnectorpatch.so execution test: createEpollFd returned %d",
                epoll_fd
            );
            append_log(line);
        }

        result +=
            "execute createEpollFd: returned " +
            std::to_string(epoll_fd) +
            "\n";

        if (epoll_fd >= 0) {
            // Second real execution test: createEventFd().
            // This JNI wrapper directly calls eventfd(0, EFD_NONBLOCK).
            append_log(
                "libxconnectorpatch.so execution test: "
                "calling createEventFd"
            );

            void* create_event_symbol = solder_dlsym(
                handle,
                "Java_com_winlator_xconnector_XConnectorEpollNative_createEventFd"
            );

            const char* create_event_err = solder_dlerror();
            int event_fd = -1;

            if (create_event_symbol) {
                auto create_event_fd =
                    reinterpret_cast<CreateEventFdFn>(create_event_symbol);

                event_fd = create_event_fd(nullptr, nullptr);

                char line[128];
                std::snprintf(
                    line,
                    sizeof(line),
                    "libxconnectorpatch.so execution test: createEventFd returned %d",
                    event_fd
                );
                append_log(line);

                result +=
                    "execute createEventFd: returned " +
                    std::to_string(event_fd) +
                    "\n";
            } else {
                append_logf(
                    "libxconnectorpatch.so execution test: "
                    "createEventFd dlsym failed: %s",
                    create_event_err ? create_event_err : "(no error text)"
                );

                result +=
                    "createEventFd dlsym FAILED: " +
                    std::string(create_event_err ? create_event_err : "(no error text)") +
                    "\n";
            }

            // Third test: exercise add/remove through the actual JNI wrapper
            // using the event fd when the compatibility layer provides one.
            if (event_fd >= 0) {
                append_log(
                    "libxconnectorpatch.so execution test: "
                    "stage=before addFdToEpoll dlsym"
                );

                void* add_symbol = solder_dlsym(
                    handle,
                    "Java_com_winlator_xconnector_XConnectorEpollNative_addFdToEpoll"
                );

                const char* add_err = solder_dlerror();

                append_log(
                    add_symbol
                        ? "libxconnectorpatch.so execution test: "
                          "stage=after addFdToEpoll dlsym (success)"
                        : "libxconnectorpatch.so execution test: "
                          "stage=after addFdToEpoll dlsym (NULL)"
                );

                if (add_symbol) {
                    auto add_fd =
                        reinterpret_cast<AddFdToEpollFn>(add_symbol);

                    append_log(
                        "libxconnectorpatch.so execution test: "
                        "stage=before addFdToEpoll call"
                    );

                    int add_result =
                        add_fd(nullptr, nullptr, epoll_fd, event_fd);

                    char line[128];
                    std::snprintf(
                        line,
                        sizeof(line),
                        "libxconnectorpatch.so execution test: addFdToEpoll returned %d",
                        add_result
                    );
                    append_log(line);

                    result +=
                        "execute addFdToEpoll: returned " +
                        std::to_string(add_result) +
                        "\n";

                    append_log(
                        "libxconnectorpatch.so execution test: "
                        "stage=before removeFdFromEpoll dlsym"
                    );

                    void* remove_symbol = solder_dlsym(
                        handle,
                        "Java_com_winlator_xconnector_XConnectorEpollNative_removeFdFromEpoll"
                    );

                    const char* remove_err = solder_dlerror();

                    append_log(
                        remove_symbol
                            ? "libxconnectorpatch.so execution test: "
                              "stage=after removeFdFromEpoll dlsym (success)"
                            : "libxconnectorpatch.so execution test: "
                              "stage=after removeFdFromEpoll dlsym (NULL)"
                    );

                    if (remove_symbol) {
                        append_log(
                            "libxconnectorpatch.so execution test: "
                            "stage=before removeFdFromEpoll call"
                        );
                        auto remove_fd =
                            reinterpret_cast<RemoveFdFromEpollFn>(remove_symbol);

                        remove_fd(
                            nullptr,
                            nullptr,
                            epoll_fd,
                            event_fd
                        );

                        append_log(
                            "libxconnectorpatch.so execution test: "
                            "removeFdFromEpoll returned"
                        );

                        result +=
                            "execute removeFdFromEpoll: completed\n";
                    } else {
                        append_logf(
                            "libxconnectorpatch.so execution test: "
                            "removeFdFromEpoll dlsym failed: %s",
                            remove_err ? remove_err : "(no error text)"
                        );

                        result +=
                            "removeFdFromEpoll dlsym FAILED: " +
                            std::string(remove_err ? remove_err : "(no error text)") +
                            "\n";
                    }
                } else {
                    append_logf(
                        "libxconnectorpatch.so execution test: "
                        "addFdToEpoll dlsym failed: %s",
                        add_err ? add_err : "(no error text)"
                    );

                    result +=
                        "addFdToEpoll dlsym FAILED: " +
                        std::string(add_err ? add_err : "(no error text)") +
                        "\n";
                }
            }

            void* close_symbol = solder_dlsym(
                handle,
                "Java_com_winlator_xconnector_XConnectorEpollNative_closeFd"
            );

            const char* close_err = solder_dlerror();

            if (close_symbol) {
                auto close_fd =
                    reinterpret_cast<CloseFdFn>(close_symbol);

                int close_result =
                    close_fd(nullptr, nullptr, epoll_fd);

                {
                    char line[128];
                    std::snprintf(
                        line,
                        sizeof(line),
                        "libxconnectorpatch.so execution cleanup: closeFd returned %d",
                        close_result
                    );
                    append_log(line);
                }

                result +=
                    "execute closeFd: returned " +
                    std::to_string(close_result) +
                    "\n";

                if (event_fd >= 0) {
                    int event_close_result =
                        close_fd(nullptr, nullptr, event_fd);

                    char line[128];
                    std::snprintf(
                        line,
                        sizeof(line),
                        "libxconnectorpatch.so execution cleanup: "
                        "eventFd closeFd returned %d",
                        event_close_result
                    );
                    append_log(line);

                    result +=
                        "execute eventFd closeFd: returned " +
                        std::to_string(event_close_result) +
                        "\n";
                }
            } else {
                append_logf(
                    "libxconnectorpatch.so execution cleanup: "
                    "closeFd dlsym failed: %s",
                    close_err ? close_err : "(no error text)"
                );

                result +=
                    "closeFd dlsym FAILED: " +
                    std::string(close_err ? close_err : "(no error text)") +
                    "\n";
            }
        }

        // Keep the module alive for diagnostics.
        return;
    }

    result += "dlsym: FAILED\n";
    result += "error: ";
    result += dlsym_err ? dlsym_err : "(no error text)";
    result += "\n";

    append_logf(
        "libxconnectorpatch.so relocation test: FAILED: %s",
        dlsym_err ? dlsym_err : "(no error text)"
    );

    solder_dlclose(handle);
}




struct ElfTables {
    std::string dynstr;
    std::vector<Elf64_Sym> dynsym;
};

bool read_elf_dynsym(const std::string& path, ElfTables& out) {
    FILE* fp = std::fopen(path.c_str(), "rb");
    if (!fp)
        return false;

    Elf64_Ehdr ehdr{};
    if (std::fread(&ehdr, sizeof(ehdr), 1, fp) != 1 ||
        std::memcmp(ehdr.e_ident, ELFMAG, SELFMAG) != 0 ||
        ehdr.e_ident[EI_CLASS] != ELFCLASS64 ||
        ehdr.e_shnum == 0 ||
        ehdr.e_shentsize != sizeof(Elf64_Shdr)) {
        std::fclose(fp);
        return false;
    }

    std::vector<Elf64_Shdr> shdrs(ehdr.e_shnum);
    std::fseek(fp, static_cast<long>(ehdr.e_shoff), SEEK_SET);
    if (std::fread(shdrs.data(), sizeof(Elf64_Shdr), ehdr.e_shnum, fp) != ehdr.e_shnum) {
        std::fclose(fp);
        return false;
    }

    const Elf64_Shdr* dynsym_sh = nullptr;
    const Elf64_Shdr* dynstr_sh = nullptr;
    const Elf64_Shdr* shstr_sh =
        (ehdr.e_shstrndx < ehdr.e_shnum) ? &shdrs[ehdr.e_shstrndx] : nullptr;

    std::string section_names;
    if (shstr_sh) {
        section_names.resize(static_cast<size_t>(shstr_sh->sh_size));
        std::fseek(fp, static_cast<long>(shstr_sh->sh_offset), SEEK_SET);
        if (!section_names.empty() &&
            std::fread(&section_names[0], 1, section_names.size(), fp) != section_names.size()) {
            std::fclose(fp);
            return false;
        }
    }

    for (size_t i = 0; i < shdrs.size(); ++i) {
        const char* name = "";
        if (shdrs[i].sh_name < section_names.size())
            name = section_names.c_str() + shdrs[i].sh_name;

        if (!std::strcmp(name, ".dynsym"))
            dynsym_sh = &shdrs[i];
        else if (!std::strcmp(name, ".dynstr"))
            dynstr_sh = &shdrs[i];
    }

    if (!dynsym_sh || !dynstr_sh) {
        std::fclose(fp);
        return false;
    }

    out.dynstr.assign(static_cast<size_t>(dynstr_sh->sh_size), '\0');
    std::fseek(fp, static_cast<long>(dynstr_sh->sh_offset), SEEK_SET);
    if (!out.dynstr.empty() &&
        std::fread(&out.dynstr[0], 1, out.dynstr.size(), fp) != out.dynstr.size()) {
        std::fclose(fp);
        return false;
    }

    const size_t dynsym_count =
        static_cast<size_t>(dynsym_sh->sh_size / sizeof(Elf64_Sym));
    out.dynsym.resize(dynsym_count);
    std::fseek(fp, static_cast<long>(dynsym_sh->sh_offset), SEEK_SET);
    if (dynsym_count &&
        std::fread(out.dynsym.data(), sizeof(Elf64_Sym), dynsym_count, fp) != dynsym_count) {
        std::fclose(fp);
        return false;
    }

    std::fclose(fp);
    return true;
}

bool bundle_export_exists(
    const std::vector<std::string>& bundle_exports,
    const char* name
) {
    return std::binary_search(
        bundle_exports.begin(),
        bundle_exports.end(),
        std::string(name)
    );
}

void batch_audit_all_sos(std::string& result) {
    result.clear();

    append_log("============================================================");
    append_log("BATCH AUDIT V6: complete undefined-symbol inventory");
    append_log("All ARM64 .so files are loaded first with lazy + no-auto-load; constructors are not triggered.");
    append_log("Then every undefined symbol is checked against the custom main export table and all bundled ELF exports.");
    append_log("No relocation pass, dependency initialization, constructors, or arbitrary exported functions are executed.");
    append_log("============================================================");

    DIR* dir = opendir(kNativeDir);
    if (!dir) {
        result = "FAILED: cannot open native directory\n";
        append_log("BATCH AUDIT V6: opendir FAILED");
        return;
    }

    std::string names[64];
    size_t count = 0;

    while (dirent* e = readdir(dir)) {
        if (e->d_type != DT_REG)
            continue;

        const char* dot = std::strrchr(e->d_name, '.');
        if (!dot || std::strcmp(dot, ".so") != 0)
            continue;

        if (count >= 64)
            break;

        names[count++] = e->d_name;
    }

    closedir(dir);

    for (size_t i = 0; i < count; ++i) {
        for (size_t j = i + 1; j < count; ++j) {
            if (names[j] < names[i]) {
                std::string tmp = names[i];
                names[i] = names[j];
                names[j] = tmp;
            }
        }
    }

    struct LoadedModule {
        std::string name;
        void* handle;
    };

    LoadedModule loaded[64];
    size_t loaded_count = 0;
    int load_fail_count = 0;

    result += "Found " + std::to_string(count) + " ARM64 .so files\n\n";

    // Phase 1: preload every bundled module and KEEP it alive.
    // We intentionally allow DT_NEEDED dependency discovery so the live
    // global namespace contains bundled providers such as libpulsecommon.so.
    for (size_t i = 0; i < count; ++i) {
        const std::string& name = names[i];

        append_log(("PRELOAD [" + std::to_string(i + 1) + "/" +
                    std::to_string(count) + "] " + name +
                    " : starting").c_str());

        void* handle = solder_dlopen(name.c_str(), SOLDER_LAZY | SOLDER_NO_AUTOLOAD);
        const char* load_err = solder_dlerror();

        if (!handle) {
            ++load_fail_count;
            append_logf(
                ("PRELOAD " + name + " : FAILED: %s").c_str(),
                load_err ? load_err : "(no error text)"
            );
            continue;
        }

        loaded[loaded_count].name = name;
        loaded[loaded_count].handle = handle;
        ++loaded_count;

        append_log(("PRELOAD " + name + " : OK").c_str());
    }

    append_log(("PRELOAD SUMMARY: requested=" + std::to_string(count) +
                " loaded=" + std::to_string(loaded_count) +
                " failed=" + std::to_string(load_fail_count)).c_str());

    // Build a purely static provider index from the 29 bundled ELF files.
    // This avoids relying on libsolder's linked-module list and avoids
    // triggering relocation/initialization just to answer "does this symbol exist?".
    std::vector<std::string> bundle_exports;
    bundle_exports.reserve(20000);

    for (size_t mi = 0; mi < loaded_count; ++mi) {
        ElfTables tables;
        const std::string path = std::string(kNativeDir) + "/" + loaded[mi].name;
        if (!read_elf_dynsym(path, tables))
            continue;

        for (size_t si = 1; si < tables.dynsym.size(); ++si) {
            const Elf64_Sym& sym = tables.dynsym[si];
            if (sym.st_shndx == SHN_UNDEF)
                continue;
            if (sym.st_name >= tables.dynstr.size())
                continue;

            const char* exp_name = tables.dynstr.c_str() + sym.st_name;
            if (!exp_name[0])
                continue;

            if (!main_export_exists(exp_name) &&
                !bundle_export_exists(bundle_exports, exp_name)) {
                bundle_exports.emplace_back(exp_name);
            }
        }
    }

    std::sort(bundle_exports.begin(), bundle_exports.end());

    append_log(("STATIC PROVIDER INDEX: bundled_defined_unique=" +
                std::to_string(bundle_exports.size()) +
                " main_exports=" +
                std::to_string(g_main_export_count)).c_str());

    // Phase 2: parse each ELF's .dynsym/.dynstr directly. For every unique
    // undefined symbol, ask the live libsolder global namespace whether a
    // provider exists. This is much faster and safer than forcing relocation
    // one import at a time, and it gives us the COMPLETE inventory in one run.
    size_t total_undefined = 0;
    size_t unique_missing_total = 0;
    size_t unique_resolved_total = 0;
    size_t unique_modules_scanned = 0;

    struct SymbolStat {
        std::string name;
        size_t missing_occurrences;
        size_t resolved_occurrences;
    };
    SymbolStat* global_stats = new SymbolStat[4096];
    size_t global_stat_count = 0;

    append_log("SYMBOL INVENTORY: begin live global-namespace scan");

    for (size_t mi = 0; mi < loaded_count; ++mi) {
        const std::string& name = loaded[mi].name;
        const std::string path = std::string(kNativeDir) + "/" + name;

        FILE* fp = std::fopen(path.c_str(), "rb");
        if (!fp) {
            append_log(("SYMBOL INVENTORY " + name + " : FAILED open").c_str());
            continue;
        }

        Elf64_Ehdr ehdr{};
        if (std::fread(&ehdr, sizeof(ehdr), 1, fp) != 1 ||
            std::memcmp(ehdr.e_ident, ELFMAG, SELFMAG) != 0 ||
            ehdr.e_ident[EI_CLASS] != ELFCLASS64) {
            append_log(("SYMBOL INVENTORY " + name + " : FAILED invalid ELF64").c_str());
            std::fclose(fp);
            continue;
        }

        if (ehdr.e_shnum == 0 || ehdr.e_shentsize != sizeof(Elf64_Shdr)) {
            append_log(("SYMBOL INVENTORY " + name + " : FAILED section table").c_str());
            std::fclose(fp);
            continue;
        }

        Elf64_Shdr* shdrs = new Elf64_Shdr[ehdr.e_shnum];
        if (!shdrs) {
            std::fclose(fp);
            append_log(("SYMBOL INVENTORY " + name + " : FAILED alloc section table").c_str());
            continue;
        }

        std::fseek(fp, static_cast<long>(ehdr.e_shoff), SEEK_SET);
        if (std::fread(shdrs, sizeof(Elf64_Shdr), ehdr.e_shnum, fp) != ehdr.e_shnum) {
            delete[] shdrs;
            std::fclose(fp);
            append_log(("SYMBOL INVENTORY " + name + " : FAILED read section table").c_str());
            continue;
        }

        const Elf64_Shdr* dynsym_sh = nullptr;
        const Elf64_Shdr* dynstr_sh = nullptr;
        const Elf64_Shdr* shstr_sh = nullptr;

        if (ehdr.e_shstrndx < ehdr.e_shnum)
            shstr_sh = &shdrs[ehdr.e_shstrndx];

        std::string section_names;
        if (shstr_sh) {
            section_names.resize(static_cast<size_t>(shstr_sh->sh_size));
            std::fseek(fp, static_cast<long>(shstr_sh->sh_offset), SEEK_SET);
            if (!section_names.empty())
                std::fread(&section_names[0], 1, section_names.size(), fp);
        }

        for (int si = 0; si < ehdr.e_shnum; ++si) {
            const char* sname = "";
            if (shdrs[si].sh_name < section_names.size())
                sname = section_names.c_str() + shdrs[si].sh_name;

            if (!std::strcmp(sname, ".dynsym"))
                dynsym_sh = &shdrs[si];
            else if (!std::strcmp(sname, ".dynstr"))
                dynstr_sh = &shdrs[si];
        }

        if (!dynsym_sh || !dynstr_sh) {
            delete[] shdrs;
            std::fclose(fp);
            append_log(("SYMBOL INVENTORY " + name + " : FAILED no dynsym/dynstr").c_str());
            continue;
        }

        std::string dynstr(static_cast<size_t>(dynstr_sh->sh_size), '\0');
        std::fseek(fp, static_cast<long>(dynstr_sh->sh_offset), SEEK_SET);
        if (!dynstr.empty())
            std::fread(&dynstr[0], 1, dynstr.size(), fp);

        const size_t dynsym_count =
            static_cast<size_t>(dynsym_sh->sh_size / sizeof(Elf64_Sym));
        Elf64_Sym* dynsym = new Elf64_Sym[dynsym_count];
        if (!dynsym) {
            delete[] shdrs;
            std::fclose(fp);
            append_log(("SYMBOL INVENTORY " + name + " : FAILED alloc dynsym").c_str());
            continue;
        }

        std::fseek(fp, static_cast<long>(dynsym_sh->sh_offset), SEEK_SET);
        if (std::fread(dynsym, sizeof(Elf64_Sym), dynsym_count, fp) != dynsym_count) {
            delete[] dynsym;
            delete[] shdrs;
            std::fclose(fp);
            append_log(("SYMBOL INVENTORY " + name + " : FAILED read dynsym").c_str());
            continue;
        }

        std::string* seen = new std::string[4096];
        size_t seen_count = 0;
        size_t module_undef = 0;
        size_t module_missing = 0;
        size_t module_resolved = 0;

        for (size_t si = 1; si < dynsym_count; ++si) {
            const Elf64_Sym& sym = dynsym[si];
            if (sym.st_shndx != SHN_UNDEF)
                continue;
            if (sym.st_name >= dynstr.size())
                continue;

            const char* symname = dynstr.c_str() + sym.st_name;
            if (!symname[0])
                continue;

            bool duplicate = false;
            for (size_t k = 0; k < seen_count; ++k) {
                if (seen[k] == symname) {
                    duplicate = true;
                    break;
                }
            }
            if (duplicate)
                continue;

            if (seen_count < 4096)
                seen[seen_count++] = symname;

            ++module_undef;
            ++total_undefined;

            const bool resolved = main_export_exists(symname) || bundle_export_exists(bundle_exports, symname);
            if (resolved) {
                ++module_resolved;
                ++unique_resolved_total;
            } else {
                ++module_missing;
                ++unique_missing_total;

                char line[512];
                std::snprintf(
                    line, sizeof(line),
                    "UNRESOLVED module=%s symbol=%s bind=%u type=%u",
                    name.c_str(), symname,
                    static_cast<unsigned>(ELF64_ST_BIND(sym.st_info)),
                    static_cast<unsigned>(ELF64_ST_TYPE(sym.st_info))
                );
                append_log(line);
            }

            size_t stat_idx = 0;
            for (; stat_idx < global_stat_count; ++stat_idx) {
                if (global_stats[stat_idx].name == symname)
                    break;
            }
            if (stat_idx == global_stat_count && global_stat_count < 4096) {
                global_stats[global_stat_count].name = symname;
                global_stats[global_stat_count].missing_occurrences = 0;
                global_stats[global_stat_count].resolved_occurrences = 0;
                ++global_stat_count;
            }
            if (stat_idx < global_stat_count) {
                if (resolved)
                    ++global_stats[stat_idx].resolved_occurrences;
                else
                    ++global_stats[stat_idx].missing_occurrences;
            }
        }

        char module_summary[256];
        std::snprintf(
            module_summary, sizeof(module_summary),
            "SYMBOL INVENTORY %s : unique_undefined=%zu missing=%zu resolved=%zu",
            name.c_str(), module_undef, module_missing, module_resolved
        );
        append_log(module_summary);

        delete[] seen;
        delete[] dynsym;
        delete[] shdrs;
        std::fclose(fp);
        ++unique_modules_scanned;
    }

    // Sort global missing symbols by descending occurrence count for a compact
    // actionable tail section in the log.
    for (size_t i = 0; i < global_stat_count; ++i) {
        for (size_t j = i + 1; j < global_stat_count; ++j) {
            if (global_stats[j].missing_occurrences > global_stats[i].missing_occurrences) {
                SymbolStat tmp = global_stats[i];
                global_stats[i] = global_stats[j];
                global_stats[j] = tmp;
            }
        }
    }

    append_log("============================================================");
    append_log("UNRESOLVED SYMBOL SUMMARY: sorted by missing-module occurrences");
    for (size_t i = 0; i < global_stat_count; ++i) {
        if (!global_stats[i].missing_occurrences)
            continue;

        char line[512];
        std::snprintf(
            line, sizeof(line),
            "MISSING symbol=%s occurrences=%zu also_resolved_occurrences=%zu",
            global_stats[i].name.c_str(),
            global_stats[i].missing_occurrences,
            global_stats[i].resolved_occurrences
        );
        append_log(line);
    }

    char summary[512];
    std::snprintf(
        summary, sizeof(summary),
        "BATCH V6 SUMMARY: files=%zu loaded=%zu load_fail=%d scanned_modules=%zu unique_undefined=%zu missing=%zu resolved=%zu",
        count,
        loaded_count,
        load_fail_count,
        unique_modules_scanned,
        total_undefined,
        unique_missing_total,
        unique_resolved_total
    );

    append_log(summary);
    result += summary;
    delete[] global_stats;

    // No dlclose here: keep the diagnostic deterministic until process exit.
    append_log("CLOSE: skipped (diagnostic mode; process exit will reclaim modules)");
}



void runtime_probe_leaf_module(std::string& result) {
    // V13 diagnostic step: preload every bundled module lazily without
    // dependency autoload, install only the ArrayList_add bridge, hook the
    // target constructor, then call dlsym() directly on the target.
    const char* target = "libvortekrenderer.so";
    const char* symbol = "Java_com_winlator_xenvironment_components_VortekRendererComponent_createVkContext";

    append_log("============================================================");
    append_log("RUNTIME PROBE V15: resolve native Vortek createVkContext after relocation");
    append_log((std::string("Target: ") + target).c_str());
    append_log((std::string("Probe symbol: ") + symbol).c_str());
    append_log("All bundled modules are preloaded with LAZY|NO_AUTOLOAD. The target is reopened with LAZY (autoload enabled) so its declared bundled dependency can enter scope.");
    append_log("Only the target is forced through solder_dlsym(); target dependency autoload is enabled.");
    append_log("No exported function is called after dlsym().");

    std::vector<std::string> names;
    DIR* dir = opendir(kNativeDir);
    if (!dir) {
        result = "RUNTIME PROBE: cannot open native dir";
        append_log(result.c_str());
        return;
    }
    struct dirent* ent = nullptr;
    while ((ent = readdir(dir)) != nullptr) {
        const char* n = ent->d_name;
        const size_t len = std::strlen(n);
        if (len >= 3 && std::strcmp(n + len - 3, ".so") == 0)
            names.emplace_back(n);
    }
    closedir(dir);
    std::sort(names.begin(), names.end());

    void* handles[64]{};
    size_t loaded = 0;
    for (size_t i = 0; i < names.size() && loaded < 64; ++i) {
        append_log((std::string("PROBE PRELOAD [") + std::to_string(i + 1) + "/" +
                    std::to_string(names.size()) + "] " + names[i]).c_str());
        void* h = solder_dlopen(names[i].c_str(), SOLDER_LAZY | SOLDER_NO_AUTOLOAD);
        const char* err = solder_dlerror();
        if (!h) {
            append_logf((std::string("PROBE PRELOAD FAILED ") + names[i] + ": %s").c_str(),
                        err ? err : "(no error text)");
            continue;
        }
        handles[loaded++] = h;
    }

    append_log((std::string("PROBE PRELOAD SUMMARY loaded=") + std::to_string(loaded)).c_str());

    // V13 diagnostic isolation:
    // V12 proved that direct dlsym() no longer hangs, but relocation stops
    // on the first unresolved import: ArrayList_add. Promote the REAL bundled
    // implementation from libwinlator_11.so into the main export namespace,
    // while deliberately keeping NO_AUTOLOAD and skipping the second autoload
    // dlopen path. This isolates symbol-namespace behavior from dependency
    // autoload/constructor behavior.
    append_log("RUNTIME PROBE V15: installing direct ArrayList_add bridge");

    void* winlator11_handle = solder_dlopen(
        "libwinlator_11.so",
        SOLDER_LAZY | SOLDER_NO_AUTOLOAD
    );

    if (!winlator11_handle) {
        const char* err = solder_dlerror();
        result = std::string("RUNTIME PROBE: ArrayList bridge dlopen FAILED: ") +
                 (err ? err : "(no error text)");
        append_log(result.c_str());
        return;
    }

    void* arraylist_add = solder_dlsym(
        winlator11_handle,
        "ArrayList_add"
    );
    const char* arraylist_err = solder_dlerror();

    if (!arraylist_add) {
        result = std::string("RUNTIME PROBE: ArrayList_add bridge lookup FAILED: ") +
                 (arraylist_err ? arraylist_err : "(no error text)");
        append_log(result.c_str());
        return;
    }

    char bridge_line[256];
    std::snprintf(
        bridge_line, sizeof(bridge_line),
        "RUNTIME PROBE: ArrayList_add implementation=%p",
        arraylist_add
    );
    append_log(bridge_line);

    if (main_export_exists("ArrayList_add")) {
        append_log("RUNTIME PROBE: ArrayList_add already present in main exports");
    } else if (g_main_export_count >= kMaxMainExports) {
        result = "RUNTIME PROBE: main export table full; cannot promote ArrayList_add";
        append_log(result.c_str());
        return;
    } else {
        solder_export_t promoted = g_main_exports[0];
        promoted.name = "ArrayList_add";
        promoted.addr_rx = reinterpret_cast<decltype(promoted.addr_rx)>(arraylist_add);
        g_main_exports[g_main_export_count++] = promoted;

        if (solder_set_main_exports(
                g_main_exports,
                g_main_export_count
            ) != 0) {
            result = "RUNTIME PROBE: failed to re-install main exports with ArrayList_add";
            append_log(result.c_str());
            return;
        }

        append_log("RUNTIME PROBE: promoted bundled ArrayList_add from libwinlator_11.so into main exports");
    }

    void* target_handle = nullptr;
    for (size_t i = 0; i < names.size(); ++i) {
        if (names[i] == target) {
            target_handle = solder_dlopen(target, SOLDER_LAZY | SOLDER_NO_AUTOLOAD);
            break;
        }
    }

    if (!target_handle) {
        const char* err = solder_dlerror();
        result = std::string("RUNTIME PROBE: target initial dlopen FAILED: ") +
                 (err ? err : "(no error text)");
        append_log(result.c_str());
        return;
    }

    // libvortekrenderer.so has one constructor in .init_array at 0x6617c.
    // Vortek uses Android linker/loader internals there. Keep that constructor
    // from executing so we can test dependency resolution independently.
    const int hook_rc = solder_hook_offset(
        target_handle,
        0x6617cULL,
        reinterpret_cast<void*>(gn_ctor_noop)
    );

    if (hook_rc != 0) {
        result = std::string("RUNTIME PROBE: Vortek constructor hook FAILED rc=") +
                 std::to_string(hook_rc);
        append_log(result.c_str());
        return;
    }

    append_log("RUNTIME PROBE: hooked Vortek init_array constructor at offset 0x6617c");

    // V12 diagnostic isolation:
    // Do NOT reopen the target with autoload enabled here.
    // The target is already mapped and hooked. We now call solder_dlsym()
    // directly so we can determine whether the hang occurs inside relocation/
    // symbol resolution itself, independent of a second dlopen() path.
    append_log("RUNTIME PROBE V15: skipping second autoload dlopen; using direct symbol bridge");
    append_log((std::string("RUNTIME PROBE: before direct dlsym(") + symbol + ")").c_str());
    void* resolved = solder_dlsym(target_handle, symbol);
    const char* err = solder_dlerror();

    if (!resolved) {
        result = std::string("RUNTIME PROBE: dlsym FAILED: ") +
                 (err ? err : "(no error text)");
        append_log(result.c_str());
        return;
    }

    char line[512];
    std::snprintf(line, sizeof(line),
                  "RUNTIME PROBE: SUCCESS module=%s symbol=%s addr=%p",
                  target, symbol, resolved);
    append_log(line);
    result = line;

    append_log("RUNTIME PROBE V15: createVkContext is the actual Vortek JNI bootstrap entrypoint");
    append_log("RUNTIME PROBE V15: resolve-only mode; NOT calling createVkContext yet");
    append_log("RUNTIME PROBE V15: expected JNI signature conceptually (JNIEnv*, jobject, jint, jobject) -> jlong");

    // The Android-side VortekRendererComponent calls createVkContext(clientFd, options).
    // We deliberately stop after symbol resolution because this native Switch
    // probe does not have a real JVM/JNIEnv or a valid Options Java object.
    // Calling the function with fabricated pointers/objects would turn a
    // useful loader diagnostic into an avoidable crash.
    append_log("RUNTIME PROBE V15: JNI entrypoint resolved successfully; execution deferred until JNI arguments are reconstructed");

    append_log("RUNTIME PROBE: handles intentionally kept alive until process exit");
}

} // namespace

int main(int /*argc*/, char** /*argv*/) {
    consoleInit(nullptr);
    socketInitializeDefault();

    mkdir(kRoot, 0777);

    append_log("GameNative NX 0.2.0 started");
    append_log("MODE: batch ARM64 .so audit");

    const bool solder_ok = init_solder();

    PadState pad;
    padConfigureInput(1, HidNpadStyleSet_NpadStandard);
    padInitializeDefault(&pad);

    bool audited = false;
    std::string audit_result;

    while (appletMainLoop()) {
        draw_header();

        std::printf(
            "RUNTIME PROBE\n\n"
            "This pass preloads all ARM64 .so and then forces one leaf module:\n"
            "  SOLDER_LAZY | SOLDER_NO_AUTOLOAD\n\n"
            "It does NOT call dlsym on arbitrary exports and\n"
            "does NOT execute JNI functions.\n\n"
        );

        std::printf(
            "Native dir : %s\n",
            exists(kNativeDir) ? "FOUND" : "MISSING"
        );

        std::printf(
            "ARM64 .so : %zu\n",
            count_entries(kNativeDir, ".so")
        );

        std::printf(
            "libsolder  : %s\n\n",
            solder_ok ? "READY" : "FAILED"
        );

        std::printf(
            "A = Run runtime probe\n"
            "+ = Exit\n\n"
        );

        if (audited) {
            std::printf(
                "============================================================\n"
                "RESULT\n"
                "============================================================\n"
                "%s\n",
                audit_result.c_str()
            );
        }

        consoleUpdate(nullptr);
        padUpdate(&pad);

        const u64 buttons = padGetButtonsDown(&pad);

        if ((buttons & HidNpadButton_Plus) != 0)
            break;

        if ((buttons & HidNpadButton_A) != 0 &&
            solder_ok &&
            !audited) {

            runtime_probe_leaf_module(audit_result);
            audited = true;
        }

        svcSleepThread(16'000'000ULL);
    }

    if (solder_ok)
        solder_quit();

    socketExit();
    consoleExit(nullptr);
    return 0;
}
