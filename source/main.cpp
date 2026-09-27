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
constexpr int kMaxMainExports = 512;

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

    const solder_export_t* compat_exports =
        android_compat_exports(
            &compat_count
        );

    for (int i = 0;
         i < compat_count &&
         g_main_export_count < kMaxMainExports;
         ++i) {

        const solder_export_t& exp =
            compat_exports[i];

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
            "  A      Inspect libwinlator.so\n"
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
