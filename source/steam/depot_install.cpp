#include "depot_manifest.h"
#include <switch.h>
#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cerrno>
#include <sys/stat.h>
extern "C" {
#include "b64.h"
#include "log.h"
}

static bool directory(const std::string& path) {
    if (mkdir(path.c_str(), 0777) == 0) return true;
    struct stat info{};
    return errno == EEXIST && stat(path.c_str(), &info) == 0 && S_ISDIR(info.st_mode);
}

static bool depot_path(std::string& name, bool encrypted, const uint8_t key[32]) {
    if (encrypted) {
        uint8_t* cipher = nullptr;
        size_t length = 0;
        if (!b64_decode(name.data(), name.size(), &cipher, &length)) return false;
        std::vector<uint8_t> clear;
        const bool ok = decrypt_depot_bytes(key, cipher, length, clear);
        std::free(cipher);
        if (!ok || clear.empty()) return false;
        if (clear.back() == 0) clear.pop_back();
        name.assign(clear.begin(), clear.end());
    }
    std::replace(name.begin(), name.end(), '\\', '/');
    if (name.empty() || name.size() > 768) return false;
    for (size_t start = 0;;) {
        const size_t end = name.find('/', start);
        const std::string part = name.substr(start, end == std::string::npos ? end : end-start);
        if (part.empty() || part == "." || part == ".." || part.back() == '.' || part.back() == ' ')
            return false;
        for (unsigned char c : part)
            if (c < 32 || c == 127 || std::strchr(":*?\"<>|", c)) return false;
        if (end == std::string::npos) return true;
        start = end+1;
    }
}

static bool write_depot_file(FILE* output, DepotFile& file, const std::string& cache,
                             const uint8_t key[32], PadState& pad) {
    std::sort(file.parts.begin(), file.parts.end(), [](const DepotPart& a, const DepotPart& b) {
        return a.offset < b.offset;
    });
    Sha1Context sha;
    sha1ContextCreate(&sha);
    uint64_t written = 0;
    std::vector<uint8_t> ciphertext, decoded;
    for (const auto& part : file.parts) {
        padUpdate(&pad);
        if (!appletMainLoop() || (padGetButtonsDown(&pad) & HidNpadButton_B)) return false;
        if (part.offset != written || part.chunk.original > file.size-written ||
            part.chunk.compressed > 4*1024*1024) return false;
        const std::string path = cache + "/" + part.chunk.sha + ".encrypted";
        FILE* input = std::fopen(path.c_str(), "rb");
        if (!input) return false;
        ciphertext.resize(part.chunk.compressed);
        const bool read = std::fread(ciphertext.data(), 1, ciphertext.size(), input) == ciphertext.size();
        std::fclose(input);
        if (!read || !decode_depot_chunk(part.chunk, key, ciphertext.data(), ciphertext.size(), decoded))
            return false;
        if (std::fwrite(decoded.data(), 1, decoded.size(), output) != decoded.size()) return false;
        sha1ContextUpdate(&sha, decoded.data(), decoded.size());
        written += decoded.size();
    }
    std::array<uint8_t,20> digest{};
    sha1ContextGetHash(&sha, digest.data());
    return written == file.size && (file.has_hash ? digest == file.hash : written == 0);
}

bool assemble_depot(uint32_t depot, uint64_t manifest, DepotPlan& plan,
                    const uint8_t key[32], const std::string& cache, PadState& pad) {
    constexpr uint64_t directory_flag = 64, symlink_flag = 512;
    const std::string parent = "sdmc:/switch/gamenative_nx/installed";
    const std::string root = parent + "/" + std::to_string(depot) + "_" + std::to_string(manifest);
    const std::string temporary = root + ".part";
    for (auto& file : plan.mappings) {
        if (file.link || (file.flags & symlink_flag) ||
            !depot_path(file.name, plan.encrypted_names, key)) {
            log_printf("Depot %u assembly rejected an unsupported path or link\n", depot);
            return false;
        }
    }
    if (!directory(parent) || !directory(root)) return false;
    size_t index = 0;
    for (auto& file : plan.mappings) {
        ++index;
        consoleClear();
        std::printf("Assembling Steam depot %u | file %zu/%zu\nB Cancel\n", depot, index, plan.mappings.size());
        consoleUpdate(nullptr);
        const std::string path = root + "/" + file.name;
        for (size_t slash = path.find('/', root.size()+1); slash != std::string::npos;
             slash = path.find('/', slash+1))
            if (!directory(path.substr(0, slash))) return false;
        if (file.flags & directory_flag) {
            if (!directory(path)) return false;
            continue;
        }
        FILE* output = std::fopen(temporary.c_str(), "wb");
        if (!output) return false;
        const bool valid = write_depot_file(output, file, cache, key, pad);
        const bool closed = std::fclose(output) == 0;
        if (!valid || !closed || std::rename(temporary.c_str(), path.c_str()) != 0) {
            std::remove(temporary.c_str());
            log_printf("Depot %u assembly stopped at file %zu/%zu\n", depot, index, plan.mappings.size());
            return false;
        }
    }
    log_printf("Depot %u assembly complete: %zu entries\n", depot, index);
    return true;
}
