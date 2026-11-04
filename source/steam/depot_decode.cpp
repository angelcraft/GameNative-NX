#include "depot_manifest.h"
#include <switch.h>
#include <lzma.h>
#include <zstd.h>
#include <zlib.h>
#include <cstring>

static bool valid_chunk(const DepotChunk& chunk, const std::vector<uint8_t>& bytes) {
    return bytes.size() == chunk.original &&
        adler32(0, bytes.data(), bytes.size()) == chunk.adler;
}

// Port of GameNative gn-download's depot_chunk.rs to libnx and Switch portlibs.
bool decode_depot_chunk(const DepotChunk& chunk, const uint8_t key[32],
                        const void* encrypted, size_t size, std::vector<uint8_t>& output) {
    if (size < 32 || size % 16 || chunk.original > 4*1024*1024) return false;
    const auto* input = static_cast<const uint8_t*>(encrypted);
    Aes256Context aes;
    aes256ContextCreate(&aes, key, false);
    uint8_t iv[16];
    aes256DecryptBlock(&aes, iv, input);
    std::vector<uint8_t> plain(size - 16);
    for (size_t offset = 16; offset < size; offset += 16) {
        auto* block = plain.data() + offset - 16;
        aes256DecryptBlock(&aes, block, input + offset);
        const auto* previous = offset == 16 ? iv : input + offset - 16;
        for (size_t i = 0; i < 16; ++i) block[i] ^= previous[i];
    }
    for (size_t i = 0; i < sizeof(aes); ++i)
        reinterpret_cast<volatile uint8_t*>(&aes)[i] = 0;
    const size_t padding = plain.back();
    if (!padding || padding > 16) return false;
    for (size_t i = 0; i < padding; ++i)
        if (plain[plain.size()-1-i] != padding) return false;
    plain.resize(plain.size()-padding);
    const auto* data = plain.data();
    const size_t length = plain.size();

    output.resize(chunk.original);
    if (length > 8 && std::memcmp(data, "VSZa", 4) == 0) {
        if (ZSTD_decompress(output.data(), output.size(), data+8, length-8) != output.size())
            return false;
    } else if (length >= 22 && std::memcmp(data, "VZa", 3) == 0) {
        if (data[length-2] != 'z' || data[length-1] != 'v') return false;
        lzma_filter filters[] = {{LZMA_FILTER_LZMA1EXT, nullptr}, {LZMA_VLI_UNKNOWN, nullptr}};
        if (lzma_properties_decode(&filters[0], nullptr, data+7, 5) != LZMA_OK) return false;
        auto* options = static_cast<lzma_options_lzma*>(filters[0].options);
        options->ext_flags = LZMA_LZMA1EXT_ALLOW_EOPM;
        lzma_set_ext_size((*options), chunk.original);
        size_t input_pos = 0, output_pos = 0;
        const bool ok = options->dict_size <= 32*1024*1024 &&
            lzma_raw_buffer_decode(filters, nullptr, data+12, &input_pos, length-22,
                                   output.data(), &output_pos, output.size()) == LZMA_OK &&
            output_pos == output.size();
        lzma_filters_free(filters, nullptr);
        if (!ok) return false;
    } else if (!inflate_depot_zip(data, length, chunk.original, output)) {
        return false;
    }
    return valid_chunk(chunk, output);
}
