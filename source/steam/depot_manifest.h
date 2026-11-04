#pragma once
#include <cstddef>
#include <array>
#include <cstdint>
#include <string>
#include <vector>
struct DepotChunk { std::string sha; uint32_t compressed; uint32_t original; uint32_t adler = 0; };
struct DepotPart { DepotChunk chunk; uint64_t offset; };
struct DepotFile {
    std::string name;
    uint64_t size = 0, flags = 0;
    bool link = false, has_hash = false;
    std::array<uint8_t,20> hash{};
    std::vector<DepotPart> parts;
};
struct DepotPlan { size_t files = 0; uint64_t bytes = 0; bool encrypted_names = false; std::vector<DepotChunk> chunks; std::vector<DepotFile> mappings; };
bool read_depot_manifest(const void* zip, size_t length, uint32_t depot, uint64_t manifest, DepotPlan& plan);
bool inflate_depot_zip(const void*, size_t, size_t, std::vector<uint8_t>&);
bool decode_depot_chunk(const DepotChunk&, const uint8_t key[32], const void*, size_t, std::vector<uint8_t>&);
bool decrypt_depot_bytes(const uint8_t key[32], const void*, size_t, std::vector<uint8_t>&);
