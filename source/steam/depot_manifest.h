#pragma once
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>
struct DepotChunk { std::string sha; uint32_t compressed; uint32_t original; uint32_t adler = 0; };
struct DepotPlan { size_t files = 0; uint64_t bytes = 0; bool encrypted_names = false; std::vector<DepotChunk> chunks; };
bool read_depot_manifest(const void* zip, size_t length, uint32_t depot, uint64_t manifest, DepotPlan& plan);
bool inflate_depot_zip(const void*, size_t, size_t, std::vector<uint8_t>&);
bool decode_depot_chunk(const DepotChunk&, const uint8_t key[32], const void*, size_t, std::vector<uint8_t>&);
