#pragma once
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>
struct DepotChunk { std::string sha; uint32_t compressed; uint32_t original; };
struct DepotPlan { size_t files = 0; uint64_t bytes = 0; bool encrypted_names = false; std::vector<DepotChunk> chunks; };
bool read_depot_manifest(const void* zip, size_t length, uint32_t depot, uint64_t manifest, DepotPlan& plan);
