#include "depot_manifest.h"
#include <zlib.h>
#include <cstring>
#include <map>
extern "C" {
#include "pb.h"
}
static uint32_t le32(const uint8_t* p) { return uint32_t(p[0]) | uint32_t(p[1])<<8 | uint32_t(p[2])<<16 | uint32_t(p[3])<<24; }
static unsigned le16(const uint8_t* p) { return p[0] | unsigned(p[1])<<8; }
bool inflate_depot_zip(const void* zip, size_t length, size_t limit, std::vector<uint8_t>& data) {
    const auto* z = static_cast<const uint8_t*>(zip);
    if (length < 30 || le32(z) != 0x04034b50 || (le16(z+6) & ~0x806u) != 0) return false;
    const size_t start = 30 + le16(z+26) + le16(z+28);
    const uint32_t packed = le32(z+18), unpacked = le32(z+22);
    if (start > length || packed > length-start || !unpacked || unpacked > limit) return false;
    const unsigned method = le16(z+8);
    if (method == 0) {
        if (packed != unpacked) return false;
        data.assign(z+start, z+start+packed);
        return crc32(0, data.data(), unpacked) == le32(z+14);
    }
    if (method != 8) return false;
    data.resize(unpacked);
    z_stream stream{};
    stream.next_in = const_cast<Bytef*>(z+start); stream.avail_in = packed;
    stream.next_out = data.data(); stream.avail_out = unpacked;
    if (inflateInit2(&stream, -MAX_WBITS) != Z_OK) return false;
    const int result = inflate(&stream, Z_FINISH);
    const bool inflated = result == Z_STREAM_END && stream.total_out == unpacked && stream.total_in == packed;
    inflateEnd(&stream);
    return inflated && crc32(0, data.data(), unpacked) == le32(z+14);
}
bool read_depot_manifest(const void* zip, size_t length, uint32_t depot, uint64_t manifest, DepotPlan& out) {
    out = {};
    std::vector<uint8_t> data;
    if (!inflate_depot_zip(zip, length, 16*1024*1024, data)) return false;
    DepotPlan plan;
    bool payload = false, metadata = false, end = false;
    std::map<std::string, DepotChunk> chunks;
    size_t pos = 0;
    while (pos+4 <= data.size()) {
        const uint32_t magic = le32(data.data()+pos); pos += 4;
        if (magic == 0x32c415ab) { end = pos == data.size(); break; }
        if (data.size()-pos < 4) return false;
        const size_t size = le32(data.data()+pos); pos += 4;
        if (size > data.size()-pos) return false;
        const auto* body = data.data()+pos; pos += size;
        if (magic == 0x1f4812be) {
            uint64_t id=0, gid=0, encrypted=0;
            if (metadata || !pb_get_u64(body,size,1,&id) || id != depot ||
                !pb_get_u64(body,size,2,&gid) || gid != manifest) return false;
            pb_get_u64(body,size,4,&encrypted); plan.encrypted_names = encrypted != 0;
            metadata = true;
        } else if (magic == 0x71f617d0) {
            if (payload) return false;
            payload = true;
            PbReader files; PbField f; pb_reader(&files,body,size);
            while (files.pos < files.len) {
                if (!pb_next(&files,&f)) return false;
                if (f.field != 1 || f.wire != PB_BYTES) continue;
                ++plan.files;
                uint64_t file_size=0; pb_get_u64(f.data,f.len,2,&file_size);
                if (UINT64_MAX-plan.bytes < file_size) return false;
                plan.bytes += file_size;
                PbReader fields; PbField c; pb_reader(&fields,f.data,f.len);
                while (fields.pos < fields.len) {
                    if (!pb_next(&fields,&c)) return false;
                    if (c.field != 6 || c.wire != PB_BYTES) continue;
                    const uint8_t* sha=nullptr; size_t sha_size=0; uint64_t compressed=0,original=0,adler=0;
                    pb_get_u64(c.data,c.len,2,&adler);
                    if (adler > UINT32_MAX) return false;
                    if (!pb_get_bytes(c.data,c.len,1,&sha,&sha_size) || sha_size != 20 ||
                        !pb_get_u64(c.data,c.len,4,&original) || !original || original > UINT32_MAX ||
                        !pb_get_u64(c.data,c.len,5,&compressed) || !compressed || compressed > UINT32_MAX) return false;
                    std::string hex; constexpr char digits[]="0123456789abcdef";
                    for (size_t i=0;i<20;++i) { hex += digits[sha[i]>>4]; hex += digits[sha[i]&15]; }
                    const DepotChunk chunk{hex,static_cast<uint32_t>(compressed),static_cast<uint32_t>(original),static_cast<uint32_t>(adler)};
                    const auto existing=chunks.find(hex);
                    if (existing != chunks.end() && (existing->second.compressed != compressed || existing->second.original != original || existing->second.adler != adler)) return false;
                    chunks[hex]=chunk;
                }
            }
        } else if (magic != 0x1b81b817) return false;
    }
    if (!payload || !metadata || !end) return false;
    for (const auto& item: chunks) plan.chunks.push_back(item.second);
    out = std::move(plan);
    return true;
}
