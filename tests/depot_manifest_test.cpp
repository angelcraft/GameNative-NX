#include "depot_manifest.h"
#include <cassert>
#include <cstring>
#include <zlib.h>
extern "C" {
#include "pb.h"
}
static void put(std::vector<uint8_t>& v, uint32_t n) { for(int i=0;i<4;++i) v.push_back(n>>(8*i)); }
static void section(std::vector<uint8_t>& v, uint32_t magic, PbBuf& b) { put(v,magic); put(v,b.len); v.insert(v.end(),b.data,b.data+b.len); pb_free(&b); }
int main() {
    PbBuf chunk{}, file{}, payload{}, metadata{};
    uint8_t sha[20]{}; pb_bytes(&chunk,1,sha,20); pb_varint(&chunk,4,96); pb_varint(&chunk,5,64);
    pb_string(&file,1,"encrypted-name"); pb_varint(&file,2,96); pb_bytes(&file,6,chunk.data,chunk.len);
    pb_bytes(&payload,1,file.data,file.len); pb_free(&file); pb_free(&chunk);
    pb_varint(&metadata,1,1929291); pb_varint(&metadata,2,4836465726223256507ULL); pb_varint(&metadata,4,1);
    std::vector<uint8_t> raw; section(raw,0x71f617d0,payload); section(raw,0x1f4812be,metadata); put(raw,0x32c415ab);
    std::vector<uint8_t> packed(compressBound(raw.size())); z_stream stream{};
    assert(deflateInit2(&stream,6,Z_DEFLATED,-MAX_WBITS,8,Z_DEFAULT_STRATEGY)==Z_OK);
    stream.next_in=raw.data(); stream.avail_in=raw.size(); stream.next_out=packed.data(); stream.avail_out=packed.size();
    assert(deflate(&stream,Z_FINISH)==Z_STREAM_END); packed.resize(stream.total_out); deflateEnd(&stream);
    std::vector<uint8_t> zip; put(zip,0x04034b50); put(zip,20); put(zip,8); zip.resize(14);
    put(zip,crc32(0,raw.data(),raw.size())); put(zip,packed.size()); put(zip,raw.size()); put(zip,0);
    zip.insert(zip.end(),packed.begin(),packed.end());
    DepotPlan plan;
    assert(read_depot_manifest(zip.data(),zip.size(),1929291,4836465726223256507ULL,plan));
    assert(plan.files==1 && plan.bytes==96 && plan.encrypted_names && plan.chunks.size()==1 && plan.chunks[0].compressed==64);
    assert(!read_depot_manifest(zip.data(),zip.size(),42,4836465726223256507ULL,plan));
    for(size_t i=0;i<zip.size();++i) assert(!read_depot_manifest(zip.data(),i,1929291,4836465726223256507ULL,plan));
    zip[14]^=1; assert(!read_depot_manifest(zip.data(),zip.size(),1929291,4836465726223256507ULL,plan));
}
