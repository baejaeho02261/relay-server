/* Cozy central native text imports. */
#include "../../Cozy.Strings/Cozy.Strings.Tests.h"
#line 1
/* Cozy central native text imports. */
#line 1
/* Cozy central native text imports. */
#line 1
// Standalone C++11 codec/asset verification; no graphics device is required.
#include <cassert>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <limits>
#include <vector>
#include "../../Cozy.Bridge/Cozy.Core/Cozy.game_imgui_scene_qoi.h"
#include "../../Cozy.Bridge/Cozy.Core/Cozy.game_imgui_scene_assets.h"

typedef std::vector<unsigned char> Bytes;
static Bytes stream(unsigned width,unsigned height,const Bytes& chunks) {
    Bytes data={0x71,0x6f,0x69,0x66,0,0,0,0,0,0,0,0,4,0};
    for(unsigned n=0;n<4;++n){data[7-n]=static_cast<unsigned char>(width>>(n*8));data[11-n]=static_cast<unsigned char>(height>>(n*8));}
    data.insert(data.end(),chunks.begin(),chunks.end());
    const unsigned char end[]={0,0,0,0,0,0,0,1};data.insert(data.end(),end,end+8);return data;
}
static bool guarded(const Bytes& data,unsigned width,unsigned height,const Bytes* expected=0) {
    const size_t size=size_t(width)*height*4;
    Bytes output(size+32,0xcd);
    const bool ok=game_scene_decode_qoi(data.data(),data.size(),output.data()+16,size,width,height);
    for(size_t n=0;n<16;++n){assert(output[n]==0xcd);assert(output[size+16+n]==0xcd);}
    if(expected){assert(ok);assert(expected->size()==size);assert(std::memcmp(expected->data(),output.data()+16,size)==0);}
    return ok;
}
static void malformed_tests() {
    // RGB, DIFF, LUMA, RGBA, INDEX and RUN in one stream, including alpha cache.
    const Bytes chunks={0xfe,10,20,30,0x76,0xa3,0x69,0xff,1,2,3,4,9,0xc1};
    const Bytes expected={10,20,30,255,11,19,30,255,12,22,34,255,1,2,3,4,10,20,30,255,10,20,30,255,10,20,30,255};
    const Bytes valid=stream(7,1,chunks);guarded(valid,7,1,&expected);
    const Bytes wrapped={254,254,254,255};guarded(stream(1,1,Bytes{0x40}),1,1,&wrapped);
    const Bytes zero={0,0,0,0};guarded(stream(1,1,Bytes{0}),1,1,&zero);
    const Bytes black(62*4,0);Bytes opaque=black;for(size_t at=3;at<opaque.size();at+=4)opaque[at]=255;
    guarded(stream(62,1,Bytes{0xfd}),62,1,&opaque);
    // Every truncation of a multi-opcode valid stream fails without writing past output.
    for(size_t n=0;n<valid.size();++n)assert(!guarded(Bytes(valid.begin(),valid.begin()+n),7,1));
    for(size_t n=valid.size()-8;n<valid.size();++n){Bytes changed=valid;changed[n]^=1;assert(!guarded(changed,7,1));}
    for(unsigned offset=0;offset<14;++offset){Bytes changed=valid;changed[offset]^=0x80;assert(!guarded(changed,7,1));}
    Bytes trailing=valid;trailing.push_back(0);assert(!guarded(trailing,7,1));
    Bytes redundant=valid;redundant.insert(redundant.end()-8,0xc0);assert(!guarded(redundant,7,1));
    assert(!guarded(stream(1,1,Bytes{}),1,1));
    assert(!guarded(stream(2,1,Bytes{0xc0}),2,1));
    assert(!guarded(stream(1,1,Bytes{0xc1}),1,1));
    assert(!guarded(stream(1,1,Bytes{0xfe,1,2}),1,1));
    assert(!guarded(stream(1,1,Bytes{0xff,1,2,3}),1,1));
    assert(!guarded(stream(1,1,Bytes{0xa0}),1,1));
    unsigned char out[28]={};
    assert(!game_scene_decode_qoi(0,valid.size(),out,sizeof(out),7,1));
    assert(!game_scene_decode_qoi(valid.data(),valid.size(),0,sizeof(out),7,1));
    assert(!game_scene_decode_qoi(valid.data(),valid.size(),out,sizeof(out)-1,7,1));
    assert(!game_scene_decode_qoi(valid.data(),valid.size(),out,sizeof(out)+1,7,1));
    assert(!game_scene_decode_qoi(valid.data(),std::numeric_limits<size_t>::max(),out,sizeof(out),7,1));
    assert(!game_scene_decode_qoi(valid.data(),valid.size(),out,sizeof(out),0,1));
    assert(!game_scene_decode_qoi(valid.data(),valid.size(),out,sizeof(out),513,1));
    assert(!game_scene_decode_qoi(valid.data(),valid.size(),out,sizeof(out),1,769));
    assert(!game_scene_decode_qoi(valid.data(),valid.size(),out,sizeof(out),~0u,~0u));
    // Deterministic adversarial chunk streams exercise all tags with guarded output.
    unsigned state=0x514f4931;
    for(unsigned n=0;n<20000;++n){Bytes random;const size_t length=n%81;
        for(size_t i=0;i<length;++i){state=state*1664525u+1013904223u;random.push_back(static_cast<unsigned char>(state>>24));}
        guarded(stream(16,1,random),16,1);
    }
}
struct Asset {const unsigned char* bytes;size_t size;unsigned width,height;const char* name;};
#define SCENE_ASSET(n) {GameSceneImage##n,sizeof(GameSceneImage##n),512,768,"art" #n}, {GameSceneBlur##n,sizeof(GameSceneBlur##n),128,192,"blur" #n}
static const Asset assets[]={SCENE_ASSET(0),SCENE_ASSET(1),SCENE_ASSET(2),SCENE_ASSET(3),SCENE_ASSET(4),SCENE_ASSET(5),SCENE_ASSET(6),SCENE_ASSET(7),SCENE_ASSET(8),SCENE_ASSET(9),SCENE_ASSET(10),SCENE_ASSET(11),SCENE_ASSET(12),SCENE_ASSET(13),SCENE_ASSET(14),SCENE_ASSET(15),SCENE_ASSET(16),SCENE_ASSET(17)};
static_assert(sizeof(assets)/sizeof(assets[0])==GameSceneImageCount*2,COZY_TEXT_TEST_SCENE_QOI_EVERY_SCENE_IMAGE_AND_BLUR_MUST_BE_DECODED_785596C8);
int main(int argc,char** argv) {
    assert(argc==2);malformed_tests();size_t packed=0,decoded=0;
    for(size_t n=0;n<sizeof(assets)/sizeof(assets[0]);++n){const Asset& asset=assets[n];
        Bytes output(size_t(asset.width)*asset.height*4+32,0xcd);
        assert(game_scene_decode_qoi(asset.bytes,asset.size,output.data()+16,output.size()-32,asset.width,asset.height));
        for(size_t i=0;i<16;++i){assert(output[i]==0xcd);assert(output[output.size()-16+i]==0xcd);}
        char path[4096];const int length=std::snprintf(path,sizeof(path),COZY_TEXT_TEST_SCENE_QOI_S_S_RGBA_81F33BAF,argv[1],asset.name);assert(length>0&&size_t(length)<sizeof(path));
        FILE* file=std::fopen(path,COZY_TEXT_TEST_SCENE_QOI_WB_735A62E4);assert(file);assert(std::fwrite(output.data()+16,1,output.size()-32,file)==output.size()-32);assert(std::fclose(file)==0);
        packed+=asset.size;decoded+=output.size()-32;
    }
    std::printf(COZY_TEXT_TEST_SCENE_QOI_QOI_C_PASS_ZU_ASSETS_ZU_PACKED_BYTES_ZU_EXACT_RG_3C7D74A0,sizeof(assets)/sizeof(assets[0]),packed,decoded);
}
