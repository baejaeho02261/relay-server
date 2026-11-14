#ifndef COZY_GAME_IMGUI_TEXTURE_H
#define COZY_GAME_IMGUI_TEXTURE_H
#include <stddef.h>
#include <stdint.h>

/* Font coverage is kept as Alpha8 on the CPU. The DX11 shader still receives
   ordinary white RGBA8 pixels, uploaded in bounded synchronous strips. No
   full RGBA copy or frame-sized stack allocation is required. */
static const size_t GameTextureUploadBytes = 256u * 1024u;
static uint32_t game_texture_strip_rows(uint32_t width,uint32_t remaining) {
    if(!width || width>16384u || !remaining)return 0;
    const size_t rows=GameTextureUploadBytes/(static_cast<size_t>(width)*4u);
    return remaining<rows?remaining:static_cast<uint32_t>(rows);
}
static bool game_texture_expand_alpha8(const unsigned char* source,size_t source_bytes,
 size_t source_pitch,uint32_t width,uint32_t rows,unsigned char* output,size_t output_bytes) {
    if(!source || !output || !width || width>16384u || !rows || rows>16384u || source_pitch<width)return false;
    const size_t rgba_pitch=static_cast<size_t>(width)*4u;
    if(rows>GameTextureUploadBytes/rgba_pitch || rows>output_bytes/rgba_pitch)return false;
    if(static_cast<size_t>(rows-1)>static_cast<size_t>(-1)/source_pitch)return false;
    const size_t last_row=static_cast<size_t>(rows-1)*source_pitch;
    if(last_row>source_bytes || width>source_bytes-last_row)return false;
    for(uint32_t y=0;y<rows;++y){
        const unsigned char* in=source+static_cast<size_t>(y)*source_pitch;
        unsigned char* out=output+static_cast<size_t>(y)*rgba_pitch;
        for(uint32_t x=0;x<width;++x){out[x*4u]=255;out[x*4u+1]=255;out[x*4u+2]=255;out[x*4u+3]=in[x];}
    }
    return true;
}
#endif
