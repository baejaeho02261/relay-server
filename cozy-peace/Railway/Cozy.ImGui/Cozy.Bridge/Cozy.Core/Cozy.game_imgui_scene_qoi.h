/* Bounded QOI v1 decoder for immutable scene RGBA8 assets.
   Specification: https://qoiformat.org/qoi-specification.pdf
   No allocations, platform calls or external codec dependency. The scene
   profile is RGBA, sRGB with linear alpha, at most 512 x 768 pixels. */
#ifndef COZY_GAME_IMGUI_SCENE_QOI_H
#define COZY_GAME_IMGUI_SCENE_QOI_H
#include <stddef.h>
#include <stdint.h>

static bool game_scene_decode_qoi(const unsigned char* source,size_t source_bytes,
                                 unsigned char* output,size_t output_bytes,
                                 unsigned width,unsigned height) {
    if(!source||!output||!width||!height||width>512||height>768)return false;
    const size_t pixels=static_cast<size_t>(width)*height;
    if(output_bytes!=pixels*4||source_bytes<22||source_bytes>pixels*5+22)return false;
    if(source[0]!=0x71||source[1]!=0x6f||source[2]!=0x69||source[3]!=0x66)return false;
    const uint32_t encoded_width=(uint32_t(source[4])<<24)|(uint32_t(source[5])<<16)|(uint32_t(source[6])<<8)|source[7];
    const uint32_t encoded_height=(uint32_t(source[8])<<24)|(uint32_t(source[9])<<16)|(uint32_t(source[10])<<8)|source[11];
    if(encoded_width!=width||encoded_height!=height||source[12]!=4||source[13]!=0)return false;
    const size_t end=source_bytes-8;
    for(size_t i=end;i<source_bytes-1;++i)if(source[i]!=0)return false;
    if(source[source_bytes-1]!=1)return false;
    struct Pixel { unsigned char r,g,b,a; };
    Pixel index[64]={};
    Pixel pixel={0,0,0,255};
    size_t at=14,written=0;
    while(written<pixels) {
        if(at>=end)return false;
        const unsigned char chunk=source[at++];
        size_t count=1;
        if(chunk==0xfe) {
            if(end-at<3)return false;
            pixel.r=source[at++];pixel.g=source[at++];pixel.b=source[at++];
        } else if(chunk==0xff) {
            if(end-at<4)return false;
            pixel.r=source[at++];pixel.g=source[at++];pixel.b=source[at++];pixel.a=source[at++];
        } else switch(chunk&0xc0) {
        case 0x00:pixel=index[chunk&0x3f];break;
        case 0x40:
            pixel.r=static_cast<unsigned char>(pixel.r+((chunk>>4)&3)-2);
            pixel.g=static_cast<unsigned char>(pixel.g+((chunk>>2)&3)-2);
            pixel.b=static_cast<unsigned char>(pixel.b+(chunk&3)-2);break;
        case 0x80: {
            if(at>=end)return false;
            const unsigned char next=source[at++];
            const int dg=int(chunk&0x3f)-32;
            pixel.r=static_cast<unsigned char>(pixel.r+dg+int(next>>4)-8);
            pixel.g=static_cast<unsigned char>(pixel.g+dg);
            pixel.b=static_cast<unsigned char>(pixel.b+dg+int(next&15)-8);break;
        }
        default:count=size_t(chunk&0x3f)+1;break;
        }
        if(count>pixels-written)return false;
        index[(unsigned(pixel.r)*3+unsigned(pixel.g)*5+unsigned(pixel.b)*7+unsigned(pixel.a)*11)&63]=pixel;
        for(size_t i=0;i<count;++i) {
            const size_t offset=written++*4;
            output[offset]=pixel.r;output[offset+1]=pixel.g;output[offset+2]=pixel.b;output[offset+3]=pixel.a;
        }
    }
    return at==end;
}
#endif
