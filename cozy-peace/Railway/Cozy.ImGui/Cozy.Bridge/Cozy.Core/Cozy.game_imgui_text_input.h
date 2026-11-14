#ifndef COZY_GAME_IMGUI_TEXT_INPUT_H
#define COZY_GAME_IMGUI_TEXT_INPUT_H
#include <stddef.h>
#include <stdint.h>

/* Opt-in, application-focused Korean text transport. No clipboard, file,
   keyboard hook, OS context, allocation, or borrowed pointer is retained.
   The caller supplies already delivered window/IME events. */
static const uint32_t CozyTextBytes = 512;
struct CozyTextInput {
    bool focused, composing;
    uint16_t high_surrogate;
    uint32_t committed_bytes, composition_bytes;
    char committed[CozyTextBytes + 1], composition[CozyTextBytes + 1];
};
static void cozy_text_wipe(void* memory, size_t bytes) {
    volatile unsigned char* p=static_cast<volatile unsigned char*>(memory);
    while(bytes--)*p++=0;
}
static bool cozy_text_scalar(uint32_t cp) {
    return (cp>=32 && cp<=126) || (cp>=0x1100 && cp<=0x11FF) ||
        (cp>=0x3131 && cp<=0x318E) || (cp>=0xA960 && cp<=0xA97C) ||
        (cp>=0xAC00 && cp<=0xD7A3) || (cp>=0xD7B0 && cp<=0xD7FB);
}
static bool cozy_text_decode(const char* text,uint32_t bytes,uint32_t& offset,uint32_t& cp) {
    if(!text || offset>=bytes)return false;
    uint32_t first=static_cast<unsigned char>(text[offset]),need=0;
    if(first<0x80){cp=first;need=1;}
    else if(first>=0xC2 && first<=0xDF){cp=first&31;need=2;}
    else if(first>=0xE0 && first<=0xEF){cp=first&15;need=3;}
    else if(first>=0xF0 && first<=0xF4){cp=first&7;need=4;}
    else return false;
    if(need>bytes-offset)return false;
    for(uint32_t j=1;j<need;++j){uint32_t b=static_cast<unsigned char>(text[offset+j]);if((b&0xC0)!=0x80)return false;cp=(cp<<6)|(b&63);}
    if((need==2 && cp<0x80)||(need==3 && cp<0x800)||(need==4 && cp<0x10000)||
       cp>0x10FFFF||(cp>=0xD800 && cp<=0xDFFF)||!cozy_text_scalar(cp))return false;
    offset+=need;return true;
}
static bool cozy_text_utf8(const char* text,uint32_t bytes) {
    if(bytes>CozyTextBytes || (!text && bytes))return false;
    uint32_t at=0,cp=0;while(at<bytes)if(!cozy_text_decode(text,bytes,at,cp))return false;
    return true;
}
static void cozy_text_reset(CozyTextInput* s,bool focused) {
    if(!s)return;
    cozy_text_wipe(s,sizeof(*s));s->focused=focused;
}
/* action: 0 append committed text, 1 replace preedit, 2 begin, 3 end,
   4 cancel all pending input. End never promotes preedit to committed text. */
static bool cozy_text_event(CozyTextInput* s,int32_t action,const char* text,uint32_t bytes) {
    if(!s || !s->focused || action<0 || action>4)return false;
    if(action>=2){
        if(bytes)return false;
        if(action==4){cozy_text_reset(s,true);return true;}
        cozy_text_wipe(s->composition,sizeof(s->composition));s->composition_bytes=0;
        s->high_surrogate=0;s->composing=(action==2);return true;
    }
    if(!cozy_text_utf8(text,bytes) || s->high_surrogate)return false;
    if(action==1){
        if(!s->composing)return false;
        cozy_text_wipe(s->composition,sizeof(s->composition));
        for(uint32_t i=0;i<bytes;++i)s->composition[i]=text[i];
        s->composition_bytes=bytes;return true;
    }
    if(bytes>CozyTextBytes-s->committed_bytes)return false;
    for(uint32_t i=0;i<bytes;++i)s->committed[s->committed_bytes+i]=text[i];
    s->committed_bytes+=bytes;s->committed[s->committed_bytes]=0;
    cozy_text_wipe(s->composition,sizeof(s->composition));s->composition_bytes=0;
    return true;
}
/* A UTF-16 stream never replaces invalid sequences with a different character.
   Supplementary scalars are structurally checked but outside Korean v1. */
static bool cozy_text_utf16(CozyTextInput* s,uint32_t unit) {
    if(!s || !s->focused)return false;
    if(unit>0xFFFF){s->high_surrogate=0;return false;}
    if(s->high_surrogate){
        const uint32_t high=s->high_surrogate;s->high_surrogate=0;
        if(unit<0xDC00||unit>0xDFFF)return false;
        const uint32_t cp=0x10000+((high-0xD800)<<10)+(unit-0xDC00);
        return cozy_text_scalar(cp); // v1 rejects every supplementary scalar
    }
    if(unit>=0xD800 && unit<=0xDBFF){s->high_surrogate=static_cast<uint16_t>(unit);return true;}
    if(!cozy_text_scalar(unit))return false;
    char utf8[3];uint32_t n=0;
    if(unit<0x80)utf8[n++]=static_cast<char>(unit);
    else if(unit<0x800){utf8[n++]=static_cast<char>(0xC0|(unit>>6));utf8[n++]=static_cast<char>(0x80|(unit&63));}
    else {utf8[n++]=static_cast<char>(0xE0|(unit>>12));utf8[n++]=static_cast<char>(0x80|((unit>>6)&63));utf8[n++]=static_cast<char>(0x80|(unit&63));}
    const bool ok=cozy_text_event(s,0,utf8,n);cozy_text_wipe(utf8,sizeof(utf8));return ok;
}
static int32_t cozy_text_read(CozyTextInput* s,uint32_t kind,void* output,uint32_t bytes) {
    if(!s || !s->focused || !output || kind>1 || bytes!=CozyTextBytes+1)return -1;
    char* target=static_cast<char*>(output);cozy_text_wipe(target,bytes);
    const uint32_t n=kind?s->composition_bytes:s->committed_bytes;
    const char* source=kind?s->composition:s->committed;
    for(uint32_t i=0;i<n;++i)target[i]=source[i];
    if(!kind){cozy_text_wipe(s->committed,sizeof(s->committed));s->committed_bytes=0;}
    return static_cast<int32_t>(n);
}
#endif
