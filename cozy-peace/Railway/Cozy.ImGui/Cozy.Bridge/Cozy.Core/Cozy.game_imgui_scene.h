/* Cozy central native text imports. */
#include "../../Cozy.Strings/Cozy.Strings.Bridge.h"
#line 1
/* Cozy central native text imports. */
#line 1
/* Cozy central native text imports. */
#line 1
/* Fixed, authenticated presentation only. Static catalogue text never accepts
   executable paths or external content. START requests a local visual action;
   the host owns authorization, its bounded presentation state and all session authority. */
#ifndef COZY_GAME_IMGUI_SCENE_H
#define COZY_GAME_IMGUI_SCENE_H

static ImU32 cozy_scene_alpha(ImU32 color,float alpha) {
    const unsigned a=(color>>24)&255u;
    return (color&0x00ffffffu)|(static_cast<unsigned>(a*ImClamp(alpha,0.0f,1.0f))<<24);
}
static ImU32 cozy_scene_mix(ImU32 a,ImU32 b,float t) {
    t=ImClamp(t,0.0f,1.0f);unsigned out=0;
    for(unsigned shift=0;shift<32;shift+=8){const float from=static_cast<float>((a>>shift)&255u),to=static_cast<float>((b>>shift)&255u);
        out|=static_cast<unsigned>(from+(to-from)*t)<<shift;}
    return out;
}
static float cozy_scene_font_size(float requested) {
    // Every text path uses a size baked at create, including fractional DPI.
    const float sizes[]={10,13,16.25f,19.5f,22.75f,26,32.5f,39,52,78,104};
    float result=sizes[0],distance=game_fabsf(requested-result);
    for(unsigned i=1;i<sizeof(sizes)/sizeof(sizes[0]);++i){const float d=game_fabsf(requested-sizes[i]);if(d<distance){result=sizes[i];distance=d;}}
    return result;
}
static void cozy_scene_label(GameImGuiContext* c,ImDrawList* draw,const char* text,
 float x,float y,float size,ImU32 color) {
    draw->AddText(c->bounded_font,cozy_scene_font_size(size),ImVec2(ImFloor(x+0.5f),ImFloor(y+0.5f)),color,text);
}
static void cozy_scene_center(GameImGuiContext* c,ImDrawList* draw,const char* text,
 float center,float y,float size,ImU32 color) {
    size=cozy_scene_font_size(size);
    const ImVec2 measured=c->bounded_font->CalcTextSizeA(size,FLT_MAX,0,text);
    cozy_scene_label(c,draw,text,center-measured.x*0.5f,y,size,color);
}
static void cozy_scene_paragraph(GameImGuiContext* c,ImDrawList* draw,const char* text,
 float x,float y,float width,float size,ImU32 color) {
    draw->AddText(c->bounded_font,cozy_scene_font_size(size),ImVec2(ImFloor(x+0.5f),ImFloor(y+0.5f)),color,text,0,width);
}
static float cozy_scene_ease(float value,float target,float delta,bool reduced) {
    if(reduced)return target;
    return value+(target-value)*(1.0f-static_cast<float>(game_pow(0.0000061442123533,delta)));
}
static float cozy_scene_reveal_amount(float elapsed) {
    const float remaining=1.0f-ImClamp(elapsed/0.45f,0.0f,1.0f);
    return 1.0f-remaining*remaining*remaining*remaining;
}
static void cozy_scene_reveal_draw(ImDrawList* draw,int first_vertex,int first_command,
 const ImVec2& display,float amount) {
    // Only this scene's draw data is transformed. Item hit targets remain at
    // their final positions and are disabled until the reveal is complete.
    const float scale=0.14f+0.86f*amount;const ImVec2 center(display.x*0.5f,display.y*0.5f);
    const int last_command=draw->CmdBuffer.Size;draw->AddDrawCmd();
    for(int i=first_vertex;i<draw->VtxBuffer.Size;++i){ImDrawVert& vertex=draw->VtxBuffer[i];
      vertex.pos=ImVec2(center.x+(vertex.pos.x-center.x)*scale,center.y+(vertex.pos.y-center.y)*scale);
      vertex.col=cozy_scene_alpha(vertex.col,amount);}
    for(int i=first_command;i<last_command;++i){ImDrawCmd& command=draw->CmdBuffer[i];if(!command.ElemCount)continue;
      ImVec4& clip=command.ClipRect;
      clip=ImVec4(center.x+(clip.x-center.x)*scale,center.y+(clip.y-center.y)*scale,
        center.x+(clip.z-center.x)*scale,center.y+(clip.w-center.y)*scale);}
}
struct CozySceneCard {const char* title;const char* category;const char* description;ImU32 accent;};
static const CozySceneCard CozySceneCards[]={
    {COZY_TEXT_GAME_IMGUI_SCENE_PUBG_E0D9363F,COZY_TEXT_GAME_IMGUI_SCENE_BATTLE_ROYALE_9561DC7D,COZY_TEXT_GAME_IMGUI_SCENE_KRAFTON_S_BATTLE_ROYALE_NSCAVENGE_PLAN_AND_SURVI_AFD98A0F,IM_COL32(236,176,74,255)},
    {COZY_TEXT_GAME_IMGUI_SCENE_TALESRUNNER_B67227B0,COZY_TEXT_GAME_IMGUI_SCENE_ADVENTURE_RACING_81111004,COZY_TEXT_GAME_IMGUI_SCENE_RHAON_S_CASUAL_RACING_NADVENTURE_SET_IN_A_NFAIRY_2F3F5D51,IM_COL32(92,189,246,255)},
    {COZY_TEXT_GAME_IMGUI_SCENE_LOST_SAGA_F05D966E,COZY_TEXT_GAME_IMGUI_SCENE_TEAM_ACTION_FA85F861,COZY_TEXT_GAME_IMGUI_SCENE_BUILD_A_TEAM_OF_HEROES_NAND_SWITCH_BETWEEN_THEM__8D0BAC6D,IM_COL32(154,103,218,255)},
    {COZY_TEXT_GAME_IMGUI_SCENE_APEX_LEGENDS_DF6FAF1A,COZY_TEXT_GAME_IMGUI_SCENE_HERO_BATTLE_ROYALE_E604CB00,COZY_TEXT_GAME_IMGUI_SCENE_RESPAWN_S_BATTLE_ROYALE_NWITH_DISTINCT_LEGENDS_N_C700E12E,IM_COL32(216,71,75,255)},
    {COZY_TEXT_GAME_IMGUI_SCENE_OVERWATCH_341E8091,COZY_TEXT_GAME_IMGUI_SCENE_TEAM_ACTION_FA85F861,COZY_TEXT_GAME_IMGUI_SCENE_BLIZZARD_S_TEAM_BASED_NACTION_GAME_WITH_NDISTINC_F64B2CDE,IM_COL32(248,160,61,255)},
    {COZY_TEXT_GAME_IMGUI_SCENE_COUNTER_STRIKE_2_F233088A,COZY_TEXT_GAME_IMGUI_SCENE_COMPETITIVE_FPS_546C816A,COZY_TEXT_GAME_IMGUI_SCENE_VALVE_S_COMPETITIVE_FPS_NTEAM_TACTICS_MEET_NPREC_DF5BF859,IM_COL32(232,144,53,255)},
    {COZY_TEXT_GAME_IMGUI_SCENE_BATTLEYE_706417B6,COZY_TEXT_GAME_IMGUI_SCENE_ANTI_CHEAT_F5852C6D,COZY_TEXT_GAME_IMGUI_SCENE_AN_ANTI_CHEAT_SYSTEM_NTHAT_DETECTS_AND_HELPS_NPR_D09A1CC9,IM_COL32(224,188,28,255)},
    {COZY_TEXT_GAME_IMGUI_SCENE_XIGNCODE3_5CF9C19E,COZY_TEXT_GAME_IMGUI_SCENE_GAME_SECURITY_8E6E9A8B,COZY_TEXT_GAME_IMGUI_SCENE_WELLBIA_S_GAME_SECURITY_NSOLUTION_FOR_PROTECTING_3FB1BA88,IM_COL32(239,44,58,255)},
    {COZY_TEXT_GAME_IMGUI_SCENE_EASY_ANTI_CHEAT_516F3A4A,COZY_TEXT_GAME_IMGUI_SCENE_ANTI_CHEAT_F5852C6D,COZY_TEXT_GAME_IMGUI_SCENE_EPIC_GAMES_ANTI_CHEAT_NSERVICE_SUPPORTING_NFAIR__407816F5,IM_COL32(35,161,221,255)},
    {COZY_TEXT_GAME_IMGUI_SCENE_RIOT_VANGUARD_00AB6A50,COZY_TEXT_GAME_IMGUI_SCENE_GAME_SECURITY_8E6E9A8B,COZY_TEXT_GAME_IMGUI_SCENE_RIOT_GAMES_SECURITY_NSOFTWARE_SUPPORTING_FAIR_NC_ADB3B525,IM_COL32(255,71,87,255)},
    {COZY_TEXT_GAME_IMGUI_SCENE_RICOCHET_9C627143,COZY_TEXT_GAME_IMGUI_SCENE_ANTI_CHEAT_F5852C6D,COZY_TEXT_GAME_IMGUI_SCENE_CALL_OF_DUTY_S_ANTI_CHEAT_NAPPROACH_USES_CLIENT__B05F5149,IM_COL32(111,184,201,255)},
    {COZY_TEXT_GAME_IMGUI_SCENE_ACE_972CC7E5,COZY_TEXT_GAME_IMGUI_SCENE_GAME_SECURITY_8E6E9A8B,COZY_TEXT_GAME_IMGUI_SCENE_ANTI_CHEAT_EXPERT_OFFERS_NGAME_SECURITY_FOR_NPC__861B9B0C,IM_COL32(73,137,248,255)},
    {COZY_TEXT_GAME_IMGUI_SCENE_ROBLOX_4F3308B5,COZY_TEXT_GAME_IMGUI_SCENE_CREATIVE_WORLDS_2455EDDF,COZY_TEXT_GAME_IMGUI_SCENE_DISCOVER_COMMUNITY_WORLDS_NCREATE_AND_PLAY_WITH__FF787052,IM_COL32(235,238,246,255)},
    {COZY_TEXT_GAME_IMGUI_SCENE_BRAWL_STARS_739EF121,COZY_TEXT_GAME_IMGUI_SCENE_TEAM_ACTION_FA85F861,COZY_TEXT_GAME_IMGUI_SCENE_FAST_MULTIPLAYER_BATTLES_NWITH_A_COLORFUL_ROSTER_92E048D5,IM_COL32(247,196,53,255)},
    {COZY_TEXT_GAME_IMGUI_SCENE_PUBG_MOBILE_2FC19130,COZY_TEXT_GAME_IMGUI_SCENE_BATTLE_ROYALE_9561DC7D,COZY_TEXT_GAME_IMGUI_SCENE_THE_MOBILE_BATTLEFIELD_NPLAN_EXPLORE_AND_SURVIVE_3A248CF3,IM_COL32(240,171,63,255)},
    {COZY_TEXT_GAME_IMGUI_SCENE_GENSHIN_IMPACT_6B5BE08C,COZY_TEXT_GAME_IMGUI_SCENE_OPEN_WORLD_RPG_509168B5,COZY_TEXT_GAME_IMGUI_SCENE_EXPLORE_TEYVAT_AND_DISCOVER_NAN_ELEMENTAL_ADVENT_6A6BDC61,IM_COL32(119,184,220,255)},
    {COZY_TEXT_GAME_IMGUI_SCENE_POKEMON_GO_6E54CBE6,COZY_TEXT_GAME_IMGUI_SCENE_REAL_WORLD_ADVENTURE_C8761CCE,COZY_TEXT_GAME_IMGUI_SCENE_EXPLORE_YOUR_SURROUNDINGS_NFIND_POKEMON_AND_JOIN_DE31513F,IM_COL32(91,194,159,255)},
    {COZY_TEXT_GAME_IMGUI_SCENE_CLASH_ROYALE_F9ABA5DC,COZY_TEXT_GAME_IMGUI_SCENE_STRATEGY_DUELS_354020E1,COZY_TEXT_GAME_IMGUI_SCENE_BUILD_A_BATTLE_DECK_AND_NCHALLENGE_OPPONENTS_IN__AD4288E7,IM_COL32(102,159,241,255)}
};
static int cozy_scene_tab_base(int tab) {return tab==1?12:tab==2?6:0;}
static void cozy_scene_center_bold(GameImGuiContext* c,ImDrawList* draw,const char* text,
 float center,float y,float size,ImU32 color,float scale) {
    // A bounded subpixel glyph stroke thickens the reviewed atlas without
    // duplicating the full Korean font or growing the locked glyph cache.
    cozy_scene_center(c,draw,text,center-0.28f*scale,y,size,color);
    cozy_scene_center(c,draw,text,center+0.28f*scale,y,size,color);
}
static void cozy_scene_glow(ImDrawList* draw,ImVec2 center,ImVec2 radius,ImU32 color) {
    for(int i=36;i>0;--i){const float k=i/36.0f;
        draw->AddEllipseFilled(center,ImVec2(radius.x*k,radius.y*k),cozy_scene_alpha(color,0.011f),0,48);}
}
// Percentage is supplied by the host. The local clock moves only the water;
// it cannot complete authentication, grant a product or advance pending work.
static float cozy_scene_progress(float current,float target,float delta,bool complete) {
    const float ceiling=complete?1.0f:0.99f;
    target=ImMax(ImClamp(current,0.0f,ceiling),ImClamp(target,0.0f,ceiling));
    if(complete&&target==1.0f)return 1.0f;
    const float next=ImMax(current,cozy_scene_ease(current,target,delta,false));
    return target-next<0.0005f?target:next;
}
static void cozy_scene_liquid(GameImGuiContext* c,ImDrawList* draw,ImVec2 center,
 float scale,float progress,float time,ImU32 accent,float alpha) {
    const float radius=47*scale,inner=43.5f*scale;
    progress=ImClamp(progress,0.0f,1.0f);
    cozy_scene_glow(draw,center,ImVec2(65*scale,65*scale),cozy_scene_alpha(accent,0.24f*alpha));
    draw->AddCircleFilled(center,radius,cozy_scene_alpha(IM_COL32(12,14,22,239),alpha),128);
    c->scene_wave_draw=draw;c->scene_wave_first_vertex=draw->VtxBuffer.Size;
    c->scene_wave_x=center.x;c->scene_wave_y=center.y;c->scene_wave_radius=inner;
    // Each narrow convex strip is clipped analytically against the circle.
    // A whole sinusoid is concave and must never enter AddConvexPolyFilled.
    const ImDrawListFlags saved_flags=draw->Flags;draw->Flags&=~ImDrawListFlags_AntiAliasedFill;
    const int strips=128;const float level=center.y+inner*(1-2*progress);
    const float amplitude=game_sinf(progress*3.1415926536f)*inner*0.065f;
    for(int layer=0;layer<2;++layer){
      const ImU32 color=cozy_scene_alpha(cozy_scene_mix(accent,IM_COL32(224,235,255,255),layer?0.12f:0.28f),(layer?0.70f:0.32f)*alpha);
      for(int i=0;i<strips;++i){
        const float x0=-inner+2*inner*i/strips,x1=-inner+2*inner*(i+1)/strips;
        const float half0=game_sqrtf(ImMax(0.0f,inner*inner-x0*x0)),half1=game_sqrtf(ImMax(0.0f,inner*inner-x1*x1));
        const float phase=time*(layer?-2.1f:1.55f)+layer*2.3f;
        const float y0=ImClamp(level+game_sinf(x0/inner*3.8f+phase)*amplitude,center.y-half0,center.y+half0);
        const float y1=ImClamp(level+game_sinf(x1/inner*3.8f+phase)*amplitude,center.y-half1,center.y+half1);
        if(y0>=center.y+half0&&y1>=center.y+half1)continue;
        draw->AddQuadFilled(ImVec2(center.x+x0,y0),ImVec2(center.x+x1,y1),
          ImVec2(center.x+x1,center.y+half1),ImVec2(center.x+x0,center.y+half0),color);
      }
    }
    draw->Flags=saved_flags;c->scene_wave_last_vertex=draw->VtxBuffer.Size;
    draw->AddCircle(center,radius,cozy_scene_alpha(accent,0.60f*alpha),128,1.2f*scale);
    draw->AddCircle(center,inner,cozy_scene_alpha(IM_COL32(242,247,255,100),0.30f*alpha),128,0.65f*scale);
    const int percent=ImClamp(static_cast<int>(game_floorf(progress*100+0.0001f)),0,100);c->scene_wave_percent=percent;
    char label[5];int length=0;
    if(percent==100)label[length++]='1';
    if(percent>=10)label[length++]=static_cast<char>('0'+(percent/10)%10);
    label[length++]=static_cast<char>('0'+percent%10);label[length++]='%';label[length]=0;
    const float y=center.y-cozy_scene_font_size(26*scale)*0.5f;
    cozy_scene_center_bold(c,draw,label,center.x,y+1.2f*scale,26*scale,cozy_scene_alpha(IM_COL32(8,10,18,180),alpha),scale);
    cozy_scene_center_bold(c,draw,label,center.x,y,26*scale,cozy_scene_alpha(IM_COL32(251,252,255,255),alpha),scale);
}
#ifdef GAME_IMGUI_PORTABLE_TEST
extern "C" int game_imgui_test_wave_state(GameImGuiHandle handle,float* values,unsigned count) {
    GameApiCall call;if(!call)return 0;GameImGuiContext* c=game_context(handle);if(!c||!values||count!=10)return 0;
    for(unsigned i=0;i<count;++i)values[i]=0;
    values[0]=c->scene_wave_draw?1.0f:0.0f;values[1]=c->scene_run_progress;values[2]=static_cast<float>(c->scene_wave_percent);
    values[3]=c->scene_wave_x;values[4]=c->scene_wave_y;values[5]=c->scene_wave_radius;values[9]=c->license_hint_visible?1.0f:0.0f;
    if(c->scene_wave_draw){const ImDrawList* draw=c->scene_wave_draw;
      values[6]=static_cast<float>(c->scene_wave_last_vertex-c->scene_wave_first_vertex);
      for(int i=c->scene_wave_first_vertex;i<c->scene_wave_last_vertex;++i){const ImVec2 p=draw->VtxBuffer[i].pos;
        const float dx=p.x-c->scene_wave_x,dy=p.y-c->scene_wave_y;
        values[7]=ImMax(values[7],dx*dx+dy*dy);values[8]+=dx*0.001f+dy*(i-c->scene_wave_first_vertex+1)*0.00001f;}}
    return 1;
}
#endif
static ImTextureRef cozy_scene_texture(GameImGuiContext* c,int index,bool blurred=false) {
#ifndef GAME_IMGUI_PORTABLE_TEST
    return ImTextureRef(static_cast<ImTextureID>(reinterpret_cast<uintptr_t>(blurred?c->scene_blurs[index]:c->scene_images[index])));
#else
    (void)c;return ImTextureRef(static_cast<ImTextureID>(index+(blurred?20:2)));
#endif
}
static void cozy_scene_art(GameImGuiContext* c,ImDrawList* draw,int index,
 const ImVec2& min,const ImVec2& max,float radius,float alpha,bool blurred=false) {
    const float source_aspect=static_cast<float>(GameSceneImageWidth)/GameSceneImageHeight;
    const float aspect=(max.x-min.x)/(max.y-min.y);ImVec2 uv0(0,0),uv1(1,1);
    if(aspect>source_aspect){const float crop=(1.0f-source_aspect/aspect)*0.5f;uv0.y=crop;uv1.y=1-crop;}
    else {const float crop=(1.0f-aspect/source_aspect)*0.5f;uv0.x=crop;uv1.x=1-crop;}
    draw->AddImageRounded(cozy_scene_texture(c,index,blurred),min,max,uv0,uv1,
      IM_COL32(255,255,255,static_cast<int>(255*alpha)),radius);
}
static void cozy_scene_logo(ImDrawList* draw,float s,float ox,float oy,ImU32 accent) {
    draw->PathLineTo(ImVec2(ox+24*s,oy+43*s));draw->PathLineTo(ImVec2(ox+36*s,oy+32*s));
    draw->PathBezierCubicCurveTo(ImVec2(ox+33*s,oy+37*s),ImVec2(ox+38*s,oy+42*s),ImVec2(ox+42*s,oy+48*s),8);
    draw->PathBezierCubicCurveTo(ImVec2(ox+44*s,oy+53*s),ImVec2(ox+42*s,oy+55*s),ImVec2(ox+40*s,oy+58*s),6);
    draw->PathFillConcave(IM_COL32(247,247,250,255));
    draw->PathLineTo(ImVec2(ox+38*s,oy+28*s));draw->PathLineTo(ImVec2(ox+53*s,oy+43*s));draw->PathLineTo(ImVec2(ox+43*s,oy+54*s));
    draw->PathBezierCubicCurveTo(ImVec2(ox+47*s,oy+48*s),ImVec2(ox+42*s,oy+43*s),ImVec2(ox+38*s,oy+38*s),8);
    draw->PathBezierCubicCurveTo(ImVec2(ox+35*s,oy+33*s),ImVec2(ox+36*s,oy+31*s),ImVec2(ox+38*s,oy+28*s),6);
    draw->PathFillConcave(accent);
}
static void cozy_scene_tab_icon(ImDrawList* draw,int tab,ImVec2 center,float s,ImU32 color) {
    if(tab==0){
      const ImVec2 star[]={ImVec2(center.x,center.y-6*s),ImVec2(center.x+1.7f*s,center.y-1.7f*s),ImVec2(center.x+6*s,center.y),ImVec2(center.x+1.7f*s,center.y+1.7f*s),ImVec2(center.x,center.y+6*s),ImVec2(center.x-1.7f*s,center.y+1.7f*s),ImVec2(center.x-6*s,center.y),ImVec2(center.x-1.7f*s,center.y-1.7f*s)};
      draw->AddConcavePolyFilled(star,8,color);draw->AddCircleFilled(ImVec2(center.x+6.5f*s,center.y-5*s),1.1f*s,color,12);
    } else if(tab==1){
      draw->AddRect(ImVec2(center.x-4.4f*s,center.y-6.5f*s),ImVec2(center.x+4.4f*s,center.y+6.5f*s),color,2*s,0,1.2f*s);
      draw->AddLine(ImVec2(center.x-1.5f*s,center.y+4.1f*s),ImVec2(center.x+1.5f*s,center.y+4.1f*s),color,1.1f*s);
    } else {
      const ImVec2 shield[]={ImVec2(center.x,center.y-6.5f*s),ImVec2(center.x+5.5f*s,center.y-4*s),ImVec2(center.x+4.4f*s,center.y+2.8f*s),ImVec2(center.x,center.y+6.5f*s),ImVec2(center.x-4.4f*s,center.y+2.8f*s),ImVec2(center.x-5.5f*s,center.y-4*s)};
      draw->AddPolyline(shield,6,color,ImDrawFlags_Closed,1.25f*s);
      draw->AddLine(ImVec2(center.x-2.2f*s,center.y),ImVec2(center.x-0.5f*s,center.y+1.8f*s),color,1.2f*s);
      draw->AddLine(ImVec2(center.x-0.5f*s,center.y+1.8f*s),ImVec2(center.x+2.5f*s,center.y-2*s),color,1.2f*s);
    }
}
static void cozy_scene_spinner(ImDrawList* draw,ImVec2 center,float s,float time) {
    draw->AddCircle(center,6.8f*s,IM_COL32(40,40,45,45),36,1.7f*s);
    draw->PathArcTo(center,6.8f*s,time*7.0f,time*7.0f+4.45f,32);
    draw->PathStroke(IM_COL32(28,28,33,255),0,1.7f*s);
}
static float cozy_scene_wrap(float position) {while(position>=6)position-=6;while(position<0)position+=6;return position;}
static float cozy_scene_nearest(float target,float position) {while(target-position>3)target-=6;while(target-position<-3)target+=6;return target;}
static float cozy_scene_weight(float distance) {const float p=ImMax(0.0f,1.0f-game_fabsf(distance));return p*p*(3-2*p);}
static float cozy_scene_width(float distance) {return 150+26*cozy_scene_weight(distance);}
static float cozy_scene_card_x(int slot,float position) {
    const int base=static_cast<int>(ImFloor(position));const float fraction=position-base;
    const float separation=(cozy_scene_width(base-position)+cozy_scene_width(base+1-position))*0.5f+13;
    float x=-fraction*separation;
    if(slot>base)for(int n=base;n<slot;++n)x+=(cozy_scene_width(n-position)+cozy_scene_width(n+1-position))*0.5f+13;
    else for(int n=base;n>slot;--n)x-=(cozy_scene_width(n-position)+cozy_scene_width(n-1-position))*0.5f+13;
    return x;
}
static void cozy_scene_card_text(GameImGuiContext* c,ImDrawList* draw,int index,const ImVec2& a,const ImVec2& b,float s,float detail) {
    if(detail<=0.001f)return;
    const CozySceneCard& card=CozySceneCards[index];const float width=b.x-a.x;
    draw->PushClipRect(ImVec2(a.x+7*s,a.y+7*s),ImVec2(b.x-7*s,b.y-7*s),true);
    if(detail>0.001f){
      const ImU32 text=cozy_scene_alpha(IM_COL32(248,249,252,255),detail);
      cozy_scene_center(c,draw,card.category,(a.x+b.x)*0.5f,a.y+24*s,10*s,cozy_scene_alpha(card.accent,detail));
      cozy_scene_center(c,draw,card.title,(a.x+b.x)*0.5f,a.y+49*s,13*s,text);
      draw->AddLine(ImVec2(a.x+18*s,a.y+79*s),ImVec2(b.x-18*s,a.y+79*s),cozy_scene_alpha(IM_COL32(235,240,250,55),detail),s);
      cozy_scene_paragraph(c,draw,card.description,a.x+15*s,a.y+97*s,width-30*s,13*s,text);
      cozy_scene_center(c,draw,COZY_TEXT_GAME_IMGUI_SCENE_CLICK_TO_CLOSE_64671117,(a.x+b.x)*0.5f,b.y-28*s,10*s,cozy_scene_alpha(IM_COL32(224,229,239,190),detail));
    }
    draw->PopClipRect();
}
static int32_t cozy_scene_frame(GameImGuiContext* c,int32_t phase,int32_t selected,uint32_t flags,
 float animation_seconds,float carousel_position,int32_t licensed_card,float run_progress,bool legacy) {
    const int tab_requested=static_cast<int>((flags>>4)&3);
    if(!c||c->license_only||!c->canvas_started||c->scene_drawn||c->widgets||c->text_bytes||phase<0||phase>3||selected<0||selected>5||
       (flags&~55u)!=0||tab_requested>2||licensed_card< -1||licensed_card>17||
       !(run_progress>=0&&run_progress<=1)||!(animation_seconds>=0&&animation_seconds<=86400)||!(carousel_position>=-1&&carousel_position<=6)||
       game_imgui_runtime_failed||game_imgui_dx11_failed||!game_memory_ready(c))return -1;
    if(c->scene_tab!=tab_requested){c->scene_tab=tab_requested;c->scene_detail_open=false;c->scene_detail_mix=0;
      c->scene_drag_pending=false;c->scene_dragging=false;c->scene_drag_moved=false;c->scene_velocity=0;}
    // This fixed surface reserves the full caller-side legacy admission budget.
    c->scene_drawn=true;c->widgets=8;c->text_bytes=512;
    const ImVec2 display=ImGui::GetIO().DisplaySize;
    const float s=ImMin(display.x/680.0f,display.y/440.0f);if(!(s>0))return -1;
    const float ox=(display.x-680*s)*0.5f,oy=(display.y-440*s)*0.5f;
    const bool reduced=(flags&2)!=0;
    const float delta=ImGui::GetIO().DeltaTime;
    const bool was_revealing=c->scene_reveal_seconds<0.45f;
    c->scene_reveal_seconds=reduced?0.45f:ImMin(0.45f,c->scene_reveal_seconds+delta);
    const bool revealing=c->scene_reveal_seconds<0.45f;
    const float reveal=cozy_scene_reveal_amount(c->scene_reveal_seconds);
    const bool enabled=!revealing&&(phase==0||phase==3)&&(flags&4)!=0;
    if(was_revealing&&!revealing){ImGui::ClearActiveID();c->focus_requested=true;}
    if(!reduced)c->scene_motion_time=animation_seconds;
    const float t=c->scene_motion_time;
    if(c->scene_phase!=phase){if(phase==1||phase==0||phase==3)c->scene_run_progress=0;c->scene_phase=phase;c->scene_entry=0;c->focus_requested=enabled;ImGui::ClearActiveID();
      c->scene_drag_pending=false;c->scene_dragging=false;c->scene_drag_moved=false;c->scene_velocity=0;}
    if(!enabled){c->scene_drag_pending=false;c->scene_dragging=false;c->scene_drag_moved=false;c->scene_velocity=0;}
    c->scene_reduced=reduced;c->scene_entry=cozy_scene_ease(c->scene_entry,1,delta,reduced);
    if(!c->scene_position_ready){c->scene_position=cozy_scene_wrap(carousel_position);c->scene_position_ready=true;c->scene_host_selected=selected;}
    if(c->scene_host_selected!=selected){c->scene_detail_open=false;c->scene_host_selected=selected;}
    c->scene_detail_mix=cozy_scene_ease(c->scene_detail_mix,c->scene_detail_open?1.0f:0.0f,delta,reduced);
    const float color_position=cozy_scene_wrap(c->scene_position),color_fraction=color_position-ImFloor(color_position);
    const int color_first=static_cast<int>(ImFloor(color_position)),base=cozy_scene_tab_base(c->scene_tab);
    const ImU32 desired=cozy_scene_mix(CozySceneCards[base+color_first].accent,CozySceneCards[base+(color_first+1)%6].accent,color_fraction);
    ImU32 accent=0xff000000u;
    for(int n=0;n<3;++n){const float value=static_cast<float>((desired>>(n*8))&255u);
      c->scene_accent[n]=!c->scene_accent_ready?value:cozy_scene_ease(c->scene_accent[n],value,delta,reduced);
      accent|=static_cast<unsigned>(c->scene_accent[n])<<(n*8);}
    c->scene_accent_ready=true;
    ImDrawList* draw=ImGui::GetWindowDrawList();
    if(revealing)draw->AddDrawCmd();
    const int reveal_vertex=draw->VtxBuffer.Size,reveal_command=draw->CmdBuffer.Size-1;
    draw->AddRectFilled(ImVec2(0,0),display,IM_COL32(10,10,13,255),6*s);
    const float wave=static_cast<float>(game_sin(t*0.90f)),wave2=static_cast<float>(game_sin(t*0.61f+1.7f));
    cozy_scene_glow(draw,ImVec2(ox+(340+wave*185)*s,oy+(-25+wave2*25)*s),ImVec2(590*s,235*s),accent);
    cozy_scene_glow(draw,ImVec2(ox+(290-wave2*245)*s,oy+8*s),ImVec2(360*s,145*s),cozy_scene_mix(accent,IM_COL32(142,154,184,255),0.25f));
    cozy_scene_logo(draw,s,ox,oy,accent);
    // The entitlement title is independent of the card the user browses.
    // Keep it on the logo's centerline, in the free header area to the right
    // of all three tabs; no badge or secondary license/status label.
    if(licensed_card>=0){const char* title=CozySceneCards[licensed_card].title;
      float size=cozy_scene_font_size(13*s);ImVec2 measured=c->bounded_font->CalcTextSizeA(size,FLT_MAX,0,title);
      if(measured.x>164*s){size=cozy_scene_font_size(10*s);measured=c->bounded_font->CalcTextSizeA(size,FLT_MAX,0,title);}
      draw->PushClipRect(ImVec2(ox+488*s,oy+24*s),ImVec2(ox+656*s,oy+62*s),true);
      cozy_scene_label(c,draw,title,ox+654*s-measured.x,oy+43*s-measured.y*0.5f,size,IM_COL32(202,199,215,255));
      draw->PopClipRect();}
    int32_t actions=0;const ImGuiIO& io=ImGui::GetIO();c->scene_control_index=0;
    ImGui::PushStyleColor(ImGuiCol_NavCursor,ImVec4(0,0,0,0));
    const char* const tab_ids[]={COZY_TEXT_GAME_IMGUI_SCENE_SCENECLEANNERV2_0975B65B,COZY_TEXT_GAME_IMGUI_SCENE_SCENEMOBILEV3_A9EF177C,COZY_TEXT_GAME_IMGUI_SCENE_SCENESPOOFERV2_C5B6453E};
    const char* const tab_labels[]={COZY_TEXT_GAME_IMGUI_SCENE_CLEANNER_A530EAA9,COZY_TEXT_GAME_IMGUI_SCENE_MOBILE_919A3FCF,COZY_TEXT_GAME_IMGUI_SCENE_SPOOFER_EF1042EF};
    // All three labels share the diamond logo's visual center at y=43.
    for(int tab=0;tab<3;++tab){const float x=ox+(208+tab*88)*s,y=oy+26.5f*s;
      ImGui::SetCursorPos(ImVec2(x,y));ImGui::BeginDisabled(!enabled);
      const bool click=ImGui::InvisibleButton(tab_ids[tab],ImVec2(88*s,33*s),ImGuiButtonFlags_EnableNav);
      const bool hover=enabled&&(ImGui::IsItemHovered()||ImGui::IsItemFocused());if(ImGui::IsItemFocused())c->scene_control_index=1+tab;ImGui::EndDisabled();
      c->scene_hovers[7+tab]=cozy_scene_ease(c->scene_hovers[7+tab],hover?1.0f:0.0f,delta,reduced);
      if(click&&enabled&&c->scene_tab!=tab){actions=1<<(13+tab);c->scene_tab=tab;
        c->scene_detail_open=false;c->scene_detail_mix=0;c->scene_drag_pending=false;c->scene_dragging=false;c->scene_drag_moved=false;c->scene_velocity=0;}
      const float strength=tab==c->scene_tab?1.0f:0.48f+c->scene_hovers[7+tab]*0.28f;
      const ImU32 label=cozy_scene_alpha(IM_COL32(242,237,248,255),strength);
      const float size=cozy_scene_font_size(16.25f*s);
      const ImVec2 text=c->bounded_font->CalcTextSizeA(size,FLT_MAX,0,tab_labels[tab]);
      const float group_width=14*s+7*s+text.x,group_x=x+(88*s-group_width)*0.5f;
      cozy_scene_tab_icon(draw,tab,ImVec2(group_x+7*s,y+16.5f*s),s,label);
      cozy_scene_label(c,draw,tab_labels[tab],group_x+21*s,y+(33*s-text.y)*0.5f,size,label);
    }
    c->scene_tab_position=cozy_scene_ease(c->scene_tab_position,static_cast<float>(c->scene_tab),delta,reduced);
    const float underline=ox+(212+88*c->scene_tab_position)*s;
    draw->AddRectFilled(ImVec2(underline,oy+63*s),ImVec2(underline+80*s,oy+64.5f*s),cozy_scene_alpha(accent,0.90f),0.75f*s);
    const ImVec2 band_min(0,oy+94*s),band_max(display.x,oy+355*s);
    const bool art_hover=io.MousePos.x>=band_min.x&&io.MousePos.x<=band_max.x&&io.MousePos.y>=band_min.y&&io.MousePos.y<=band_max.y;
    const float spacing=176*s;
    if(enabled&&art_hover&&ImGui::IsMouseClicked(0)){
      c->scene_drag_pending=true;c->scene_dragging=false;c->scene_drag_moved=false;
      c->scene_drag_origin=c->scene_position;c->scene_drag_last=c->scene_position;c->scene_velocity=0;
    }
    bool released_drag=false,suppress_click=false;float target=cozy_scene_nearest(static_cast<float>(selected),c->scene_position);
    if(c->scene_drag_pending){const ImVec2 movement=ImGui::GetMouseDragDelta(0,0);
      if(game_fabsf(movement.x)>6*s||game_fabsf(movement.y)>6*s)c->scene_drag_moved=true;
      if(!c->scene_dragging&&game_fabsf(movement.x)>6*s&&game_fabsf(movement.x)>game_fabsf(movement.y)*1.1f){c->scene_dragging=true;c->scene_detail_open=false;}
      suppress_click=c->scene_drag_moved;
      if(c->scene_dragging){const float next=c->scene_drag_origin-ImClamp(movement.x/spacing,-5.75f,5.75f);
        const float speed=ImClamp((next-c->scene_drag_last)/ImMax(0.001f,delta),-10.0f,10.0f);
        c->scene_velocity=cozy_scene_ease(c->scene_velocity,speed,delta,false);c->scene_position=next;c->scene_drag_last=next;}
      if(ImGui::IsMouseReleased(0)){released_drag=c->scene_dragging;
        if(released_drag){const float momentum=reduced?0:ImClamp(c->scene_velocity*0.10f,-0.65f,0.65f);
          target=ImFloor(c->scene_position+momentum+0.5f);const int index=(static_cast<int>(target)%6+6)%6;actions=128<<index;c->scene_host_selected=index;}
        c->scene_drag_pending=false;c->scene_dragging=false;c->scene_drag_moved=false;c->scene_velocity=0;
      }else if(!ImGui::IsMouseDown(0)){c->scene_drag_pending=false;c->scene_dragging=false;c->scene_drag_moved=false;c->scene_velocity=0;suppress_click=true;}
    }
    if(!c->scene_dragging){c->scene_position=cozy_scene_ease(c->scene_position,target,delta,reduced);
      if(game_fabsf(c->scene_position-target)<0.0001f)c->scene_position=target;c->scene_position=cozy_scene_wrap(c->scene_position);}
    const float position=c->scene_position;const int first=static_cast<int>(ImFloor(position))-2;int order[6]={0,1,2,3,4,5};
    for(int i=0;i<5;++i)for(int j=i+1;j<6;++j)if(game_fabsf(first+order[i]-position)<game_fabsf(first+order[j]-position)){const int swap=order[i];order[i]=order[j];order[j]=swap;}
    const char* const ids[]={COZY_TEXT_GAME_IMGUI_SCENE_SCENETILE0_ECCC69D2,COZY_TEXT_GAME_IMGUI_SCENE_SCENETILE1_087C8596,COZY_TEXT_GAME_IMGUI_SCENE_SCENETILE2_A8EF7311,COZY_TEXT_GAME_IMGUI_SCENE_SCENETILE3_6116E31A,COZY_TEXT_GAME_IMGUI_SCENE_SCENETILE4_78C714A9,COZY_TEXT_GAME_IMGUI_SCENE_SCENETILE5_27800BDA};
    draw->PushClipRect(band_min,band_max,true);
    for(int pass=0;pass<6;++pass){const int slot=first+order[pass],index=(slot%6+6)%6,art=cozy_scene_tab_base(c->scene_tab)+index;
      const float distance=static_cast<float>(slot)-position,weight=cozy_scene_weight(distance),w=cozy_scene_width(distance)*s,h=(225+26*weight)*s;
      const float cx=display.x*0.5f+cozy_scene_card_x(slot,position)*s,cy=oy+224*s;
      const ImVec2 a(cx-w*0.5f,cy-h*0.5f),b(cx+w*0.5f,cy+h*0.5f);
      ImGui::SetCursorPos(a);ImGui::BeginDisabled(!enabled);
      const bool click=ImGui::InvisibleButton(ids[index],ImVec2(w,h),ImGuiButtonFlags_EnableNav);
      const bool hover=enabled&&ImGui::IsItemHovered(),focused=ImGui::IsItemFocused();ImGui::EndDisabled();
      c->scene_hovers[index]=cozy_scene_ease(c->scene_hovers[index],hover||focused?1.0f:0.0f,delta,reduced);
      const float lift=c->scene_hovers[index]*2*s;const ImVec2 image_min(a.x,a.y-lift),image_max(b.x,b.y-lift);
      const float detail=c->scene_detail_index==art?c->scene_detail_mix:0;
      // The frosted texture is the opaque base while details are open. Drawing
      // it over an opaque sharp base leaves an antialiased sharp rim at edges.
      cozy_scene_art(c,draw,art,image_min,image_max,4*s,1,detail>0.001f);
      if(detail>0.001f){
        if(detail<0.999f)cozy_scene_art(c,draw,art,image_min,image_max,4*s,1-detail,false);
        draw->AddRectFilled(image_min,image_max,cozy_scene_alpha(IM_COL32(18,24,35,210),detail),4*s);
        draw->AddRectFilled(image_min,image_max,cozy_scene_alpha(IM_COL32(215,228,247,22),detail),4*s);}
      const float muted=(1-weight)*0.56f;draw->AddRectFilled(image_min,image_max,IM_COL32(12,12,18,static_cast<int>(muted*255)),4*s);
      cozy_scene_card_text(c,draw,art,image_min,image_max,s,detail);
      if(click&&enabled&&!suppress_click&&!released_drag){
        const bool centered=index==selected&&game_fabsf(distance)<0.025f;
        actions=128<<index;c->scene_host_selected=index;
        if(!centered){c->scene_detail_open=false;c->scene_detail_mix=0;}
        else if(c->scene_detail_open&&c->scene_detail_index==art)c->scene_detail_open=false;
        else {c->scene_detail_index=art;c->scene_detail_open=true;c->scene_detail_mix=0;}}
    }
    draw->PopClipRect();const float wheel=io.MouseWheelH!=0?io.MouseWheelH:-io.MouseWheel;
    if(enabled&&art_hover&&wheel!=0&&!c->scene_drag_pending){actions=wheel>0?4:2;c->scene_detail_open=false;}
    const bool start_allowed=enabled&&licensed_card==cozy_scene_tab_base(c->scene_tab)+selected&&
      game_fabsf(cozy_scene_nearest(static_cast<float>(selected),c->scene_position)-c->scene_position)<0.025f;
    const float bx=display.x*0.5f-75*s,by=oy+377*s,bw=150*s,bh=42*s;
    ImGui::SetCursorPos(ImVec2(bx,by));ImGui::BeginDisabled(!start_allowed);
    const bool run=ImGui::InvisibleButton(COZY_TEXT_GAME_IMGUI_SCENE_SCENERUNV2_83AA90DF,ImVec2(bw,bh),ImGuiButtonFlags_EnableNav);
    const bool run_hover=start_allowed&&ImGui::IsItemHovered(),run_focus=ImGui::IsItemFocused(),run_active=ImGui::IsItemActive();
    if(c->focus_requested&&start_allowed){ImGui::SetItemDefaultFocus();ImGui::SetFocusID(ImGui::GetItemID(),ImGui::GetCurrentWindow());ImGui::FocusWindow(ImGui::GetCurrentWindow());c->focus_requested=false;}
    ImGui::EndDisabled();c->scene_hovers[6]=cozy_scene_ease(c->scene_hovers[6],run_hover?1.0f:run_focus?0.25f:0.0f,delta,reduced);
    const float lift=c->scene_hovers[6]*1.3f*s,press=run_active?0.8f*s:0;
    const ImVec2 button_min(bx,by-lift+press),button_max(bx+bw,by+bh-lift+press);
    const ImU32 button=start_allowed?cozy_scene_mix(accent,IM_COL32(247,247,251,255),0.82f+c->scene_hovers[6]*0.15f):IM_COL32(32,33,40,255);
    if(start_allowed)cozy_scene_glow(draw,ImVec2(bx+bw*0.5f,by+bh*0.5f),ImVec2(88*s,29*s),cozy_scene_alpha(accent,0.30f));
    draw->AddRectFilled(button_min,button_max,button,7*s);
    draw->AddRect(button_min,button_max,cozy_scene_alpha(start_allowed?IM_COL32(255,255,255,255):IM_COL32(113,114,127,255),start_allowed?0.30f:0.18f),7*s,0,s);
    cozy_scene_center_bold(c,draw,COZY_TEXT_GAME_IMGUI_SCENE_START_778F8907,bx+bw*0.5f,by+(bh-cozy_scene_font_size(16.25f*s))*0.5f-lift+press,16.25f*s,start_allowed?IM_COL32(23,23,29,255):IM_COL32(112,113,124,255),s);
    if(run&&start_allowed)actions=8;ImGui::PopStyleColor();
    if(phase==1||phase==2){
      c->scene_blur_active=true;c->scene_foreground=ImGui::GetForegroundDrawList();ImDrawList* overlay=c->scene_foreground;
      const float alpha=c->scene_entry;overlay->AddRectFilled(ImVec2(0,0),display,cozy_scene_alpha(IM_COL32(7,8,13,54),alpha));
      c->scene_run_progress=cozy_scene_progress(c->scene_run_progress,phase==2?run_progress:0,delta,phase==2);
      cozy_scene_liquid(c,overlay,ImVec2(display.x*0.5f,display.y*0.5f),s,c->scene_run_progress,
        reduced?0:static_cast<float>(ImGui::GetTime()),accent,alpha);
      actions=0;
    }
    if(revealing)cozy_scene_reveal_draw(draw,reveal_vertex,reveal_command,display,reveal);
    return game_imgui_runtime_failed?-1:actions;
}
extern "C" int32_t GAME_IMGUI_CALL game_imgui_scene_v3(GameImGuiHandle handle,int32_t phase,int32_t selected,uint32_t flags,
 float animation_seconds,float carousel_position,int32_t licensed_card,float run_progress) GAME_IMGUI_NOEXCEPT {
    GameApiCall call;if(!call)return -1;
    return cozy_scene_frame(game_context(handle),phase,selected,flags,animation_seconds,carousel_position,licensed_card,run_progress,false);
}
extern "C" int32_t GAME_IMGUI_CALL game_imgui_scene_v2(GameImGuiHandle handle,int32_t phase,int32_t selected,uint32_t flags,
 float animation_seconds,float carousel_position) GAME_IMGUI_NOEXCEPT {
    GameApiCall call;if(!call||flags>7)return -1;GameImGuiContext* c=game_context(handle);if(!c)return -1;
    // Legacy diagnostic callers have no product entitlement and cannot START.
    return cozy_scene_frame(c,phase,selected,flags|(static_cast<uint32_t>(c->scene_tab)<<4),animation_seconds,carousel_position,-1,0,true);
}
#ifdef GAME_IMGUI_PORTABLE_TEST
extern "C" int game_imgui_test_scene_entitlement(GameImGuiHandle handle,float* values,unsigned count) {
    GameApiCall call;if(!call||!game_context(handle)||!values||count!=5)return 0;
    const ImDrawData* data=ImGui::GetDrawData();if(!data||!data->Valid)return 0;
    const float s=ImMin(data->DisplaySize.x/680.0f,data->DisplaySize.y/440.0f);
    const float ox=(data->DisplaySize.x-680*s)*0.5f,oy=(data->DisplaySize.y-440*s)*0.5f;
    values[0]=0;values[1]=values[2]=FLT_MAX;values[3]=values[4]=-FLT_MAX;
    for(int n=0;n<data->CmdListsCount;++n){const ImDrawList* draw=data->CmdLists[n];
      for(int i=0;i<draw->CmdBuffer.Size;++i){const ImDrawCmd& command=draw->CmdBuffer[i];
        if(game_fabsf(command.ClipRect.x-(ox+488*s))>0.01f||game_fabsf(command.ClipRect.y-(oy+24*s))>0.01f)continue;
        values[0]+=command.ElemCount;
        for(unsigned j=0;j<command.ElemCount;++j){const ImDrawVert& v=draw->VtxBuffer[command.VtxOffset+draw->IdxBuffer[command.IdxOffset+j]];
          values[1]=ImMin(values[1],v.pos.x);values[2]=ImMin(values[2],v.pos.y);values[3]=ImMax(values[3],v.pos.x);values[4]=ImMax(values[4],v.pos.y);}}}
    return 1;
}
extern "C" int game_imgui_test_scene_reveal(GameImGuiHandle handle,float* values,unsigned count) {
    GameApiCall call;if(!call)return 0;GameImGuiContext* c=game_context(handle);if(!c||!values||count!=3)return 0;
    values[0]=c->scene_reveal_seconds;values[2]=cozy_scene_reveal_amount(c->scene_reveal_seconds);
    values[1]=0.14f+0.86f*values[2];return 1;
}
extern "C" int game_imgui_test_scene_draw_bounds(GameImGuiHandle handle,float* values,unsigned count) {
    GameApiCall call;if(!call||!game_context(handle)||!values||count!=6)return 0;
    const ImDrawData* data=ImGui::GetDrawData();if(!data||!data->Valid)return 0;
    values[0]=values[1]=FLT_MAX;values[2]=values[3]=-FLT_MAX;values[4]=values[5]=0;
    for(int n=0;n<data->CmdListsCount;++n){const ImDrawList* draw=data->CmdLists[n];
      for(int i=0;i<draw->VtxBuffer.Size;++i){const ImDrawVert& v=draw->VtxBuffer[i];
        values[0]=ImMin(values[0],v.pos.x);values[1]=ImMin(values[1],v.pos.y);
        values[2]=ImMax(values[2],v.pos.x);values[3]=ImMax(values[3],v.pos.y);values[4]=ImMax(values[4],static_cast<float>(v.col>>24));}
      for(int i=0;i<draw->CmdBuffer.Size;++i){const ImDrawCmd& command=draw->CmdBuffer[i];if(!command.ElemCount)continue;
        const ImVec4& r=command.ClipRect;if(!(r.x<=r.z&&r.y<=r.w))values[5]+=1;}}
    return 1;
}
#endif
#endif
