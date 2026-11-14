/* Cozy central native text imports. */
#include "../../Cozy.Strings/Cozy.Strings.Bridge.h"
#line 1
/* Cozy central native text imports. */
#line 1
/* Compact B activation view. The host owns the secret and server result;
   this renderer sees only a bounded length and a presentation phase. */
#ifndef COZY_GAME_IMGUI_LICENSE_H
#define COZY_GAME_IMGUI_LICENSE_H
extern "C" int32_t GAME_IMGUI_CALL game_imgui_license_scene_v1(GameImGuiHandle handle,
 int32_t phase,int32_t key_characters,float run_progress) GAME_IMGUI_NOEXCEPT {
    GameApiCall call;if(!call)return -1;GameImGuiContext* c=game_context(handle);
    if(!c||!c->canvas_started||c->scene_drawn||c->widgets||c->text_bytes||phase<0||phase>3||
       key_characters<0||key_characters>100||!(run_progress>=0&&run_progress<=1)||
       game_imgui_runtime_failed||game_imgui_dx11_failed||!game_memory_ready(c))return -1;
    c->scene_drawn=true;c->widgets=8;c->text_bytes=512;
    const ImGuiIO& io=ImGui::GetIO();const ImVec2 display=io.DisplaySize;
    const float s=ImMin(display.x/340.0f,display.y/380.0f),ox=(display.x-340*s)*0.5f,oy=(display.y-380*s)*0.5f;
    if(!(s>0))return -1;
    // ImGui otherwise focuses the first navigable item one frame after the
    // panel appears. Preserve the empty hint until explicit click/tab/retry.
    if(!c->license_focus_ready){c->focus_requested=false;GImGui->NavInitRequest=false;
      GImGui->NavInitResult.Clear();ImGui::NavUpdateAnyRequestFlag();}
    const bool enabled=phase==0||phase==2;const float delta=io.DeltaTime,t=static_cast<float>(ImGui::GetTime());
    if(c->scene_phase!=phase){c->scene_phase=phase;c->scene_entry=0;ImGui::ClearActiveID();
      if(phase!=3)c->scene_run_progress=0;
      if(phase==2)c->focus_requested=true;}
    c->scene_entry=cozy_scene_ease(c->scene_entry,1.0f,delta,false);
    ImDrawList* draw=ImGui::GetWindowDrawList();const ImU32 accent=IM_COL32(177,154,236,255);
    draw->AddRectFilled(ImVec2(0,0),display,IM_COL32(10,10,13,255),6*s);
    // Same two broad, continuously moving top light fields as the O gallery.
    const float wave=game_sinf(t*0.90f),wave2=game_sinf(t*0.61f+1.7f);
    cozy_scene_glow(draw,ImVec2(ox+(170+wave*92.5f)*s,oy+(-12.5f+wave2*12.5f)*s),ImVec2(295*s,166*s),accent);
    cozy_scene_glow(draw,ImVec2(ox+(145-wave2*122.5f)*s,oy+4*s),ImVec2(230*s,113*s),cozy_scene_mix(accent,IM_COL32(142,154,184,255),0.25f));
    cozy_scene_logo(draw,s,ox+131*s,oy+29*s,accent);
    cozy_scene_center_bold(c,draw,COZY_TEXT_GAME_IMGUI_LICENSE_LICENSE_ACTIVATION_264434F8,ox+170*s,oy+110*s,19.5f*s,IM_COL32(246,246,249,255),s);
    cozy_scene_center(c,draw,COZY_TEXT_GAME_IMGUI_LICENSE_ENTER_YOUR_LICENSE_KEY_TO_CONTINUE_D8CB9FDD,ox+170*s,oy+139*s,10*s,IM_COL32(143,143,153,255));
    int32_t actions=0;ImGui::PushStyleColor(ImGuiCol_NavCursor,ImVec4(0,0,0,0));
    const ImVec2 field_min(ox+49*s,oy+185*s),field_max(ox+291*s,oy+227*s);
    const bool inside=io.MousePos.x>=field_min.x&&io.MousePos.x<field_max.x&&io.MousePos.y>=field_min.y&&io.MousePos.y<field_max.y;
    const bool outside_click=enabled&&ImGui::IsMouseClicked(ImGuiMouseButton_Left)&&!inside;
    if(outside_click){ImGui::ClearActiveID();ImGui::SetNavID(0,GImGui->NavLayer,ImGui::GetCurrentWindow()->NavRootFocusScopeId,ImRect());c->focus_requested=false;}
    ImGui::SetCursorPos(field_min);ImGui::BeginDisabled(!enabled);
    const bool focus=ImGui::InvisibleButton(COZY_TEXT_GAME_IMGUI_LICENSE_LICENSEINPUTV1_DA1B4A82,ImVec2(242*s,42*s),ImGuiButtonFlags_EnableNav);
    if(c->focus_requested&&enabled){ImGui::SetItemDefaultFocus();ImGui::SetFocusID(ImGui::GetItemID(),ImGui::GetCurrentWindow());ImGui::FocusWindow(ImGui::GetCurrentWindow());c->focus_requested=false;}
    const bool input_focused=enabled&&ImGui::IsItemFocused(),input_hover=enabled&&ImGui::IsItemHovered(),input_active=enabled&&ImGui::IsItemActive();
    ImGui::EndDisabled();
    if(enabled){
      if(c->license_focus_ready&&input_focused!=c->license_field_focused)actions|=input_focused?4:8;
      c->license_field_focused=input_focused;c->license_focus_ready=true;
      if(focus)actions|=4;
    }
    c->scene_hovers[1]=cozy_scene_ease(c->scene_hovers[1],input_hover?1.0f:0.0f,delta,false);
    c->scene_hovers[2]=cozy_scene_ease(c->scene_hovers[2],input_focused?1.0f:0.0f,delta,false);
    c->scene_hovers[3]=cozy_scene_ease(c->scene_hovers[3],input_active?1.0f:0.0f,delta,false);
    const float focus_mix=c->scene_hovers[2],hover_mix=c->scene_hovers[1],press_mix=c->scene_hovers[3];
    if(focus_mix>0.001f)cozy_scene_glow(draw,ImVec2(ox+170*s,oy+206*s),ImVec2(133*s,29*s),cozy_scene_alpha(accent,0.10f*focus_mix));
    draw->AddRectFilled(field_min,field_max,cozy_scene_mix(IM_COL32(20,20,25,255),IM_COL32(31,29,42,255),hover_mix*0.3f+focus_mix*0.45f+press_mix*0.25f),7*s);
    draw->AddRect(field_min,field_max,cozy_scene_mix(IM_COL32(49,48,59,210),cozy_scene_alpha(accent,0.86f),focus_mix*0.75f+hover_mix*0.15f+press_mix*0.10f),7*s,0,s);
    // The glyph, mask and caret share the same centerline; long keys scroll
    // their mask rather than ever advancing the caret beyond the right clip.
    const float text_y=oy+206*s;const ImVec2 key(ox+67*s,text_y);
    const ImU32 key_color=cozy_scene_mix(IM_COL32(145,145,157,255),accent,focus_mix);
    draw->AddCircle(key,3.8f*s,key_color,24,1.3f*s);
    draw->AddLine(ImVec2(key.x+3.4f*s,key.y),ImVec2(key.x+10*s,key.y),key_color,1.3f*s);
    draw->AddLine(ImVec2(key.x+8*s,key.y),ImVec2(key.x+8*s,key.y+3*s),key_color,1.3f*s);
    const float text_left=ox+88*s,text_right=field_max.x-12*s,text_size=cozy_scene_font_size(13*s),spacing=6*s;
    const int capacity=ImMax(1,static_cast<int>((text_right-text_left-6*s)/spacing));
    c->license_mask_count=ImMin(key_characters,capacity);
    c->license_caret_x=text_left+c->license_mask_count*spacing;
    draw->PushClipRect(ImVec2(text_left-1*s,field_min.y+2*s),ImVec2(text_right+1*s,field_max.y-2*s),true);
    c->license_hint_visible=key_characters==0&&!input_focused;
    if(c->license_hint_visible)cozy_scene_label(c,draw,COZY_TEXT_GAME_IMGUI_LICENSE_LICENSE_KEY_D78819B2,text_left,text_y-text_size*0.5f,13*s,IM_COL32(124,124,135,255));
    else for(int i=0;i<c->license_mask_count;++i)draw->AddCircleFilled(ImVec2(text_left+(i+0.5f)*spacing,text_y),1.65f*s,IM_COL32(225,225,233,255),16);
    if(input_focused&&game_fmod(t,1.0)<0.55){const float x=ImFloor(c->license_caret_x+0.5f),half=text_size*0.5f;
      draw->AddLine(ImVec2(x,text_y-half),ImVec2(x,text_y+half),IM_COL32(232,229,248,255),s);}
    draw->PopClipRect();
    const bool can_submit=enabled&&key_characters>0;
    const ImVec2 hit_min(ox+49*s,oy+245*s);ImGui::SetCursorPos(hit_min);ImGui::BeginDisabled(!can_submit);
    const bool submit=ImGui::InvisibleButton(COZY_TEXT_GAME_IMGUI_LICENSE_LICENSEACTIVATEV1_E126F9F1,ImVec2(242*s,40*s),ImGuiButtonFlags_EnableNav);
    const bool hover=can_submit&&(ImGui::IsItemHovered()||ImGui::IsItemFocused()),pressed=can_submit&&ImGui::IsItemActive();ImGui::EndDisabled();
    c->scene_hovers[0]=cozy_scene_ease(c->scene_hovers[0],hover?1.0f:0.0f,delta,false);
    const float lift=c->scene_hovers[0]*1.3f*s,press=pressed?0.8f*s:0;
    const ImVec2 button_min(hit_min.x,hit_min.y-lift+press),button_max(ox+291*s,oy+285*s-lift+press);
    const ImU32 button=can_submit?cozy_scene_mix(accent,IM_COL32(247,247,251,255),0.82f+c->scene_hovers[0]*0.15f):IM_COL32(32,33,40,255);
    if(can_submit)cozy_scene_glow(draw,ImVec2(ox+170*s,oy+265*s),ImVec2(132*s,29*s),cozy_scene_alpha(accent,0.30f));
    draw->AddRectFilled(button_min,button_max,button,7*s);
    draw->AddRect(button_min,button_max,cozy_scene_alpha(can_submit?IM_COL32(255,255,255,255):IM_COL32(113,114,127,255),can_submit?0.30f:0.18f),7*s,0,s);
    cozy_scene_center_bold(c,draw,COZY_TEXT_GAME_IMGUI_LICENSE_ACTIVATE_B7F3E8D1,ox+170*s,oy+265*s-cozy_scene_font_size(16.25f*s)*0.5f-lift+press,16.25f*s,can_submit?IM_COL32(23,23,29,255):IM_COL32(112,113,124,255),s);
    if(submit&&can_submit)actions|=1;ImGui::PopStyleColor();
    if(phase==1||phase==3){
      c->scene_blur_active=true;c->scene_foreground=ImGui::GetForegroundDrawList();ImDrawList* overlay=c->scene_foreground;
      const float alpha=c->scene_entry;overlay->AddRectFilled(ImVec2(0,0),display,cozy_scene_alpha(IM_COL32(7,8,13,54),alpha));
      c->scene_run_progress=cozy_scene_progress(c->scene_run_progress,run_progress,delta,false);
      cozy_scene_liquid(c,overlay,ImVec2(display.x*0.5f,display.y*0.5f),s,c->scene_run_progress,t,accent,alpha);
      actions=0;
    }
    return game_imgui_runtime_failed?-1:actions;
}
#ifdef GAME_IMGUI_PORTABLE_TEST
extern "C" int game_imgui_test_license_state(GameImGuiHandle handle,float* values,unsigned count) {
    GameApiCall call;if(!call)return 0;GameImGuiContext* c=game_context(handle);if(!c||!values||count!=8)return 0;
    values[0]=c->license_field_focused?1.0f:0.0f;values[1]=c->scene_hovers[1];values[2]=c->scene_hovers[2];
    values[3]=c->license_caret_x;values[4]=static_cast<float>(c->license_mask_count);values[5]=c->scene_run_progress;
    values[6]=c->scene_blur_active?1.0f:0.0f;values[7]=c->scene_foreground?1.0f:0.0f;return 1;
}
#endif
#endif
