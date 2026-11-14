/* Public editable literal constants. Source organization, not encryption. */
#ifndef COZY_NATIVE_STRINGS_BRIDGE_H
#define COZY_NATIVE_STRINGS_BRIDGE_H

/* Cozy.ImGui/Cozy.Bridge/Cozy.Graphics/Cozy.game_imgui_blur.h:43 */
#define COZY_TEXT_GAME_IMGUI_BLUR_CBUFFER_PARAMETERS_REGISTER_B0_FLOAT2_STEP_UV_FL_EBDF6E97 "cbuffer Parameters:register(b0){float2 step_uv;float2 padding;}"
/* Cozy.ImGui/Cozy.Bridge/Cozy.Graphics/Cozy.game_imgui_blur.h:49 */
#define COZY_TEXT_GAME_IMGUI_BLUR_C_IMAGE_SAMPLE_LINEAR_CLAMP_I_UV_STEP_UV_2_IMAGE_6CAEEF10 "c+=(image.Sample(linear_clamp,i.uv+step_uv*2)+image.Sample(linear_clamp,i.uv-step_uv*2))*0.1216216216;"
/* Cozy.ImGui/Cozy.Bridge/Cozy.Graphics/Cozy.game_imgui_blur.h:50 */
#define COZY_TEXT_GAME_IMGUI_BLUR_C_IMAGE_SAMPLE_LINEAR_CLAMP_I_UV_STEP_UV_3_IMAGE_72FCF534 "c+=(image.Sample(linear_clamp,i.uv+step_uv*3)+image.Sample(linear_clamp,i.uv-step_uv*3))*0.0540540541;"
/* Cozy.ImGui/Cozy.Bridge/Cozy.Graphics/Cozy.game_imgui_blur.h:51 */
#define COZY_TEXT_GAME_IMGUI_BLUR_C_IMAGE_SAMPLE_LINEAR_CLAMP_I_UV_STEP_UV_4_IMAGE_4CCAE707 "c+=(image.Sample(linear_clamp,i.uv+step_uv*4)+image.Sample(linear_clamp,i.uv-step_uv*4))*0.0162162162;return c;}"
/* Cozy.ImGui/Cozy.Bridge/Cozy.Graphics/Cozy.game_imgui_blur.h:48 */
#define COZY_TEXT_GAME_IMGUI_BLUR_C_IMAGE_SAMPLE_LINEAR_CLAMP_I_UV_STEP_UV_IMAGE_S_E89FE626 "c+=(image.Sample(linear_clamp,i.uv+step_uv)+image.Sample(linear_clamp,i.uv-step_uv))*0.1945945946;"
/* Cozy.ImGui/Cozy.Bridge/Cozy.Graphics/Cozy.game_imgui_blur.h:47 */
#define COZY_TEXT_GAME_IMGUI_BLUR_FLOAT4_PS_OUT_I_SV_TARGET_FLOAT4_C_IMAGE_SAMPLE__E610A091 "float4 ps(Out i):SV_Target{float4 c=image.Sample(linear_clamp,i.uv)*0.2270270270;"
/* Cozy.ImGui/Cozy.Bridge/Cozy.Graphics/Cozy.game_imgui_blur.h:45 */
#define COZY_TEXT_GAME_IMGUI_BLUR_OUT_VS_UINT_ID_SV_VERTEXID_OUT_O_FLOAT2_UV_FLOAT_DDF8F605 "Out vs(uint id:SV_VertexID){Out o;float2 uv=float2((id<<1)&2,id&2);"
/* Cozy.ImGui/Cozy.Bridge/Cozy.Graphics/Cozy.game_imgui_blur.h:46 */
#define COZY_TEXT_GAME_IMGUI_BLUR_O_UV_UV_O_POSITION_FLOAT4_UV_FLOAT2_2_2_FLOAT2_1_8BDD0C48 "o.uv=uv;o.position=float4(uv*float2(2,-2)+float2(-1,1),0,1);return o;}"
/* Cozy.ImGui/Cozy.Bridge/Cozy.Graphics/Cozy.game_imgui_blur.h:57 */
#define COZY_TEXT_GAME_IMGUI_BLUR_PS_4_0_4ADF516C "ps_4_0"
/* Cozy.ImGui/Cozy.Bridge/Cozy.Graphics/Cozy.game_imgui_blur.h:57 */
#define COZY_TEXT_GAME_IMGUI_BLUR_PS_CB4D0610 "ps"
/* Cozy.ImGui/Cozy.Bridge/Cozy.Graphics/Cozy.game_imgui_blur.h:44 */
#define COZY_TEXT_GAME_IMGUI_BLUR_STRUCT_OUT_FLOAT4_POSITION_SV_POSITION_FLOAT2_UV_E8415B30 "struct Out{float4 position:SV_POSITION;float2 uv:TEXCOORD0;};"
/* Cozy.ImGui/Cozy.Bridge/Cozy.Graphics/Cozy.game_imgui_blur.h:42 */
#define COZY_TEXT_GAME_IMGUI_BLUR_TEXTURE2D_IMAGE_REGISTER_T0_SAMPLERSTATE_LINEAR__36FF2330 "Texture2D image:register(t0);SamplerState linear_clamp:register(s0);"
/* Cozy.ImGui/Cozy.Bridge/Cozy.Graphics/Cozy.game_imgui_blur.h:53 */
#define COZY_TEXT_GAME_IMGUI_BLUR_VS_4_0_6663D4C8 "vs_4_0"
/* Cozy.ImGui/Cozy.Bridge/Cozy.Graphics/Cozy.game_imgui_blur.h:53 */
#define COZY_TEXT_GAME_IMGUI_BLUR_VS_CD707950 "vs"
/* Cozy.ImGui/Cozy.Bridge/Cozy.Core/Cozy.game_imgui_bridge.cpp:716 */
#define COZY_TEXT_GAME_IMGUI_BRIDGE_GAMEOVERLAYCANVAS_214A44D5 "##GameOverlayCanvas"
/* Cozy.ImGui/Cozy.Bridge/Cozy.Core/Cozy.game_imgui_bridge.cpp:519 */
#define COZY_TEXT_GAME_IMGUI_BRIDGE_GAME_DELPHI_WIN64_85A712A8 "game_delphi_win64"
/* Cozy.ImGui/Cozy.Bridge/Cozy.Core/Cozy.game_imgui_bridge.cpp:773 */
#define COZY_TEXT_GAME_IMGUI_BRIDGE_GPU_IDENTITY_ABI_MUST_BE_32_BYTES_EE3EB694 "GPU identity ABI must be 32 bytes"
/* Cozy.ImGui/Cozy.Bridge/Cozy.Core/Cozy.game_imgui_bridge.h:167 */
#define COZY_TEXT_GAME_IMGUI_BRIDGE_IMGUI_ABI_ALLOC_OFFSET_2FB22D1A "ImGui ABI alloc offset"
/* Cozy.ImGui/Cozy.Bridge/Cozy.Core/Cozy.game_imgui_bridge.h:168 */
#define COZY_TEXT_GAME_IMGUI_BRIDGE_IMGUI_ABI_FREE_OFFSET_FA36BF35 "ImGui ABI free offset"
/* Cozy.ImGui/Cozy.Bridge/Cozy.Core/Cozy.game_imgui_bridge.h:166 */
#define COZY_TEXT_GAME_IMGUI_BRIDGE_IMGUI_ABI_GET_PROC_OFFSET_6CFEE93E "ImGui ABI get_proc offset"
/* Cozy.ImGui/Cozy.Bridge/Cozy.Core/Cozy.game_imgui_bridge.h:165 */
#define COZY_TEXT_GAME_IMGUI_BRIDGE_IMGUI_ABI_SIZE_OFFSET_4FACCD47 "ImGui ABI size offset"
/* Cozy.ImGui/Cozy.Bridge/Cozy.Core/Cozy.game_imgui_bridge.h:164 */
#define COZY_TEXT_GAME_IMGUI_BRIDGE_IMGUI_ABI_VERSION_OFFSET_C4567078 "ImGui ABI version offset"
/* Cozy.ImGui/Cozy.Bridge/Cozy.Core/Cozy.game_imgui_bridge.h:163 */
#define COZY_TEXT_GAME_IMGUI_BRIDGE_IMGUI_HOST_ABI_ALIGNMENT_FC6A883E "ImGui host ABI alignment"
/* Cozy.ImGui/Cozy.Bridge/Cozy.Core/Cozy.game_imgui_bridge.h:162 */
#define COZY_TEXT_GAME_IMGUI_BRIDGE_IMGUI_HOST_ABI_SIZE_61B82DFB "ImGui host ABI size"
/* Cozy.ImGui/Cozy.Bridge/Cozy.Core/Cozy.game_imgui_bridge.h:161 */
#define COZY_TEXT_GAME_IMGUI_BRIDGE_IMGUI_HOST_REQUIRES_WIN64_SIZED_POINTERS_F1FF1AF8 "ImGui host requires Win64-sized pointers"
/* Cozy.ImGui/Cozy.Bridge/Cozy.Core/Cozy.game_imgui_bridge.cpp:318 */
#define COZY_TEXT_GAME_IMGUI_BRIDGE_REVIEW_FIXED_CANVAS_MEMORY_BOUNDS_E8434B16 "review fixed-canvas memory bounds"
/* Cozy.ImGui/Cozy.Bridge/Cozy.Core/Cozy.game_imgui_bridge.cpp:34 */
#define COZY_TEXT_GAME_IMGUI_BRIDGE_THIS_BRIDGE_IS_FOR_64_BIT_HOSTS_ONLY_DF287FCF "This bridge is for 64-bit hosts only"
/* Cozy.ImGui/Cozy.Bridge/Cozy.Graphics/Cozy.game_imgui_dcomp_abi.h:85 */
#define COZY_TEXT_GAME_IMGUI_DCOMP_ABI_DIRECTCOMPOSITION_ABI_REQUIRES_WIN64_POINTERS_C75097FE "DirectComposition ABI requires Win64 pointers"
/* Cozy.ImGui/Cozy.Bridge/Cozy.Graphics/Cozy.game_imgui_dcomp_abi.h:86 */
#define COZY_TEXT_GAME_IMGUI_DCOMP_ABI_DIRECTCOMPOSITION_CLIP_ABI_SIZE_AD6B2309 "DirectComposition clip ABI size"
/* Cozy.ImGui/Cozy.Bridge/Cozy.Graphics/Cozy.game_imgui_dcomp_abi.h:88 */
#define COZY_TEXT_GAME_IMGUI_DCOMP_ABI_DIRECTCOMPOSITION_CLIP_FLOAT_ABI_SLOT_09D3C9D7 "DirectComposition clip float ABI slot"
/* Cozy.ImGui/Cozy.Bridge/Cozy.Graphics/Cozy.game_imgui_dcomp_abi.h:100 */
#define COZY_TEXT_GAME_IMGUI_DCOMP_ABI_DIRECTCOMPOSITION_CLIP_OBJECT_ABI_SLOT_D0D25CA9 "DirectComposition clip object ABI slot"
/* Cozy.ImGui/Cozy.Bridge/Cozy.Graphics/Cozy.game_imgui_dcomp_abi.h:101 */
#define COZY_TEXT_GAME_IMGUI_DCOMP_ABI_DIRECTCOMPOSITION_CLIP_RECTANGLE_ABI_SLOT_DFCC145A "DirectComposition clip rectangle ABI slot"
/* Cozy.ImGui/Cozy.Bridge/Cozy.Graphics/Cozy.game_imgui_dcomp_abi.h:87 */
#define COZY_TEXT_GAME_IMGUI_DCOMP_ABI_DIRECTCOMPOSITION_VISUAL_ABI_SIZE_8AE826CA "DirectComposition visual ABI size"
/* Cozy.ImGui/Cozy.Bridge/Cozy.Graphics/Cozy.game_imgui_dx11.cpp:782 */
#define COZY_TEXT_GAME_IMGUI_DX11_ALREADY_INITIALIZED_A_RENDERER_BACKEND_4729006B "Already initialized a renderer backend!"
/* Cozy.ImGui/Cozy.Bridge/Cozy.Graphics/Cozy.game_imgui_dx11.cpp:582 */
#define COZY_TEXT_GAME_IMGUI_DX11_CBUFFER_VERTEXBUFFER_REGISTER_B0_FLOAT4X4_PROJEC_59D82E59 "cbuffer vertexBuffer : register(b0) \
            {\
              float4x4 ProjectionMatrix; \
            };\
            struct VS_INPUT\
            {\
              float2 pos : POSITION;\
              float4 col : COLOR0;\
              float2 uv  : TEXCOORD0;\
            };\
            \
            struct PS_INPUT\
            {\
              float4 pos : SV_POSITION;\
              float4 col : COLOR0;\
              float2 uv  : TEXCOORD0;\
            };\
            \
            PS_INPUT main(VS_INPUT input)\
            {\
              PS_INPUT output;\
              output.pos = mul( ProjectionMatrix, float4(input.pos.xy, 0.0f, 1.0f));\
              output.col = input.col;\
              output.uv  = input.uv;\
              return output;\
            }"
/* Cozy.ImGui/Cozy.Bridge/Cozy.Graphics/Cozy.game_imgui_dx11.cpp:626 */
#define COZY_TEXT_GAME_IMGUI_DX11_COLOR_AE30310E "COLOR"
/* Cozy.ImGui/Cozy.Bridge/Cozy.Graphics/Cozy.game_imgui_dx11.cpp:857 */
#define COZY_TEXT_GAME_IMGUI_DX11_CONTEXT_OR_BACKEND_NOT_INITIALIZED_DID_YOU_CALL__F3ACB465 "Context or backend not initialized! Did you call ImGui_ImplDX11_Init()?"
/* Cozy.ImGui/Cozy.Bridge/Cozy.Graphics/Cozy.game_imgui_dx11.cpp:793 */
#define COZY_TEXT_GAME_IMGUI_DX11_COZY_IMGUI_DIRECTX11_325D6829 "Cozy.ImGui.DirectX11"
/* Cozy.ImGui/Cozy.Bridge/Cozy.Graphics/Cozy.game_imgui_dx11.cpp:866 */
#define COZY_TEXT_GAME_IMGUI_DX11_IMGUI_IMPLDX11_CREATEDEVICEOBJECTS_FAILED_3B91614A "ImGui_ImplDX11_CreateDeviceObjects() failed!"
/* Cozy.ImGui/Cozy.Bridge/Cozy.Graphics/Cozy.game_imgui_dx11.cpp:610 */
#define COZY_TEXT_GAME_IMGUI_DX11_MAIN_DC2573E8 "main"
/* Cozy.ImGui/Cozy.Bridge/Cozy.Graphics/Cozy.game_imgui_dx11.cpp:838 */
#define COZY_TEXT_GAME_IMGUI_DX11_NO_RENDERER_BACKEND_TO_SHUTDOWN_OR_ALREADY_SHUTD_355E33D2 "No renderer backend to shutdown, or already shutdown?"
/* Cozy.ImGui/Cozy.Bridge/Cozy.Graphics/Cozy.game_imgui_dx11.cpp:624 */
#define COZY_TEXT_GAME_IMGUI_DX11_POSITION_B31FD8B7 "POSITION"
/* Cozy.ImGui/Cozy.Bridge/Cozy.Graphics/Cozy.game_imgui_dx11.cpp:667 */
#define COZY_TEXT_GAME_IMGUI_DX11_PS_4_0_5810660D "ps_4_0"
/* Cozy.ImGui/Cozy.Bridge/Cozy.Graphics/Cozy.game_imgui_dx11.cpp:651 */
#define COZY_TEXT_GAME_IMGUI_DX11_STRUCT_PS_INPUT_FLOAT4_POS_SV_POSITION_FLOAT4_CO_2286C5DF "struct PS_INPUT\
            {\
            float4 pos : SV_POSITION;\
            float4 col : COLOR0;\
            float2 uv  : TEXCOORD0;\
            };\
            sampler sampler0;\
            Texture2D texture0;\
            \
            float4 main(PS_INPUT input) : SV_Target\
            {\
            float4 out_col = input.col * texture0.Sample(sampler0, input.uv); \
            return out_col; \
            }"
/* Cozy.ImGui/Cozy.Bridge/Cozy.Graphics/Cozy.game_imgui_dx11.cpp:625 */
#define COZY_TEXT_GAME_IMGUI_DX11_TEXCOORD_DEFCB17D "TEXCOORD"
/* Cozy.ImGui/Cozy.Bridge/Cozy.Graphics/Cozy.game_imgui_dx11.cpp:610 */
#define COZY_TEXT_GAME_IMGUI_DX11_VS_4_0_2E03D3F1 "vs_4_0"
/* Cozy.ImGui/Cozy.Bridge/Cozy.Memory/Cozy.game_imgui_fp.h:26 */
#define COZY_TEXT_GAME_IMGUI_FP_FNCLEX_N_TFLDCW_0_E3EC25B3 "fnclex\n\tfldcw %0"
/* Cozy.ImGui/Cozy.Bridge/Cozy.Memory/Cozy.game_imgui_fp.h:24 */
#define COZY_TEXT_GAME_IMGUI_FP_FNSTCW_0_38C2DB2E "fnstcw %0"
/* Cozy.ImGui/Cozy.Bridge/Cozy.Memory/Cozy.game_imgui_fp.h:26 */
#define COZY_TEXT_GAME_IMGUI_FP_MEMORY_D21AC13A "memory"
/* Cozy.ImGui/Cozy.Bridge/Cozy.Memory/Cozy.game_imgui_fp.h:26 */
#define COZY_TEXT_GAME_IMGUI_FP_M_95FF0AC7 "m"
/* Cozy.ImGui/Cozy.Bridge/Cozy.Memory/Cozy.game_imgui_fp.h:24 */
#define COZY_TEXT_GAME_IMGUI_FP_M_9FEA8A0D "=m"
/* Cozy.ImGui/Cozy.Bridge/Cozy.Memory/Cozy.game_imgui_guard.h:19 */
#define COZY_TEXT_GAME_IMGUI_GUARD_IMGUI_GUARD_RUNTIME_REQUIRES_INLINE_BYTE_ATOMICS_24BB84DC "ImGui guard runtime requires inline byte atomics"
/* Cozy.ImGui/Cozy.Bridge/Cozy.Memory/Cozy.game_imgui_guard.h:17 */
#define COZY_TEXT_GAME_IMGUI_GUARD_IMGUI_GUARD_RUNTIME_REQUIRES_THE_WIN64_SIZED_ABI_80D3BB7F "ImGui guard runtime requires the Win64-sized ABI"
/* Cozy.ImGui/Cozy.Bridge/Cozy.Core/Cozy.game_imgui_license.h:86 */
#define COZY_TEXT_GAME_IMGUI_LICENSE_ACTIVATE_B7F3E8D1 "ACTIVATE"
/* Cozy.ImGui/Cozy.Bridge/Cozy.Core/Cozy.game_imgui_license.h:34 */
#define COZY_TEXT_GAME_IMGUI_LICENSE_ENTER_YOUR_LICENSE_KEY_TO_CONTINUE_D8CB9FDD "Enter your license key to continue"
/* Cozy.ImGui/Cozy.Bridge/Cozy.Core/Cozy.game_imgui_license.h:77 */
#define COZY_TEXT_GAME_IMGUI_LICENSE_LICENSEACTIVATEV1_E126F9F1 "LicenseActivateV1"
/* Cozy.ImGui/Cozy.Bridge/Cozy.Core/Cozy.game_imgui_license.h:41 */
#define COZY_TEXT_GAME_IMGUI_LICENSE_LICENSEINPUTV1_DA1B4A82 "LicenseInputV1"
/* Cozy.ImGui/Cozy.Bridge/Cozy.Core/Cozy.game_imgui_license.h:33 */
#define COZY_TEXT_GAME_IMGUI_LICENSE_LICENSE_ACTIVATION_264434F8 "License activation"
/* Cozy.ImGui/Cozy.Bridge/Cozy.Core/Cozy.game_imgui_license.h:70 */
#define COZY_TEXT_GAME_IMGUI_LICENSE_LICENSE_KEY_D78819B2 "License key"
/* Cozy.ImGui/Cozy.Bridge/Cozy.Core/Cozy.game_imgui_scene.h:77 */
#define COZY_TEXT_GAME_IMGUI_SCENE_ACE_972CC7E5 "ACE"
/* Cozy.ImGui/Cozy.Bridge/Cozy.Core/Cozy.game_imgui_scene.h:67 */
#define COZY_TEXT_GAME_IMGUI_SCENE_ADVENTURE_RACING_81111004 "ADVENTURE RACING"
/* Cozy.ImGui/Cozy.Bridge/Cozy.Core/Cozy.game_imgui_scene.h:77 */
#define COZY_TEXT_GAME_IMGUI_SCENE_ANTI_CHEAT_EXPERT_OFFERS_NGAME_SECURITY_FOR_NPC__861B9B0C "Anti-Cheat Expert offers\ngame security for\nPC and mobile titles."
/* Cozy.ImGui/Cozy.Bridge/Cozy.Core/Cozy.game_imgui_scene.h:72 */
#define COZY_TEXT_GAME_IMGUI_SCENE_ANTI_CHEAT_F5852C6D "ANTI-CHEAT"
/* Cozy.ImGui/Cozy.Bridge/Cozy.Core/Cozy.game_imgui_scene.h:72 */
#define COZY_TEXT_GAME_IMGUI_SCENE_AN_ANTI_CHEAT_SYSTEM_NTHAT_DETECTS_AND_HELPS_NPR_D09A1CC9 "An anti-cheat system\nthat detects and helps\nprevent cheating in games."
/* Cozy.ImGui/Cozy.Bridge/Cozy.Core/Cozy.game_imgui_scene.h:69 */
#define COZY_TEXT_GAME_IMGUI_SCENE_APEX_LEGENDS_DF6FAF1A "Apex Legends"
/* Cozy.ImGui/Cozy.Bridge/Cozy.Core/Cozy.game_imgui_scene.h:72 */
#define COZY_TEXT_GAME_IMGUI_SCENE_BATTLEYE_706417B6 "BattlEye"
/* Cozy.ImGui/Cozy.Bridge/Cozy.Core/Cozy.game_imgui_scene.h:66 */
#define COZY_TEXT_GAME_IMGUI_SCENE_BATTLE_ROYALE_9561DC7D "BATTLE ROYALE"
/* Cozy.ImGui/Cozy.Bridge/Cozy.Core/Cozy.game_imgui_scene.h:70 */
#define COZY_TEXT_GAME_IMGUI_SCENE_BLIZZARD_S_TEAM_BASED_NACTION_GAME_WITH_NDISTINC_F64B2CDE "Blizzard's team-based\naction game with\ndistinct playable heroes."
/* Cozy.ImGui/Cozy.Bridge/Cozy.Core/Cozy.game_imgui_scene.h:79 */
#define COZY_TEXT_GAME_IMGUI_SCENE_BRAWL_STARS_739EF121 "BRAWL STARS"
/* Cozy.ImGui/Cozy.Bridge/Cozy.Core/Cozy.game_imgui_scene.h:83 */
#define COZY_TEXT_GAME_IMGUI_SCENE_BUILD_A_BATTLE_DECK_AND_NCHALLENGE_OPPONENTS_IN__AD4288E7 "Build a battle deck and\nchallenge opponents in\nreal-time arena duels."
/* Cozy.ImGui/Cozy.Bridge/Cozy.Core/Cozy.game_imgui_scene.h:68 */
#define COZY_TEXT_GAME_IMGUI_SCENE_BUILD_A_TEAM_OF_HEROES_NAND_SWITCH_BETWEEN_THEM__8D0BAC6D "Build a team of heroes\nand switch between them\nin action battles."
/* Cozy.ImGui/Cozy.Bridge/Cozy.Core/Cozy.game_imgui_scene.h:76 */
#define COZY_TEXT_GAME_IMGUI_SCENE_CALL_OF_DUTY_S_ANTI_CHEAT_NAPPROACH_USES_CLIENT__B05F5149 "Call of Duty's anti-cheat\napproach uses client and\nserver security measures."
/* Cozy.ImGui/Cozy.Bridge/Cozy.Core/Cozy.game_imgui_scene.h:83 */
#define COZY_TEXT_GAME_IMGUI_SCENE_CLASH_ROYALE_F9ABA5DC "CLASH ROYALE"
/* Cozy.ImGui/Cozy.Bridge/Cozy.Core/Cozy.game_imgui_scene.h:288 */
#define COZY_TEXT_GAME_IMGUI_SCENE_CLEANNER_A530EAA9 "Cleanner"
/* Cozy.ImGui/Cozy.Bridge/Cozy.Core/Cozy.game_imgui_scene.h:225 */
#define COZY_TEXT_GAME_IMGUI_SCENE_CLICK_TO_CLOSE_64671117 "Click to close"
/* Cozy.ImGui/Cozy.Bridge/Cozy.Core/Cozy.game_imgui_scene.h:71 */
#define COZY_TEXT_GAME_IMGUI_SCENE_COMPETITIVE_FPS_546C816A "COMPETITIVE FPS"
/* Cozy.ImGui/Cozy.Bridge/Cozy.Core/Cozy.game_imgui_scene.h:71 */
#define COZY_TEXT_GAME_IMGUI_SCENE_COUNTER_STRIKE_2_F233088A "Counter-Strike 2"
/* Cozy.ImGui/Cozy.Bridge/Cozy.Core/Cozy.game_imgui_scene.h:78 */
#define COZY_TEXT_GAME_IMGUI_SCENE_CREATIVE_WORLDS_2455EDDF "CREATIVE WORLDS"
/* Cozy.ImGui/Cozy.Bridge/Cozy.Core/Cozy.game_imgui_scene.h:78 */
#define COZY_TEXT_GAME_IMGUI_SCENE_DISCOVER_COMMUNITY_WORLDS_NCREATE_AND_PLAY_WITH__FF787052 "Discover community worlds,\ncreate and play with friends."
/* Cozy.ImGui/Cozy.Bridge/Cozy.Core/Cozy.game_imgui_scene.h:74 */
#define COZY_TEXT_GAME_IMGUI_SCENE_EASY_ANTI_CHEAT_516F3A4A "Easy Anti-Cheat"
/* Cozy.ImGui/Cozy.Bridge/Cozy.Core/Cozy.game_imgui_scene.h:74 */
#define COZY_TEXT_GAME_IMGUI_SCENE_EPIC_GAMES_ANTI_CHEAT_NSERVICE_SUPPORTING_NFAIR__407816F5 "Epic Games' anti-cheat\nservice supporting\nfair play in games."
/* Cozy.ImGui/Cozy.Bridge/Cozy.Core/Cozy.game_imgui_scene.h:81 */
#define COZY_TEXT_GAME_IMGUI_SCENE_EXPLORE_TEYVAT_AND_DISCOVER_NAN_ELEMENTAL_ADVENT_6A6BDC61 "Explore Teyvat and discover\nan elemental adventure\nwith your own team."
/* Cozy.ImGui/Cozy.Bridge/Cozy.Core/Cozy.game_imgui_scene.h:82 */
#define COZY_TEXT_GAME_IMGUI_SCENE_EXPLORE_YOUR_SURROUNDINGS_NFIND_POKEMON_AND_JOIN_DE31513F "Explore your surroundings,\nfind Pokemon and join\nnearby adventures."
/* Cozy.ImGui/Cozy.Bridge/Cozy.Core/Cozy.game_imgui_scene.h:79 */
#define COZY_TEXT_GAME_IMGUI_SCENE_FAST_MULTIPLAYER_BATTLES_NWITH_A_COLORFUL_ROSTER_92E048D5 "Fast multiplayer battles\nwith a colorful roster\nof unique brawlers."
/* Cozy.ImGui/Cozy.Bridge/Cozy.Core/Cozy.game_imgui_scene.h:73 */
#define COZY_TEXT_GAME_IMGUI_SCENE_GAME_SECURITY_8E6E9A8B "GAME SECURITY"
/* Cozy.ImGui/Cozy.Bridge/Cozy.Core/Cozy.game_imgui_scene.h:81 */
#define COZY_TEXT_GAME_IMGUI_SCENE_GENSHIN_IMPACT_6B5BE08C "GENSHIN IMPACT"
/* Cozy.ImGui/Cozy.Bridge/Cozy.Core/Cozy.game_imgui_scene.h:69 */
#define COZY_TEXT_GAME_IMGUI_SCENE_HERO_BATTLE_ROYALE_E604CB00 "HERO BATTLE ROYALE"
/* Cozy.ImGui/Cozy.Bridge/Cozy.Core/Cozy.game_imgui_scene.h:66 */
#define COZY_TEXT_GAME_IMGUI_SCENE_KRAFTON_S_BATTLE_ROYALE_NSCAVENGE_PLAN_AND_SURVI_AFD98A0F "KRAFTON's battle royale.\nScavenge, plan and survive\nto be the last one standing."
/* Cozy.ImGui/Cozy.Bridge/Cozy.Core/Cozy.game_imgui_scene.h:68 */
#define COZY_TEXT_GAME_IMGUI_SCENE_LOST_SAGA_F05D966E "Lost Saga"
/* Cozy.ImGui/Cozy.Bridge/Cozy.Core/Cozy.game_imgui_scene.h:288 */
#define COZY_TEXT_GAME_IMGUI_SCENE_MOBILE_919A3FCF "Mobile"
/* Cozy.ImGui/Cozy.Bridge/Cozy.Core/Cozy.game_imgui_scene.h:81 */
#define COZY_TEXT_GAME_IMGUI_SCENE_OPEN_WORLD_RPG_509168B5 "OPEN WORLD RPG"
/* Cozy.ImGui/Cozy.Bridge/Cozy.Core/Cozy.game_imgui_scene.h:70 */
#define COZY_TEXT_GAME_IMGUI_SCENE_OVERWATCH_341E8091 "Overwatch"
/* Cozy.ImGui/Cozy.Bridge/Cozy.Core/Cozy.game_imgui_scene.h:82 */
#define COZY_TEXT_GAME_IMGUI_SCENE_POKEMON_GO_6E54CBE6 "POKEMON GO"
/* Cozy.ImGui/Cozy.Bridge/Cozy.Core/Cozy.game_imgui_scene.h:66 */
#define COZY_TEXT_GAME_IMGUI_SCENE_PUBG_E0D9363F "PUBG"
/* Cozy.ImGui/Cozy.Bridge/Cozy.Core/Cozy.game_imgui_scene.h:80 */
#define COZY_TEXT_GAME_IMGUI_SCENE_PUBG_MOBILE_2FC19130 "PUBG MOBILE"
/* Cozy.ImGui/Cozy.Bridge/Cozy.Core/Cozy.game_imgui_scene.h:82 */
#define COZY_TEXT_GAME_IMGUI_SCENE_REAL_WORLD_ADVENTURE_C8761CCE "REAL WORLD ADVENTURE"
/* Cozy.ImGui/Cozy.Bridge/Cozy.Core/Cozy.game_imgui_scene.h:69 */
#define COZY_TEXT_GAME_IMGUI_SCENE_RESPAWN_S_BATTLE_ROYALE_NWITH_DISTINCT_LEGENDS_N_C700E12E "Respawn's battle royale\nwith distinct Legends\nand squad-based play."
/* Cozy.ImGui/Cozy.Bridge/Cozy.Core/Cozy.game_imgui_scene.h:67 */
#define COZY_TEXT_GAME_IMGUI_SCENE_RHAON_S_CASUAL_RACING_NADVENTURE_SET_IN_A_NFAIRY_2F3F5D51 "RHAON's casual racing\nadventure set in a\nfairy-tale world."
/* Cozy.ImGui/Cozy.Bridge/Cozy.Core/Cozy.game_imgui_scene.h:76 */
#define COZY_TEXT_GAME_IMGUI_SCENE_RICOCHET_9C627143 "RICOCHET"
/* Cozy.ImGui/Cozy.Bridge/Cozy.Core/Cozy.game_imgui_scene.h:75 */
#define COZY_TEXT_GAME_IMGUI_SCENE_RIOT_GAMES_SECURITY_NSOFTWARE_SUPPORTING_FAIR_NC_ADB3B525 "Riot Games' security\nsoftware supporting fair\ncompetition in Riot games."
/* Cozy.ImGui/Cozy.Bridge/Cozy.Core/Cozy.game_imgui_scene.h:75 */
#define COZY_TEXT_GAME_IMGUI_SCENE_RIOT_VANGUARD_00AB6A50 "Riot Vanguard"
/* Cozy.ImGui/Cozy.Bridge/Cozy.Core/Cozy.game_imgui_scene.h:78 */
#define COZY_TEXT_GAME_IMGUI_SCENE_ROBLOX_4F3308B5 "ROBLOX"
/* Cozy.ImGui/Cozy.Bridge/Cozy.Core/Cozy.game_imgui_scene.h:287 */
#define COZY_TEXT_GAME_IMGUI_SCENE_SCENECLEANNERV2_0975B65B "##sceneCleannerV2"
/* Cozy.ImGui/Cozy.Bridge/Cozy.Core/Cozy.game_imgui_scene.h:287 */
#define COZY_TEXT_GAME_IMGUI_SCENE_SCENEMOBILEV3_A9EF177C "SceneMobileV3"
/* Cozy.ImGui/Cozy.Bridge/Cozy.Core/Cozy.game_imgui_scene.h:367 */
#define COZY_TEXT_GAME_IMGUI_SCENE_SCENERUNV2_83AA90DF "##sceneRunV2"
/* Cozy.ImGui/Cozy.Bridge/Cozy.Core/Cozy.game_imgui_scene.h:287 */
#define COZY_TEXT_GAME_IMGUI_SCENE_SCENESPOOFERV2_C5B6453E "##sceneSpooferV2"
/* Cozy.ImGui/Cozy.Bridge/Cozy.Core/Cozy.game_imgui_scene.h:333 */
#define COZY_TEXT_GAME_IMGUI_SCENE_SCENETILE0_ECCC69D2 "##sceneTile0"
/* Cozy.ImGui/Cozy.Bridge/Cozy.Core/Cozy.game_imgui_scene.h:333 */
#define COZY_TEXT_GAME_IMGUI_SCENE_SCENETILE1_087C8596 "##sceneTile1"
/* Cozy.ImGui/Cozy.Bridge/Cozy.Core/Cozy.game_imgui_scene.h:333 */
#define COZY_TEXT_GAME_IMGUI_SCENE_SCENETILE2_A8EF7311 "##sceneTile2"
/* Cozy.ImGui/Cozy.Bridge/Cozy.Core/Cozy.game_imgui_scene.h:333 */
#define COZY_TEXT_GAME_IMGUI_SCENE_SCENETILE3_6116E31A "##sceneTile3"
/* Cozy.ImGui/Cozy.Bridge/Cozy.Core/Cozy.game_imgui_scene.h:333 */
#define COZY_TEXT_GAME_IMGUI_SCENE_SCENETILE4_78C714A9 "##sceneTile4"
/* Cozy.ImGui/Cozy.Bridge/Cozy.Core/Cozy.game_imgui_scene.h:333 */
#define COZY_TEXT_GAME_IMGUI_SCENE_SCENETILE5_27800BDA "##sceneTile5"
/* Cozy.ImGui/Cozy.Bridge/Cozy.Core/Cozy.game_imgui_scene.h:288 */
#define COZY_TEXT_GAME_IMGUI_SCENE_SPOOFER_EF1042EF "Spoofer"
/* Cozy.ImGui/Cozy.Bridge/Cozy.Core/Cozy.game_imgui_scene.h:377 */
#define COZY_TEXT_GAME_IMGUI_SCENE_START_778F8907 "START"
/* Cozy.ImGui/Cozy.Bridge/Cozy.Core/Cozy.game_imgui_scene.h:83 */
#define COZY_TEXT_GAME_IMGUI_SCENE_STRATEGY_DUELS_354020E1 "STRATEGY DUELS"
/* Cozy.ImGui/Cozy.Bridge/Cozy.Core/Cozy.game_imgui_scene.h:67 */
#define COZY_TEXT_GAME_IMGUI_SCENE_TALESRUNNER_B67227B0 "TalesRunner"
/* Cozy.ImGui/Cozy.Bridge/Cozy.Core/Cozy.game_imgui_scene.h:68 */
#define COZY_TEXT_GAME_IMGUI_SCENE_TEAM_ACTION_FA85F861 "TEAM ACTION"
/* Cozy.ImGui/Cozy.Bridge/Cozy.Core/Cozy.game_imgui_scene.h:80 */
#define COZY_TEXT_GAME_IMGUI_SCENE_THE_MOBILE_BATTLEFIELD_NPLAN_EXPLORE_AND_SURVIVE_3A248CF3 "The mobile battlefield.\nPlan, explore and survive\nwith your squad."
/* Cozy.ImGui/Cozy.Bridge/Cozy.Core/Cozy.game_imgui_scene.h:71 */
#define COZY_TEXT_GAME_IMGUI_SCENE_VALVE_S_COMPETITIVE_FPS_NTEAM_TACTICS_MEET_NPREC_DF5BF859 "Valve's competitive FPS.\nTeam tactics meet\nprecise shooting."
/* Cozy.ImGui/Cozy.Bridge/Cozy.Core/Cozy.game_imgui_scene.h:73 */
#define COZY_TEXT_GAME_IMGUI_SCENE_WELLBIA_S_GAME_SECURITY_NSOLUTION_FOR_PROTECTING_3FB1BA88 "Wellbia's game security\nsolution for protecting\nfair online play."
/* Cozy.ImGui/Cozy.Bridge/Cozy.Core/Cozy.game_imgui_scene.h:73 */
#define COZY_TEXT_GAME_IMGUI_SCENE_XIGNCODE3_5CF9C19E "XIGNCODE3"

#endif
