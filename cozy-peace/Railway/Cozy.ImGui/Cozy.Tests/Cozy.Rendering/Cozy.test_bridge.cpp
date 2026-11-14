/* Cozy central native text imports. */
#include "../../Cozy.Strings/Cozy.Strings.Tests.h"
#line 1
/* Cozy central native text imports. */
#line 1
/* Cozy central native text imports. */
#line 1
/* Actual upstream ImGui core tests; no GPU and no server/network simulation. */
#include "../../Cozy.Bridge/Cozy.Core/Cozy.game_imgui_bridge.h"
#include "../../Cozy.Bridge/Cozy.Graphics/Cozy.game_imgui_texture.h"
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <math.h>
#include <string.h>
#include <limits.h>
#include <float.h>
#include <thread>
#include <atomic>
#include <initializer_list>
extern "C" unsigned game_imgui_test_scene_focus(GameImGuiHandle handle);
extern "C" int game_imgui_test_scene_state(GameImGuiHandle handle,float* values,uint32_t count);
extern "C" int game_imgui_test_utf8(const char* text);
extern "C" int game_imgui_test_queue_size();
extern "C" size_t game_imgui_test_arena_peak();
extern "C" size_t game_imgui_test_arena_largest();
extern "C" void* game_imgui_test_arena_pressure(size_t bytes);
extern "C" void game_imgui_test_arena_release(void* p);
extern "C" int game_imgui_test_gpu_error(GameImGuiHandle handle,int32_t value);
extern "C" int game_imgui_test_atoi(const char* value);
extern "C" int game_imgui_test_draw_vertices(GameImGuiHandle handle);
extern "C" int game_imgui_test_input_state(GameImGuiHandle handle,int id);
extern "C" int game_imgui_test_no_files(GameImGuiHandle handle);
extern "C" int game_imgui_test_contract_state(GameImGuiHandle handle,uint32_t* words,uint32_t count);
extern "C" int game_imgui_test_scene_detail(GameImGuiHandle handle,float* values,unsigned count);
extern "C" float game_imgui_test_scene_gap(float position,int slot);
extern "C" int game_imgui_test_scene_reveal(GameImGuiHandle handle,float* values,unsigned count);
extern "C" int game_imgui_test_scene_draw_bounds(GameImGuiHandle handle,float* values,unsigned count);
extern "C" int game_imgui_test_license_state(GameImGuiHandle handle,float* values,unsigned count);
extern "C" int game_imgui_test_scene_entitlement(GameImGuiHandle handle,float* values,unsigned count);
static int allocations=0, checks=0, deny_id=0, allocation_calls=0, fail_at_call=0;
static uint32_t sequence_seed=0, sequence_step=0, sequence_operation=0;
static std::atomic<uint32_t> next_thread(0);
static uint32_t host_thread(){static thread_local uint32_t id=++next_thread;return id;}
static bool trigger_reentry=false, fail_next_allocation=false;
static int reentry_result=-2;
static GameImGuiHandle reentry_handle=0;
static void check(bool result,const char* message){++checks;if(!result){fprintf(stderr,COZY_TEXT_TEST_BRIDGE_FAIL_S_SEED_08X_STEP_U_OPERATION_U_N_596D89FA,message,sequence_seed,sequence_step,sequence_operation);exit(1);}}
static void* host_alloc(size_t n){++allocation_calls;if(allocation_calls==fail_at_call)return 0;if(fail_next_allocation){fail_next_allocation=false;return 0;}void* p=malloc(n);if(p)++allocations;return p;}
static void host_free(void* p){if(p){--allocations;free(p);}}
static int host_printf(uint64_t options,char* buffer,size_t size,const char* format,void*,va_list args){check(options==2,COZY_TEXT_TEST_BRIDGE_PRINTF_STANDARD_OPTIONS_4A3CE52E);return vsnprintf(buffer,size,format,args);}
static int host_scanf(uint64_t options,const char* buffer,size_t size,const char* format,void*,va_list args){check(options==0&&size==static_cast<size_t>(-1),COZY_TEXT_TEST_BRIDGE_SCANF_UNBOUNDED_STRING_OPTIONS_31FE521A);return vsscanf(buffer,format,args);}
static void* host_get(int32_t id){
    if(id==deny_id)return 0;
    if(id==GI_PROC_THREAD_ID && trigger_reentry){trigger_reentry=false;reentry_result=game_imgui_resize(reentry_handle,320,160);}
    switch(id){case GI_PROC_D3D11_CREATE:case GI_PROC_D3D_COMPILE:case GI_PROC_DCOMP_CREATE:return reinterpret_cast<void*>(&host_get);
    case GI_PROC_CRT_VSPRINTF:return reinterpret_cast<void*>(&host_printf);
    case GI_PROC_CRT_VSSCANF:return reinterpret_cast<void*>(&host_scanf);
    case GI_PROC_STRTOD:return reinterpret_cast<void*>(&strtod);
    case GI_PROC_ACOS:return reinterpret_cast<void*>(static_cast<double(*)(double)>(&acos));
    case GI_PROC_ATAN2:return reinterpret_cast<void*>(static_cast<double(*)(double,double)>(&atan2));
    case GI_PROC_CEIL:return reinterpret_cast<void*>(static_cast<double(*)(double)>(&ceil));
    case GI_PROC_COS:return reinterpret_cast<void*>(static_cast<double(*)(double)>(&cos));
    case GI_PROC_FABS:return reinterpret_cast<void*>(static_cast<double(*)(double)>(&fabs));
    case GI_PROC_FLOOR:return reinterpret_cast<void*>(static_cast<double(*)(double)>(&floor));
    case GI_PROC_FMOD:return reinterpret_cast<void*>(static_cast<double(*)(double,double)>(&fmod));
    case GI_PROC_LOG:return reinterpret_cast<void*>(static_cast<double(*)(double)>(&log));
    case GI_PROC_POW:return reinterpret_cast<void*>(static_cast<double(*)(double,double)>(&pow));
    case GI_PROC_SIN:return reinterpret_cast<void*>(static_cast<double(*)(double)>(&sin));
    case GI_PROC_THREAD_ID:return reinterpret_cast<void*>(&host_thread);
    case GI_PROC_SQRT:return reinterpret_cast<void*>(static_cast<double(*)(double)>(&sqrt));default:return 0;}
}
static bool frame(GameImGuiHandle h,bool enabled=true){
    check(game_imgui_new_frame(h,320,160,1.0f/60.0f)==1,COZY_TEXT_TEST_BRIDGE_BEGIN_REAL_FRAME_0796C37C);
    game_imgui_begin_canvas(h);game_imgui_set_cursor_pos(h,32,52);
    bool clicked=game_imgui_button(h,COZY_TEXT_TEST_BRIDGE_INJECTION_B9D51FDC,256,44,enabled?1:0)!=0;
    if(getenv(COZY_TEXT_TEST_BRIDGE_GAME_IMGUI_TEST_TRACE_07F65C70))fprintf(stderr,COZY_TEXT_TEST_BRIDGE_ACTIVE_AFTERBUTTON_D_6A08E617,game_imgui_test_input_state(h,3));
    game_imgui_set_cursor_pos(h,76,116);game_imgui_text(h,COZY_TEXT_TEST_BRIDGE_ACTION_NOT_CONFIGURED_8B02DC8B);game_imgui_end_canvas(h);
    check(game_imgui_render_present(h)==-1,COZY_TEXT_TEST_BRIDGE_TEST_BUILD_CANNOT_ACKNOWLEDGE_A_PRESENTED_FRAME_04A9B9B0);
    check(game_imgui_test_draw_vertices(h)>0,COZY_TEXT_TEST_BRIDGE_ACTUAL_IMGUI_GENERATED_DRAW_VERTICES_0CDF7537);
    if(getenv(COZY_TEXT_TEST_BRIDGE_GAME_IMGUI_TEST_TRACE_07F65C70)){for(int i=0;i<10;++i)fprintf(stderr,COZY_TEXT_TEST_BRIDGE_D_D190BA88,game_imgui_test_input_state(h,i));fprintf(stderr,COZY_TEXT_TEST_BRIDGE_CLICKED_D_N_BCB34714,clicked?1:0);}return clicked;
}
static unsigned char* read_test_font(const char* name,uint32_t* bytes){
    const char* path=getenv(name);if(!path)return 0;
    FILE* file=fopen(path,COZY_TEXT_TEST_BRIDGE_RB_C832BF0F);check(file!=0,COZY_TEXT_TEST_BRIDGE_EXPLICIT_TEST_FONT_OPENS_6EDF1A07);
    check(fseek(file,0,SEEK_END)==0,COZY_TEXT_TEST_BRIDGE_FONT_SIZE_SEEK_B2B0735E);long length=ftell(file);
    check(length>=256&&length<=16*1024*1024,COZY_TEXT_TEST_BRIDGE_BOUNDED_TEST_FONT_A5130F5C);rewind(file);
    unsigned char* data=static_cast<unsigned char*>(malloc(length));check(data!=0,COZY_TEXT_TEST_BRIDGE_FONT_FIXTURE_ALLOCATION_C90B3930);
    check(fread(data,1,length,file)==static_cast<size_t>(length),COZY_TEXT_TEST_BRIDGE_COMPLETE_FONT_FIXTURE_READ_FE732B06);
    check(fclose(file)==0,COZY_TEXT_TEST_BRIDGE_FONT_FIXTURE_HANDLE_CLOSES_785E982C);*bytes=static_cast<uint32_t>(length);return data;
}
// Contract model: an independent caller-side lifecycle, not a mock renderer.
// The production bridge and upstream ImGui execute every generated operation.
// A read-only test hook observes state after each call; it cannot admit a call,
// reset a failure, mutate a context or provide a fake Present result.
struct SequenceModel {
    bool frame=false, canvas=false, begun=false, editor=false, focused=false;
    uint32_t items=0, bytes=0;
};
static uint32_t next_sequence(uint32_t& state) {
    state^=state<<13;state^=state>>17;state^=state<<5;return state;
}
static void verify_model(GameImGuiHandle h,const SequenceModel& model) {
    uint32_t state[9]={};
    check(game_imgui_test_contract_state(h,state,9)==1,COZY_TEXT_TEST_BRIDGE_LIVE_MODEL_SNAPSHOT_A32D741B);
    check(state[0]==model.frame && state[1]==model.canvas && state[2]==model.begun,COZY_TEXT_TEST_BRIDGE_FRAME_CANVAS_STATE_AGREES_WITH_CALLER_CONTRACT_E11264A5);
    check(state[3]==model.items && state[4]==model.bytes,COZY_TEXT_TEST_BRIDGE_INVALID_ITEM_CANNOT_CONSUME_SUCCESSFUL_ITEM_TEXT_CA86235B);
    check(state[5]<=256,COZY_TEXT_TEST_BRIDGE_INPUT_QUEUE_BOUNDED_AFTER_EVERY_GENERATED_OPERAT_1AA6841F);
    check(state[6]==0,COZY_TEXT_TEST_BRIDGE_INVALID_CALL_DOES_NOT_POISON_HEALTHY_CONTEXT_95FCB484);
    check(state[7]==model.editor && state[8]==model.focused,COZY_TEXT_TEST_BRIDGE_EDITOR_FOCUS_STATE_AGREES_WITH_CALLER_CONTRACT_F2B44DD7);
    check(game_imgui_test_no_files(h)==1,COZY_TEXT_TEST_BRIDGE_GENERATED_LIFECYCLE_CANNOT_ENABLE_FILE_PERSISTEN_B5900403);
}
static void invalid_handle_calls(GameImGuiHandle bad,GameImGuiHandle owner) {
    uint32_t before[9]={},after[9]={};
    check(game_imgui_test_contract_state(owner,before,9)==1,COZY_TEXT_TEST_BRIDGE_OWNER_SNAPSHOT_BEFORE_INVALID_HANDLE_3C14D726);
    check(game_imgui_resize(bad,320,160)==0 && game_imgui_set_dpi(bad,1)==0,COZY_TEXT_TEST_BRIDGE_INVALID_HANDLE_CANNOT_RESIZE_SET_DPI_FC2F9188);
    check(game_imgui_new_frame(bad,320,160,1.0f/60)==0,COZY_TEXT_TEST_BRIDGE_INVALID_HANDLE_CANNOT_START_FRAME_B59890DA);
    game_imgui_begin_canvas(bad);game_imgui_set_cursor_pos(bad,10,20);
    check(game_imgui_button(bad,COZY_TEXT_TEST_BRIDGE_INVALID_557CCC4A,20,20,1)==0,COZY_TEXT_TEST_BRIDGE_INVALID_HANDLE_CANNOT_ACTIVATE_BUTTON_49403F1E);
    game_imgui_text(bad,COZY_TEXT_TEST_BRIDGE_INVALID_557CCC4A);game_imgui_end_canvas(bad);
    check(game_imgui_render_present(bad)==-1,COZY_TEXT_TEST_BRIDGE_INVALID_HANDLE_CANNOT_PRESENT_8C5E9027);
    game_imgui_mouse_pos(bad,12,34);game_imgui_mouse_button(bad,0,1);
    game_imgui_mouse_wheel(bad,1,1);game_imgui_key(bad,0x0D,1);
    game_imgui_focus(bad,1);game_imgui_clear_input(bad);
    check(game_imgui_text_input_enable_v1(bad,1)==0,COZY_TEXT_TEST_BRIDGE_INVALID_HANDLE_CANNOT_ALLOCATE_EDITOR_8C2DFF8D);
    check(game_imgui_text_input_utf8_v1(bad,COZY_TEXT_TEST_BRIDGE_X_A680F36E,1,0)==0 && game_imgui_text_input_utf16_v1(bad,'x')==0,COZY_TEXT_TEST_BRIDGE_INVALID_HANDLE_CANNOT_QUEUE_TEXT_39375061);
    char output[513];memset(output,0x5A,sizeof(output));
    check(game_imgui_text_input_read_v1(bad,output,sizeof(output),0)==-1 && output[0]==0x5A,COZY_TEXT_TEST_BRIDGE_INVALID_HANDLE_CANNOT_CONSUME_OR_TOUCH_TEXT_OUTP_BD97DDDF);
    check(game_imgui_text_input_status_v1(bad)==0 && game_imgui_text_input_display_v1(bad,COZY_TEXT_TEST_BRIDGE_X_A680F36E,1)==0,COZY_TEXT_TEST_BRIDGE_INVALID_HANDLE_HAS_NO_EDITOR_STATE_EDF79D51);
    uint32_t identity[8]={1,1,1,1,1,1,1,1};
    check(game_imgui_gpu_identity(bad,identity,sizeof(identity))==0,COZY_TEXT_TEST_BRIDGE_INVALID_HANDLE_HAS_NO_GPU_IDENTITY_82B7CAD4);
    for(unsigned i=0;i<8;++i)check(identity[i]==0,COZY_TEXT_TEST_BRIDGE_INVALID_HANDLE_CLEARS_VALID_SIZE_GPU_OUTPUT_05C465F1);
    check(game_imgui_last_error(bad)==-1 && game_imgui_destroy(bad)==0,COZY_TEXT_TEST_BRIDGE_INVALID_HANDLE_CANNOT_OBSERVE_OR_DESTROY_OWNER_DB6F6526);
    check(game_imgui_test_contract_state(owner,after,9)==1 && !memcmp(before,after,sizeof(before)),COZY_TEXT_TEST_BRIDGE_INVALID_HANDLE_APIS_PRESERVE_EVERY_OBSERVED_OWNE_7EB67593);
}
static void input_float_boundaries(GameImGuiHandle h) {
    const float rejected[]={NAN,INFINITY,-INFINITY,FLT_MAX,-FLT_MAX,1.0e30f,-1.0e30f};
    game_imgui_clear_input(h);
    for(float v:rejected) {
        const int before=game_imgui_test_queue_size();
        game_imgui_mouse_pos(h,v,0);game_imgui_mouse_pos(h,0,v);
        game_imgui_mouse_wheel(h,v,0);game_imgui_mouse_wheel(h,0,v);
        check(game_imgui_test_queue_size()==before,COZY_TEXT_TEST_BRIDGE_NONFINITE_OVERSIZED_INPUT_IS_REJECTED_BEFORE_QUE_095FB7F5);
    }
    game_imgui_mouse_pos(h,-32769,0);game_imgui_mouse_pos(h,32768,0);
    game_imgui_mouse_pos(h,0,-32769);game_imgui_mouse_pos(h,0,32768);
    game_imgui_mouse_wheel(h,-16385,0);game_imgui_mouse_wheel(h,16385,0);
    game_imgui_mouse_wheel(h,0,-16385);game_imgui_mouse_wheel(h,0,16385);
    check(game_imgui_test_queue_size()==0,COZY_TEXT_TEST_BRIDGE_ONE_PAST_INPUT_BOUNDARIES_ENQUEUE_NOTHING_B77F679A);
    game_imgui_mouse_wheel(h,-16384,16384);
    check(game_imgui_test_queue_size()==1,COZY_TEXT_TEST_BRIDGE_EXACT_FINITE_WHEEL_BOUNDARIES_REMAIN_ACCEPTED_5AE122FC);
    game_imgui_clear_input(h);
    game_imgui_mouse_pos(h,10,20);
    game_imgui_mouse_pos(h,30,40);
    const int before_leave=game_imgui_test_queue_size();
    check(before_leave>=1&&before_leave<=2,COZY_TEXT_TEST_BRIDGE_TWO_DISTINCT_POSITIONS_SEED_LEAVE_TRANSITION_IND_ED6B4509);
    game_imgui_mouse_pos(h,-1.0e30f,-1.0e30f);
    check(game_imgui_test_queue_size()==before_leave+1,COZY_TEXT_TEST_BRIDGE_EXISTING_MOUSE_LEAVE_PAIR_IS_NORMALIZED_INTO_ONE_7D23314D);
    game_imgui_mouse_pos(h,-FLT_MAX,-FLT_MAX);
    check(game_imgui_test_queue_size()==before_leave+1,COZY_TEXT_TEST_BRIDGE_NATIVE_LEAVE_SENTINEL_IS_EQUIVALENT_TO_LEGACY_PA_C590B019);
    game_imgui_mouse_pos(h,-32768,32767);
    check(game_imgui_test_queue_size()==before_leave+2,COZY_TEXT_TEST_BRIDGE_SIGNED_WIN32_COORDINATE_EXTREMES_REMAIN_ACCEPTED_4FAB57D3);
    game_imgui_clear_input(h);
}
static void seeded_public_api_sequences(const GameImGuiHost& host) {
    const uint32_t seeds[]={0x00000001u,0xA53C91E7u,0xC0A7B00Fu,0xFFFFFFFFu};
    unsigned coverage[20]={};
    const int checks_before=checks;
    unsigned lifecycles=0;
    for(uint32_t seed:seeds) {
        sequence_seed=seed;uint32_t random=seed;
        GameImGuiHandle h=0,stale=0;
        check(game_imgui_create(reinterpret_cast<void*>(1),&host,&h)==1,COZY_TEXT_TEST_BRIDGE_SEEDED_CONTEXT_CREATION_473DE950);
        ++lifecycles;SequenceModel model;
        input_float_boundaries(h);
        for(sequence_step=0;sequence_step<512;++sequence_step) {
            const uint32_t value=next_sequence(random);
            sequence_operation=value%20; ++coverage[sequence_operation];
            switch(sequence_operation) {
            case 0: {
                const int32_t dims[]={-1,0,1,160,16384,16385,INT_MAX};
                const float deltas[]={0,-1,1.0f/60,1,1.01f,NAN,INFINITY};
                int32_t w=dims[(value>>8)%7],height=dims[(value>>12)%7];float dt=deltas[(value>>16)%7];
                const bool allowed=!model.frame&&w>=1&&w<=16384&&height>=1&&height<=16384&&dt>0&&dt<=1;
                check(game_imgui_new_frame(h,w,height,dt)==(allowed?1:0),COZY_TEXT_TEST_BRIDGE_GENERATED_NEWFRAME_VALIDITY_ORDER_E2918C08);
                if(allowed){model.frame=true;model.canvas=false;model.begun=false;model.items=0;model.bytes=0;}break;
            }
            case 1:
                check(game_imgui_new_frame(h,320,160,1.0f/60)==(!model.frame?1:0),COZY_TEXT_TEST_BRIDGE_VALID_FRAME_OR_NESTED_FRAME_REJECTION_00EB7112);
                if(!model.frame){model.frame=true;model.canvas=false;model.begun=false;model.items=0;model.bytes=0;}break;
            case 2:
                game_imgui_begin_canvas(h);if(model.frame&&!model.begun){model.canvas=true;model.begun=true;}break;
            case 3: game_imgui_end_canvas(h);model.canvas=false;break;
            case 4:
                check(game_imgui_render_present(h)==-1,COZY_TEXT_TEST_BRIDGE_PORTABLE_PRESENT_MUST_NEVER_CLAIM_GPU_SUCCESS_ACCAC666);
                if(model.frame&&!model.canvas)model.frame=false;break;
            case 5: {
                const int32_t widths[]={0,1,320,16384,16385};int32_t w=widths[(value>>8)%5];
                check(game_imgui_resize(h,w,160)==(!model.frame&&w>=1&&w<=16384?1:0),COZY_TEXT_TEST_BRIDGE_RESIZE_VALIDITY_ORDER_A3C02BBE);break;
            }
            case 6: {
                const float values[]={0,0.49f,0.5f,1,8,8.01f,NAN,INFINITY};float dpi=values[(value>>8)%8];
                check(game_imgui_set_dpi(h,dpi)==(!model.frame&&dpi>=0.5f&&dpi<=8?1:0),COZY_TEXT_TEST_BRIDGE_DPI_BOUNDARY_ORDER_86FE1B95);break;
            }
            case 7: case 8: {
                char text[129];const unsigned lengths[]={0,1,63,127,128};unsigned n=lengths[(value>>8)%5];
                memset(text,'m',n);text[n]=0;
                const bool malformed=(value&0x10000)!=0;if(malformed){text[0]='\n';text[1]=0;n=1;}
                const bool valid=model.canvas&&!malformed&&n<=127&&model.items<8&&model.bytes+n<=512;
                if(sequence_operation==7)game_imgui_text(h,text);
                else check(game_imgui_button(h,text,50,20,0)==0,COZY_TEXT_TEST_BRIDGE_DISABLED_GENERATED_BUTTON_CANNOT_CLICK_012ECF3F);
                if(valid){++model.items;model.bytes+=n;}break;
            }
            case 9:
                game_imgui_set_cursor_pos(h,NAN,0);game_imgui_set_cursor_pos(h,0,INFINITY);
                check(game_imgui_button(h,COZY_TEXT_TEST_BRIDGE_BOUNDARY_46B8D146,NAN,20,1)==0 && game_imgui_button(h,COZY_TEXT_TEST_BRIDGE_BOUNDARY_46B8D146,20,-1,1)==0,COZY_TEXT_TEST_BRIDGE_INVALID_GEOMETRY_CANNOT_ACTIVATE_OR_CONSUME_ITEM_F44D0E37);break;
            case 10:
                game_imgui_mouse_pos(h,float(value%320),float((value>>8)%160));game_imgui_mouse_button(h,int32_t(value%7)-1,(value>>16)&1);
                game_imgui_mouse_wheel(h,1,-1);game_imgui_key(h,0xFFFF,1);break;
            case 11:
                model.focused=(value&0x100)!=0;game_imgui_focus(h,model.focused?1:0);break;
            case 12: game_imgui_clear_input(h);check(game_imgui_test_queue_size()==0,COZY_TEXT_TEST_BRIDGE_GENERATED_CLEAR_EMPTIES_QUEUED_INPUT_E7E3B6BF);break;
            case 13:
                model.editor=(value&0x100)!=0;check(game_imgui_text_input_enable_v1(h,model.editor?1:0)==1,COZY_TEXT_TEST_BRIDGE_GENERATED_EDITOR_ENABLE_DISABLE_D7BB2049);break;
            case 14: {
                char out[513];memset(out,0x33,sizeof(out));
                check(game_imgui_text_input_enable_v1(h,2)==0,COZY_TEXT_TEST_BRIDGE_INVALID_EDITOR_OPTION_REJECTED_3B0271EC);
                check(game_imgui_text_input_utf8_v1(h,COZY_TEXT_TEST_BRIDGE_X_A680F36E,1,99)==0,COZY_TEXT_TEST_BRIDGE_UNKNOWN_INPUT_ACTION_REJECTED_AA7CE791);
                check(game_imgui_text_input_read_v1(h,out,512,0)==-1 && out[0]==0x33,COZY_TEXT_TEST_BRIDGE_SHORT_READ_BUFFER_REJECTED_WITHOUT_WRITE_5C616936);break;
            }
            case 15: invalid_handle_calls(stale,h);break;
            case 16:
                check(game_imgui_destroy(h)==1&&allocations==0,COZY_TEXT_TEST_BRIDGE_GENERATED_OPEN_CLOSED_FRAME_DESTROY_RELEASES_ALL_84ED12FA);
                stale=h;h=0;check(game_imgui_create(reinterpret_cast<void*>(1),&host,&h)==1&&h!=stale,COZY_TEXT_TEST_BRIDGE_GENERATED_RECREATION_ADVANCES_HANDLE_GENERATION_83509876);
                ++lifecycles;model=SequenceModel();break;
            case 17:
                for(unsigned i=0;i<270;++i)game_imgui_mouse_button(h,0,i&1);
                check(game_imgui_test_queue_size()<=256,COZY_TEXT_TEST_BRIDGE_GENERATED_OVERFLOW_NEVER_GROWS_QUEUE_BEYOND_CONT_50268363);break;
            case 18:
                game_imgui_end_canvas(h);model.canvas=false;
                if(model.frame){check(game_imgui_render_present(h)==-1,COZY_TEXT_TEST_BRIDGE_RECOVERY_FINISHES_CURRENT_PORTABLE_FRAME_3B9F9541);model.frame=false;}
                check(game_imgui_new_frame(h,320,160,1.0f/60)==1,COZY_TEXT_TEST_BRIDGE_INVALID_ORDER_REJECTION_REMAINS_REUSABLE_6B49C204);
                model.frame=true;model.begun=false;model.items=0;model.bytes=0;
                game_imgui_begin_canvas(h);model.canvas=true;model.begun=true;
                game_imgui_text(h,COZY_TEXT_TEST_BRIDGE_RECOVERED_5F4C41A4);model.items=1;model.bytes=9;break;
            case 19: input_float_boundaries(h);break;
            }
            verify_model(h,model);
        }
        // A real recorded failure is sticky; invalid calls never revive a lease
        // or GPU result. Only owner destruction followed by creation recovers.
        check(game_imgui_test_gpu_error(h,static_cast<int32_t>(0x887A0005u))==1,COZY_TEXT_TEST_BRIDGE_RECORD_TERMINAL_BACKEND_FAILURE_9DF5AA20);
        for(unsigned i=0;i<16;++i){
            check(game_imgui_new_frame(h,320,160,1.0f/60)==0 && game_imgui_resize(h,320,160)==0,COZY_TEXT_TEST_BRIDGE_FAILED_BACKEND_NEVER_REOPENS_THROUGH_GENERATED_C_2E371D82);
            check(game_imgui_render_present(h)==-1 && game_imgui_last_error(h)==static_cast<int32_t>(0x887A0005u),COZY_TEXT_TEST_BRIDGE_FAILED_BACKEND_RETAINS_FIRST_DIAGNOSTIC_11E04A27);
        }
        check(game_imgui_destroy(h)==1&&allocations==0,COZY_TEXT_TEST_BRIDGE_FAILED_GENERATED_CONTEXT_RELEASES_ALL_HOST_MEMOR_013CB47A);
    }
    for(unsigned count:coverage)check(count>0,COZY_TEXT_TEST_BRIDGE_EVERY_GENERATED_OPERATION_EXERCISED_D224CA6C);
    sequence_seed=sequence_step=sequence_operation=0;
    printf(COZY_TEXT_TEST_BRIDGE_SEEDED_PUBLIC_API_MODEL_4_SEEDS_2048_OPERATIONS__987C709E,lifecycles,checks-checks_before);
}

static GameImGuiHandle scene_test_handle=0;
static int scene_test_tab=0,scene_test_licensed=-2;
static int scene_frame(GameImGuiHandle h,int phase,int selected,uint32_t flags,float position=1,float time=2) {
    check(game_imgui_new_frame(h,680,440,1.0f/60)==1,COZY_TEXT_TEST_BRIDGE_COMPACT_SCENE_STARTS_A_REAL_IMGUI_FRAME_3D09FA97);
    game_imgui_begin_canvas(h);
    if(scene_test_handle!=h){scene_test_handle=h;scene_test_tab=0;scene_test_licensed=-2;}
    const int base=scene_test_tab==1?12:scene_test_tab==2?6:0;
    const int license=scene_test_licensed==-2?base+selected:scene_test_licensed;
    int actions=game_imgui_scene_v3(h,phase,selected,flags|(scene_test_tab<<4),time,position,license,phase==2?0.5f:0.0f);
    if(actions>=0){for(int tab=0;tab<3;++tab)if(actions&(1<<(13+tab)))scene_test_tab=tab;actions&=~(7<<13);}
    game_imgui_end_canvas(h);
    check(game_imgui_render_present(h)==-1,COZY_TEXT_TEST_BRIDGE_HEADLESS_SCENE_CANNOT_ACKNOWLEDGE_A_GPU_PRESENT_823C6991);
    check(game_imgui_test_draw_vertices(h)>1000,COZY_TEXT_TEST_BRIDGE_COMPACT_SCENE_PRODUCES_ACTUAL_ROUNDED_ARTWORK_AN_BCBFB3F0);
    return actions;
}
static int scene_click(GameImGuiHandle h,int phase,int selected,uint32_t flags,float x,float y) {
    game_imgui_mouse_pos(h,x,y);scene_frame(h,phase,selected,flags,float(selected));
    game_imgui_mouse_button(h,0,1);scene_frame(h,phase,selected,flags,float(selected));
    game_imgui_mouse_button(h,0,0);return scene_frame(h,phase,selected,flags,float(selected));
}
static void scene_reveal_contracts(const GameImGuiHost& host) {
    GameImGuiHandle h=0;check(game_imgui_create(reinterpret_cast<void*>(1),&host,&h)==1,COZY_TEXT_TEST_BRIDGE_REVEAL_CREATES_A_FRESH_BOUNDED_SCENE_CD92633F);
    float state[3]={},first[6]={},last[6]={};
    check(game_imgui_test_scene_reveal(h,state,3)==1&&state[0]==0,COZY_TEXT_TEST_BRIDGE_REVEAL_BEGINS_ONLY_WHEN_A_SCENE_IS_FIRST_RENDERE_81B8C688);
    check(scene_frame(h,0,1,4)==0,COZY_TEXT_TEST_BRIDGE_FIRST_CENTERED_UNFOLDING_FRAME_CANNOT_DISPATCH_A_66741384);
    check(game_imgui_test_scene_reveal(h,state,3)==1&&state[0]>0&&state[0]<0.45f&&state[1]>0.14f&&state[1]<1&&state[2]>0&&state[2]<1,COZY_TEXT_TEST_BRIDGE_FIRST_UNFOLDING_FRAME_IS_SCALED_AND_TRANSLUCENT_6BB814A3);
    const float first_scale=state[1];game_imgui_test_scene_draw_bounds(h,first,6);
    check(first[4]>0&&first[4]<255&&first[5]==0,COZY_TEXT_TEST_BRIDGE_ACTUAL_FIRST_FRAME_VERTICES_FADE_AND_TRANSFORMED_6659D2CA);
    game_imgui_mouse_pos(h,340,398);game_imgui_mouse_button(h,0,1);
    float previous=state[1];
    for(int i=0;i<12;++i){check(scene_frame(h,0,1,4)==0,COZY_TEXT_TEST_BRIDGE_HELD_START_IS_INERT_DURING_CENTER_REVEAL_37B957AD);
      game_imgui_test_scene_reveal(h,state,3);check(state[1]>previous&&state[1]<1,COZY_TEXT_TEST_BRIDGE_CENTER_REVEAL_EXPANDS_CONTINUOUSLY_WITHOUT_OVERS_3D3F65D4);previous=state[1];}
    game_imgui_mouse_button(h,0,0);check(scene_frame(h,0,1,4)==0,COZY_TEXT_TEST_BRIDGE_A_PRESS_RELEASED_DURING_REVEAL_CANNOT_START_LATE_D542F7AF);
    check(scene_click(h,0,1,4,428,43)==0,COZY_TEXT_TEST_BRIDGE_TAB_INTERACTION_IS_INERT_DURING_REVEAL_4C145732);
    float tab_state[5]={};game_imgui_test_scene_state(h,tab_state,5);check(tab_state[2]==0,COZY_TEXT_TEST_BRIDGE_REVEAL_TIME_CLICKS_LEAVE_THE_SELECTED_TAB_UNCHAN_A3DD1BF8);
    for(int i=0;i<30;++i)check(scene_frame(h,0,1,4)==0,COZY_TEXT_TEST_BRIDGE_SETTLING_REVEAL_HAS_NO_SYNTHETIC_ACTION_3CF2527F);
    game_imgui_test_scene_reveal(h,state,3);game_imgui_test_scene_draw_bounds(h,last,6);
    check(state[0]==0.45f&&state[1]==1&&state[2]==1,COZY_TEXT_TEST_BRIDGE_ONE_SHOT_REVEAL_SETTLES_EXACTLY_AT_FINAL_IDENTIT_9F190F42);
    check(last[4]==255&&last[5]==0,COZY_TEXT_TEST_BRIDGE_SETTLED_ACTUAL_DRAW_DATA_IS_FULLY_OPAQUE_WITH_VA_058C5FE0);
    check(fabs((first[2]-first[0])/(last[2]-last[0])-first_scale)<0.002f,COZY_TEXT_TEST_BRIDGE_ACTUAL_DRAW_VERTICES_EXPAND_FROM_THE_CENTER_BY_T_3171886E);
    check(fabs((first[0]+first[2])*0.5f-(340+((last[0]+last[2])*0.5f-340)*first_scale))<0.01f,COZY_TEXT_TEST_BRIDGE_ACTUAL_HORIZONTAL_REVEAL_IS_CENTERED_ON_THE_WIND_383DD8C2);
    check(fabs((first[1]+first[3])*0.5f-(220+((last[1]+last[3])*0.5f-220)*first_scale))<0.01f,COZY_TEXT_TEST_BRIDGE_ACTUAL_VERTICAL_REVEAL_IS_CENTERED_ON_THE_WINDOW_494834F0);
    check(scene_click(h,0,1,4,428,43)==0,COZY_TEXT_TEST_BRIDGE_CENTERED_RIGHT_TAB_IS_ACTIONABLE_AFTER_REVEAL_58166D17);game_imgui_test_scene_state(h,tab_state,5);check(tab_state[2]==2,COZY_TEXT_TEST_BRIDGE_RIGHT_TAB_CENTER_SELECTS_SPOOFER_751168FD);
    scene_frame(h,1,1,4,1,0);scene_frame(h,0,1,4,1,0);game_imgui_test_scene_reveal(h,state,3);
    check(state[0]==0.45f&&state[1]==1,COZY_TEXT_TEST_BRIDGE_PHASE_CHANGES_AND_ANIMATION_CLOCK_RESET_NEVER_RE_01F05159);
    check(scene_click(h,0,1,4,252,43)==0,COZY_TEXT_TEST_BRIDGE_CENTERED_LEFT_TAB_IS_ACTIONABLE_AFTER_REVEAL_651FE8E1);game_imgui_test_scene_state(h,tab_state,5);check(tab_state[2]==0,COZY_TEXT_TEST_BRIDGE_LEFT_TAB_CENTER_SELECTS_CLEANNER_5A03D401);
    check(scene_click(h,0,1,4,340,398)==8,COZY_TEXT_TEST_BRIDGE_START_RESUMES_ITS_LOCAL_ACTION_AFTER_REVEAL_420A84FD);
    check(game_imgui_destroy(h)==1,COZY_TEXT_TEST_BRIDGE_REVEAL_SCENE_OWNERSHIP_CLOSES_NORMALLY_F7A71DEA);
    check(game_imgui_create(reinterpret_cast<void*>(1),&host,&h)==1,COZY_TEXT_TEST_BRIDGE_REDUCED_MOTION_REVEAL_CREATES_A_FRESH_SCENE_A278D8DC);
    scene_frame(h,0,1,6);game_imgui_test_scene_reveal(h,state,3);game_imgui_test_scene_draw_bounds(h,last,6);
    check(state[0]==0.45f&&state[1]==1&&state[2]==1&&last[4]==255,COZY_TEXT_TEST_BRIDGE_REDUCED_MOTION_PRESENTS_FINAL_GEOMETRY_IMMEDIATE_0AF5AAE6);
    check(game_imgui_destroy(h)==1,COZY_TEXT_TEST_BRIDGE_REDUCED_MOTION_SCENE_OWNERSHIP_CLOSES_NORMALLY_66D22A1A);
}
static void scene_contracts(const GameImGuiHost& host) {
    scene_reveal_contracts(host);
    GameImGuiHandle h=0;
    check(game_imgui_create(reinterpret_cast<void*>(1),&host,&h)==1,COZY_TEXT_TEST_BRIDGE_COMPACT_SCENE_CREATES_WITHIN_ITS_FIXED_ARENA_C03BFF85);
    check(game_imgui_scene_v2(h,0,0,6,0,0)==-1,COZY_TEXT_TEST_BRIDGE_COMPACT_SCENE_REJECTS_A_CALL_OUTSIDE_A_CANVAS_EE15D72E);
    check(game_imgui_new_frame(h,680,440,1.0f/60)==1,COZY_TEXT_TEST_BRIDGE_INVALID_COMPACT_SCENE_TEST_FRAME_CAC0E97F);game_imgui_begin_canvas(h);
    const float bad_time[]={NAN,INFINITY,-INFINITY,-1.0f,86401.0f};
    for(float f:bad_time)check(game_imgui_scene_v2(h,0,0,6,f,0)==-1,COZY_TEXT_TEST_BRIDGE_NONFINITE_AND_OUT_OF_BOUND_SCENE_TIME_IS_REJECTE_71AD31F9);
    const float bad_position[]={NAN,INFINITY,-INFINITY,-1.01f,6.01f};
    for(float f:bad_position)check(game_imgui_scene_v2(h,0,0,6,0,f)==-1,COZY_TEXT_TEST_BRIDGE_PERIODIC_POSITION_REMAINS_BOUNDED_TO_A_REVIEWED__FD7FA51F);
    check(game_imgui_scene_v2(h,-1,0,6,0,0)==-1&&game_imgui_scene_v2(h,4,0,6,0,0)==-1,COZY_TEXT_TEST_BRIDGE_UNKNOWN_SHUTDOWN_PRESENTATION_STATE_IS_REJECTED_B3671ED6);
    check(game_imgui_scene_v2(h,0,-1,6,0,0)==-1&&game_imgui_scene_v2(h,0,6,6,0,0)==-1,COZY_TEXT_TEST_BRIDGE_UNKNOWN_FIXED_PORTRAIT_INDEX_IS_REJECTED_F2BDC452);
    check(game_imgui_scene_v2(h,0,0,8,0,0)==-1,COZY_TEXT_TEST_BRIDGE_UNKNOWN_SCENE_FLAGS_ARE_REJECTED_FC6E0275);
    check(game_imgui_scene_v2(reinterpret_cast<void*>(0x1234),0,0,6,0,0)==-1,COZY_TEXT_TEST_BRIDGE_OPAQUE_SCENE_OWNERSHIP_IS_ENFORCED_3E0C7AAA);
    uint32_t state[9]={};game_imgui_test_contract_state(h,state,9);
    check(state[3]==0&&state[4]==0,COZY_TEXT_TEST_BRIDGE_REJECTED_SCENE_CALLS_LEAVE_THE_FRAME_ADMISSION_B_5975EF34);
    check(game_imgui_scene_v2(h,0,0,6,0,0)==0,COZY_TEXT_TEST_BRIDGE_FIRST_VISIBLE_SCENE_IS_THE_GALLERY_WITH_NO_AUTOM_8267CAA1);
    check(game_imgui_scene_v2(h,0,0,6,0,0)==-1,COZY_TEXT_TEST_BRIDGE_SECOND_SCENE_IN_ONE_FRAME_IS_REJECTED_8C4D17D2);
    game_imgui_text(h,COZY_TEXT_TEST_BRIDGE_UNREVIEWED_TAIL_B4A005CB);game_imgui_test_contract_state(h,state,9);
    check(state[3]==8&&state[4]==512,COZY_TEXT_TEST_BRIDGE_FIXED_COMPACT_SCENE_CONSUMES_ALL_LEGACY_TEXT_AND_35A70C62);
    game_imgui_end_canvas(h);game_imgui_render_present(h);
    check(scene_click(h,0,1,6,176,216)==128,COZY_TEXT_TEST_BRIDGE_LEFT_PORTRAIT_SELECTS_ITS_FIXED_INDEX_WITHOUT_AN_BCE409DB);
    check(scene_click(h,0,1,6,504,216)==512,COZY_TEXT_TEST_BRIDGE_RIGHT_PORTRAIT_SELECTS_ITS_FIXED_INDEX_WITHOUT_A_B1AA700D);
    check((scene_click(h,0,1,6,340,216)&8)==0,COZY_TEXT_TEST_BRIDGE_PORTRAIT_CLICK_CANNOT_INVOKE_THE_COHORT_RUN_ACTI_AD47839D);
    check(scene_click(h,0,1,2,340,396)==0,COZY_TEXT_TEST_BRIDGE_DISABLED_RUN_NEVER_REQUESTS_SHUTDOWN_7FD6C719);
    check(scene_click(h,0,1,6,340,396)==8,COZY_TEXT_TEST_BRIDGE_RUN_EMITS_EXACTLY_ONE_HOST_SHUTDOWN_REQUEST_1D30F995);
    check(scene_click(h,1,1,6,340,396)==0,COZY_TEXT_TEST_BRIDGE_PENDING_CIRCULAR_LOADER_DISABLES_REPEATED_RUN_RE_393130AE);
    check(scene_click(h,1,1,6,176,216)==0,COZY_TEXT_TEST_BRIDGE_PENDING_SHUTDOWN_DISABLES_PORTRAIT_SELECTION_21A35BE7);
    check(scene_click(h,2,1,6,340,396)==0,COZY_TEXT_TEST_BRIDGE_ACKNOWLEDGEMENT_TOAST_NEVER_EMITS_ACTIONS_B2E9D6E9);
    check(scene_click(h,3,1,6,340,396)==8,COZY_TEXT_TEST_BRIDGE_UNCONFIRMED_SHUTDOWN_CAN_REQUEST_AN_EXPLICITLY_E_DAD3C82E);
    check(scene_click(h,0,1,6,610,38)==0,COZY_TEXT_TEST_BRIDGE_OLD_PAUSE_AND_THEME_CONTROLS_HAVE_NO_HIT_TARGET_A1E6DDC3);
    float scene_state[5]={};
    scene_frame(h,0,1,4);game_imgui_test_scene_state(h,scene_state,5);
    const float before_drag=scene_state[0];
    game_imgui_mouse_pos(h,460,220);game_imgui_mouse_button(h,0,1);scene_frame(h,0,1,4);
    game_imgui_mouse_pos(h,360,220);scene_frame(h,0,1,4);game_imgui_test_scene_state(h,scene_state,5);
    check(scene_state[1]==1&&scene_state[0]>before_drag+0.5f,COZY_TEXT_TEST_BRIDGE_DRAG_MOVES_THE_REAL_CAROUSEL_BEFORE_POINTER_RELE_286A6BD8);
    const float held_position=scene_state[0];
    game_imgui_mouse_button(h,0,0);const int swipe=scene_frame(h,0,1,4);
    check(swipe==512||swipe==1024,COZY_TEXT_TEST_BRIDGE_DRAG_COMMITS_ONE_BOUNDED_DESTINATION_WITHOUT_STA_14C18EA7);
    const int destination=swipe==512?2:3;
    game_imgui_test_scene_state(h,scene_state,5);
    check(scene_state[0]>held_position&&scene_state[0]<destination,COZY_TEXT_TEST_BRIDGE_RELEASE_BEGINS_CONTINUOUS_EASING_RATHER_THAN_JUM_BC7902F6);
    const float released_position=scene_state[0];
    scene_frame(h,0,destination,4);game_imgui_test_scene_state(h,scene_state,5);
    check(scene_state[0]>=released_position&&scene_state[0]<=destination,COZY_TEXT_TEST_BRIDGE_HOST_SELECTION_ACKNOWLEDGEMENT_CONTINUES_THE_SAM_560EF30B);
    for(int frame=0;frame<90;++frame)scene_frame(h,0,destination,4);
    game_imgui_test_scene_state(h,scene_state,5);check(fabs(scene_state[0]-destination)<0.001f,COZY_TEXT_TEST_BRIDGE_CAROUSEL_SETTLES_EXACTLY_AT_ITS_DESTINATION_E10FAF3A);
    scene_frame(h,0,1,6);
    game_imgui_mouse_pos(h,460,220);game_imgui_mouse_button(h,0,1);scene_frame(h,0,1,4);
    game_imgui_mouse_pos(h,300,220);scene_frame(h,0,1,4);game_imgui_focus(h,0);game_imgui_clear_input(h);
    check(scene_frame(h,0,1,4)==0,COZY_TEXT_TEST_BRIDGE_FOCUS_LOSS_CANCELS_A_DRAG_WITHOUT_SELECTING_OR_S_4593DA55);
    game_imgui_test_scene_state(h,scene_state,5);check(scene_state[1]==0&&scene_state[3]==0,COZY_TEXT_TEST_BRIDGE_FOCUS_CANCELLATION_CLEARS_DRAG_AND_VELOCITY_F566CAC0);
    game_imgui_focus(h,1);scene_frame(h,0,1,6);
    check(scene_click(h,0,1,6,428,43)==0,COZY_TEXT_TEST_BRIDGE_SPOOFER_TAB_IS_LOCAL_PRESENTATION_AND_EMITS_NO_H_A412B232);
    game_imgui_test_scene_state(h,scene_state,5);check(scene_state[2]==2&&scene_state[4]==2,COZY_TEXT_TEST_BRIDGE_SPOOFER_TAB_SELECTION_AND_INDICATOR_FOLLOW_REDUC_4E2DE615);
    check(scene_click(h,0,1,6,252,43)==0,COZY_TEXT_TEST_BRIDGE_CLEANNER_TAB_DOES_NOT_INVOKE_A_CLEANER_OR_START_2C6F272A);
    game_imgui_test_scene_state(h,scene_state,5);check(scene_state[2]==0,COZY_TEXT_TEST_BRIDGE_CLEANNER_TAB_RETURNS_TO_ITS_SELECTED_PRESENTATIO_3088BEDD);
    check(scene_click(h,0,1,6,638,396)==0,COZY_TEXT_TEST_BRIDGE_REMOVED_INFO_CONTROL_HAS_NO_ACTION_TARGET_CA6817B5);
    bool keyboard_tab=false;
    for(int step=0;step<12&&!keyboard_tab;++step){
      game_imgui_key(h,0x09,1);scene_frame(h,0,1,6);game_imgui_key(h,0x09,0);scene_frame(h,0,1,6);
      keyboard_tab=game_imgui_test_scene_focus(h)==3;
    }
    check(keyboard_tab,COZY_TEXT_TEST_BRIDGE_KEYBOARD_TAB_REACHES_THE_SPOOFER_PRESENTATION_TA_F17CDF3C);
    game_imgui_key(h,0x0D,1);check(scene_frame(h,0,1,6)==0,COZY_TEXT_TEST_BRIDGE_FOCUSED_TAB_ENTER_DOES_NOT_EXECUTE_START_FA4D6B63);
    game_imgui_key(h,0x0D,0);scene_frame(h,0,1,6);game_imgui_test_scene_state(h,scene_state,5);
    check(scene_state[2]==2,COZY_TEXT_TEST_BRIDGE_KEYBOARD_ACTIVATION_CHANGES_THE_PRESENTATION_TAB_FADB92BC);
    game_imgui_mouse_pos(h,460,220);game_imgui_mouse_button(h,0,1);scene_frame(h,0,1,4);
    game_imgui_mouse_pos(h,300,220);scene_frame(h,0,1,4);
    check(scene_frame(h,1,1,4)==0,COZY_TEXT_TEST_BRIDGE_SHUTDOWN_PHASE_CANCELS_AN_ACTIVE_POINTER_DRAG_WI_2DF35AD0);
    game_imgui_test_scene_state(h,scene_state,5);check(scene_state[1]==0&&scene_state[3]==0,COZY_TEXT_TEST_BRIDGE_PHASE_TRANSITION_CLEARS_DRAGGING_VELOCITY_49F26159);
    game_imgui_mouse_button(h,0,0);check(scene_frame(h,1,1,4)==0,COZY_TEXT_TEST_BRIDGE_RELEASE_AFTER_PHASE_CANCELLATION_CANNOT_SELECT_A_CF1AF2EF);
    scene_frame(h,0,1,6);

    for(int index=0;index<6;++index){scene_frame(h,0,index,6,float(index));
      check(scene_click(h,0,index,6,340,224)==(128<<index),COZY_TEXT_TEST_BRIDGE_ALL_SIX_DISTINCT_CENTRAL_POSTERS_SELECT_THEIR_EX_19D20758);}
    // Twelve distinct informational cards retain six selection indices per tab.
    float detail_state[7]={};
    for(int tab=0;tab<2;++tab){
      scene_click(h,0,0,6,tab?428:252,43);
      for(int index=0;index<6;++index){
        scene_frame(h,0,index,6,float(index));scene_frame(h,0,index,6,float(index));
        check(scene_click(h,0,index,6,340,224)==(128<<index),COZY_TEXT_TEST_BRIDGE_CARD_INFO_CLICK_PRESERVES_ITS_EXACT_LOCAL_SELECT_A41FFB5A);
        scene_frame(h,0,index,6,float(index));
        check(game_imgui_test_scene_detail(h,detail_state,7)==1,COZY_TEXT_TEST_BRIDGE_READ_ONLY_CARD_DETAIL_SNAPSHOT_REMAINS_BOUNDED_FAA2559C);
        check(detail_state[0]==1&&detail_state[1]==tab*6+index&&detail_state[2]==1&&detail_state[6]==tab*6+index,COZY_TEXT_TEST_BRIDGE_EVERY_GAME_AND_ANTI_CHEAT_CARD_OPENS_ITS_OWN_BLU_0796E094);
        check(scene_click(h,0,index,6,340,224)==(128<<index),COZY_TEXT_TEST_BRIDGE_SECOND_CARD_CLICK_CLOSES_INFO_WITHOUT_INVOKING_S_E6C1A1D4);
        scene_frame(h,0,index,6,float(index));game_imgui_test_scene_detail(h,detail_state,7);
        check(detail_state[0]==0&&detail_state[2]==0,COZY_TEXT_TEST_BRIDGE_CLOSED_INFORMATION_VIEW_RETURNS_TO_THE_ORIGINAL__995C85B0);
      }
    }
    for(float position=-1;position<=6;position+=0.125f){
      const int first=static_cast<int>(floor(position))-2;
      for(int slot=first;slot<first+5;++slot)
        check(fabs(game_imgui_test_scene_gap(position,slot)-13.0f)<0.001f,COZY_TEXT_TEST_BRIDGE_ALL_ADJACENT_CARD_EDGE_GAPS_STAY_EXACTLY_THIRTEE_20BD797D);
    }
    scene_click(h,0,0,6,252,43);scene_frame(h,0,0,6,0);scene_frame(h,0,0,6,0);
    game_imgui_test_scene_detail(h,detail_state,7);
    check(detail_state[3]==236&&detail_state[4]==176&&detail_state[5]==74,COZY_TEXT_TEST_BRIDGE_PUBG_APPLIES_ITS_WARM_ACCENT_TO_THE_SHARED_SCENE_D8CA154A);
    scene_frame(h,0,1,4,1);scene_frame(h,0,1,4,1);game_imgui_test_scene_detail(h,detail_state,7);
    check(detail_state[3]<236&&detail_state[3]>92&&detail_state[5]>74&&detail_state[5]<246,COZY_TEXT_TEST_BRIDGE_CARD_ACCENT_INTERPOLATES_CONTINUOUSLY_RATHER_THA_080AE0E5);
    scene_frame(h,0,1,6,1);scene_frame(h,0,1,6,1);game_imgui_test_scene_detail(h,detail_state,7);
    check(detail_state[3]==92&&detail_state[4]==189&&detail_state[5]==246,COZY_TEXT_TEST_BRIDGE_TALESRUNNER_APPLIES_ITS_DISTINCT_COOL_ACCENT_WHE_F50258B9);
    scene_click(h,0,1,6,340,224);scene_frame(h,0,1,6,1);game_imgui_test_scene_detail(h,detail_state,7);
    check(detail_state[0]==1,COZY_TEXT_TEST_BRIDGE_INFORMATION_VIEW_OPENS_BEFORE_KEYBOARD_SELECTION_1708B493);
    scene_frame(h,0,2,6,2);game_imgui_test_scene_detail(h,detail_state,7);
    check(detail_state[0]==0,COZY_TEXT_TEST_BRIDGE_EXTERNAL_KEYBOARD_SELECTION_CLOSES_THE_PREVIOUS__7D99FA05);
    check(scene_click(h,1,2,6,428,43)==0,COZY_TEXT_TEST_BRIDGE_LOADING_DISABLES_PRESENTATION_TAB_CLICKS_98792831);
    check(scene_click(h,1,2,6,340,224)==0,COZY_TEXT_TEST_BRIDGE_LOADING_DISABLES_INFORMATION_CARD_CLICKS_6BD9970C);
    game_imgui_mouse_pos(h,340,224);game_imgui_mouse_wheel(h,1,0);
    check(scene_frame(h,1,2,6,2)==0,COZY_TEXT_TEST_BRIDGE_LOADING_DISABLES_WHEEL_SELECTION_A7CBCEF2);
    scene_frame(h,0,1,6,1);
    scene_frame(h,0,5,6,5);scene_frame(h,0,0,4,0);game_imgui_test_scene_state(h,scene_state,5);
    check(scene_state[0]>5&&scene_state[0]<6,COZY_TEXT_TEST_BRIDGE_FIVE_TO_ZERO_WRAP_TAKES_THE_SHORT_FORWARD_PATH_02715B5F);
    scene_frame(h,0,0,6,0);scene_frame(h,0,5,4,5);game_imgui_test_scene_state(h,scene_state,5);
    check(scene_state[0]>5&&scene_state[0]<6,COZY_TEXT_TEST_BRIDGE_ZERO_TO_FIVE_WRAP_TAKES_THE_SHORT_REVERSE_PATH_0CAF8941);
    scene_frame(h,0,1,6,1);
    game_imgui_mouse_pos(h,340,220);scene_frame(h,0,1,6);game_imgui_mouse_wheel(h,1,0);
    check(scene_frame(h,0,1,6)==4,COZY_TEXT_TEST_BRIDGE_HORIZONTAL_WHEEL_ADVANCES_THE_GALLERY_WITHOUT_CH_BFF1E0E4);
    game_imgui_focus(h,0);game_imgui_clear_input(h);scene_frame(h,0,1,6);game_imgui_focus(h,1);
    scene_frame(h,0,1,6);scene_frame(h,0,1,6);game_imgui_key(h,0x0D,1);
    check((scene_frame(h,0,1,6)&8)!=0,COZY_TEXT_TEST_BRIDGE_ENTER_ACTIVATES_THE_INITIALLY_FOCUSED_RUN_ACTION_71F35F76);
    check(scene_frame(h,1,1,6)==0,COZY_TEXT_TEST_BRIDGE_HELD_ENTER_CANNOT_RETRIGGER_THE_PENDING_SHUTDOWN_CE593B80);
    check(scene_frame(h,1,1,6)==0,COZY_TEXT_TEST_BRIDGE_HELD_ENTER_REMAINS_A_SINGLE_ACTION_ACROSS_LATER__AA878A82);
    game_imgui_key(h,0x0D,0);scene_frame(h,0,1,6);
    const int sizes[][2]={{480,320},{680,440},{1020,660},{1360,880}};
    for(const auto& size:sizes)for(int phase=0;phase<4;++phase)for(unsigned flags=4;flags<8;++flags){
        check(game_imgui_new_frame(h,size[0],size[1],1.0f/60)==1,COZY_TEXT_TEST_BRIDGE_COMPACT_SCENE_ADMITS_ITS_BOUNDED_PHYSICAL_VIEWPO_7E02B054);
        game_imgui_begin_canvas(h);check(game_imgui_scene_v2(h,phase,1,flags,86400,1.5f)>=0,COZY_TEXT_TEST_BRIDGE_GALLERY_AND_TRUTHFUL_SHUTDOWN_PHASES_RENDER_AT_A_308CF133);
        game_imgui_end_canvas(h);game_imgui_render_present(h);
    }
    for(float position=-1;position<=6;position+=0.125f){
        check(scene_frame(h,0,1,6,position)==0,COZY_TEXT_TEST_BRIDGE_CYCLIC_CAROUSEL_POSITIONS_NEVER_ACTIVATE_A_CARD__4D14AD82);
    }
    scene_test_tab=0;scene_test_licensed=0;scene_frame(h,0,0,6,0);
    check(scene_click(h,0,0,6,340,398)==8,COZY_TEXT_TEST_BRIDGE_MATCHING_PRODUCT_CAN_REQUEST_SERVER_AUTHORIZATIO_FCB3AAF8);
    scene_frame(h,0,1,6,1);
    check(scene_click(h,0,1,6,340,398)==0,COZY_TEXT_TEST_BRIDGE_ANOTHER_GAME_NEVER_ENABLES_START_2A8E33B5);
    scene_test_tab=1;scene_frame(h,0,0,6,0);
    check(scene_click(h,0,0,6,340,398)==0,COZY_TEXT_TEST_BRIDGE_SAME_LOCAL_CARD_INDEX_IN_ANOTHER_CATEGORY_STAYS__2D4618C0);
    scene_test_licensed=12;scene_frame(h,0,0,6,0);
    check(scene_click(h,0,0,6,340,398)==8,COZY_TEXT_TEST_BRIDGE_MOBILE_ENTITLEMENT_MAPS_TO_IMMUTABLE_GLOBAL_INDE_752F4F0F);
    scene_test_licensed=-1;scene_frame(h,0,0,6,0);
    check(scene_click(h,0,0,6,340,398)==0,COZY_TEXT_TEST_BRIDGE_UNASSIGNED_AND_LEGACY_LICENSE_CANNOT_START_F373CFB6);
    scene_test_tab=0;scene_test_licensed=0;scene_frame(h,0,0,6,0);
    check(scene_click(h,0,0,6,504,224)==256,COZY_TEXT_TEST_BRIDGE_SIDE_CARD_SELECTS_THE_NEXT_DESTINATION_ONLY_764F98A4);
    game_imgui_test_scene_detail(h,detail_state,7);check(detail_state[0]==0,COZY_TEXT_TEST_BRIDGE_SIDE_CLICK_CANNOT_OPEN_DETAILS_DURING_RECENTERIN_F3828993);
    scene_frame(h,0,1,6,1);scene_frame(h,0,1,6,1);
    game_imgui_test_scene_detail(h,detail_state,7);check(detail_state[0]==0,COZY_TEXT_TEST_BRIDGE_ARRIVING_AT_CENTER_DOES_NOT_IMPLICITLY_OPEN_DETA_AA182F3D);
    check(scene_click(h,0,1,6,340,224)==256,COZY_TEXT_TEST_BRIDGE_SECOND_CENTERED_CLICK_OPENS_DETAILS_9844325B);
    scene_frame(h,0,1,6,1);game_imgui_test_scene_detail(h,detail_state,7);check(detail_state[0]==1,COZY_TEXT_TEST_BRIDGE_CENTERED_CARD_DETAIL_IS_VISIBLE_C1BC5D5C);
    scene_test_tab=1;scene_test_licensed=12;
    for(int index=0;index<6;++index){scene_frame(h,0,index,6,float(index));scene_frame(h,0,index,6,float(index));
      scene_click(h,0,index,6,340,224);scene_frame(h,0,index,6,float(index));game_imgui_test_scene_detail(h,detail_state,7);
      check(detail_state[0]==1&&detail_state[1]==12+index,COZY_TEXT_TEST_BRIDGE_ALL_SIX_MOBILE_CARDS_HAVE_THEIR_OWN_DETAIL_ARTWO_B885379D);}
    for(int phase=1;phase<=2;++phase){
      check(scene_click(h,phase,0,6,252,43)==0,COZY_TEXT_TEST_BRIDGE_PENDING_COUNTDOWN_BLOCKS_TABS_7DB695E2);
      check(scene_click(h,phase,0,6,504,224)==0,COZY_TEXT_TEST_BRIDGE_PENDING_COUNTDOWN_BLOCKS_CARDS_74F00F28);
      check(scene_click(h,phase,0,6,340,398)==0,COZY_TEXT_TEST_BRIDGE_PENDING_COUNTDOWN_BLOCKS_START_187B8CB9);
      game_imgui_mouse_pos(h,340,224);game_imgui_mouse_wheel(h,1,0);
      check(scene_frame(h,phase,0,6,0)==0,COZY_TEXT_TEST_BRIDGE_PENDING_COUNTDOWN_BLOCKS_WHEEL_998DDDF3);}
    scene_frame(h,0,0,6,0);check(scene_click(h,0,0,6,340,398)==8,COZY_TEXT_TEST_BRIDGE_INPUT_AND_MATCHING_ENTITLEMENT_RESTORE_AFTER_COU_8B0D3D44);
    check(game_imgui_destroy(h)==1&&allocations==0,COZY_TEXT_TEST_BRIDGE_COMPACT_SCENE_TEARDOWN_FREES_EVERY_OWNED_ALLOCAT_AD20CE8D);
}

extern "C" int game_imgui_test_wave_state(GameImGuiHandle,float*,unsigned);
static int license_frame(GameImGuiHandle h,int phase,int characters,float progress=0.0f,float scale=1.0f) {
    check(game_imgui_new_frame(h,340*scale,380*scale,1.0f/60)==1,COZY_TEXT_TEST_BRIDGE_LICENSE_PANEL_STARTS_REAL_FRAME_EE104A7D);game_imgui_begin_canvas(h);
    const int action=game_imgui_license_scene_v1(h,phase,characters,progress);game_imgui_end_canvas(h);
    check(game_imgui_render_present(h)==-1,COZY_TEXT_TEST_BRIDGE_LICENSE_HEADLESS_FRAME_CANNOT_CLAIM_GPU_PRESENTA_2594BCE8);
    check(game_imgui_test_draw_vertices(h)>1000,COZY_TEXT_TEST_BRIDGE_LICENSE_LOGO_AND_PANEL_GENERATE_REAL_VERTICES_7873A7ED);return action;
}
static int license_click(GameImGuiHandle h,int phase,int characters,float x,float y) {
    game_imgui_mouse_pos(h,x,y);license_frame(h,phase,characters);
    game_imgui_mouse_button(h,0,1);license_frame(h,phase,characters);
    game_imgui_mouse_button(h,0,0);return license_frame(h,phase,characters);
}
static void license_contracts(const GameImGuiHost& host) {
    GameImGuiHandle h=0;check(game_imgui_create(reinterpret_cast<void*>(1),&host,&h)==1,COZY_TEXT_TEST_BRIDGE_LICENSE_TEST_CONTEXT_7686735E);
    check(game_imgui_license_scene_v1(h,0,1,0)==-1,COZY_TEXT_TEST_BRIDGE_LICENSE_SCENE_REQUIRES_OWNED_ACTIVE_CANVAS_AABDE850);
    check(game_imgui_new_frame(h,340,380,1.0f/60)==1,COZY_TEXT_TEST_BRIDGE_LICENSE_INVALID_INPUT_FRAME_34E7902B);game_imgui_begin_canvas(h);
    check(game_imgui_license_scene_v1(h,-1,1,0)==-1&&game_imgui_license_scene_v1(h,4,1,0)==-1,COZY_TEXT_TEST_BRIDGE_LICENSE_PHASE_BOUNDED_BF6C41F4);
    check(game_imgui_license_scene_v1(h,0,-1,0)==-1&&game_imgui_license_scene_v1(h,0,101,0)==-1,COZY_TEXT_TEST_BRIDGE_SECRET_LENGTH_STRICTLY_BOUNDED_E1F4259A);
    check(game_imgui_license_scene_v1(h,0,1,NAN)==-1&&game_imgui_license_scene_v1(h,0,1,INFINITY)==-1,COZY_TEXT_TEST_BRIDGE_LICENSE_ANIMATION_REJECTS_NONFINITE_VALUES_7B6C1B03);
    check(game_imgui_license_scene_v1(h,0,0,0)==0,COZY_TEXT_TEST_BRIDGE_EMPTY_LICENSE_RENDERS_WITHOUT_SUBMIT_C236C475);
    check(game_imgui_license_scene_v1(h,0,0,0)==-1,COZY_TEXT_TEST_BRIDGE_LICENSE_SCENE_EXCLUSIVE_ONCE_PER_FRAME_99B885FE);game_imgui_end_canvas(h);game_imgui_render_present(h);
    check(license_click(h,0,0,170,265)==0,COZY_TEXT_TEST_BRIDGE_EMPTY_KEY_CANNOT_BE_SUBMITTED_8F18E5EF);
    check(license_click(h,0,40,170,265)==1,COZY_TEXT_TEST_BRIDGE_NONEMPTY_INPUT_EMITS_ONE_HOST_SUBMIT_REQUEST_F60B4374);
    check(license_click(h,1,40,170,265)==0,COZY_TEXT_TEST_BRIDGE_BUSY_WORKER_DISABLES_REPEATED_SUBMIT_FEA90876);
    check(license_click(h,1,40,170,206)==0,COZY_TEXT_TEST_BRIDGE_BUSY_WORKER_DISABLES_KEY_EDIT_FOCUS_62FB9363);
    check(license_click(h,2,40,170,206)==4,COZY_TEXT_TEST_BRIDGE_REJECTED_KEY_RESTORES_INPUT_FOCUS_EC40D5F3);
    check(license_click(h,2,40,170,265)==1,COZY_TEXT_TEST_BRIDGE_REJECTED_KEY_CAN_BE_RESUBMITTED_BY_HOST_E74DEB11);
    check(license_click(h,1,40,317,26)==0,COZY_TEXT_TEST_BRIDGE_REMOVED_CLOSE_TARGET_CANNOT_CANCEL_AUTHENTICATIO_60CAC9FF);
    check(license_click(h,3,40,317,26)==0,COZY_TEXT_TEST_BRIDGE_CLOSING_CANNOT_SUBMIT_ANOTHER_CANCELLATION_4F6D1EAE);
    license_frame(h,0,0);
    for(int n=0;n<=100;++n)check(license_frame(h,0,n)==0,COZY_TEXT_TEST_BRIDGE_EVERY_ALLOWED_MASKED_LENGTH_RENDERS_INSIDE_FIXED_8C6E421F);
    float visual[8]={};
    game_imgui_mouse_pos(h,170,206);license_frame(h,0,1);
    check(game_imgui_test_license_state(h,visual,8)==1&&visual[1]>0&&visual[1]<1,COZY_TEXT_TEST_BRIDGE_FIELD_HOVER_BEGINS_A_SMOOTH_HIGHLIGHT_E22D99F8);
    const float first_hover=visual[1];for(int i=0;i<16;++i)license_frame(h,0,1);
    game_imgui_test_license_state(h,visual,8);check(visual[1]>first_hover,COZY_TEXT_TEST_BRIDGE_FIELD_HOVER_CONVERGES_OVER_SUCCESSIVE_FRAMES_0A296468);
    check(license_click(h,0,1,170,206)==4,COZY_TEXT_TEST_BRIDGE_FIELD_CLICK_EMITS_INPUT_FOCUS_WITHOUT_SUBMIT_OR__F720C926);
    game_imgui_mouse_pos(h,20,320);license_frame(h,0,1);game_imgui_mouse_button(h,0,1);
    check(license_frame(h,0,1)==8,COZY_TEXT_TEST_BRIDGE_OUTSIDE_CLICK_CLEARS_HOST_INPUT_FOCUS_WITHOUT_CL_285AE891);
    game_imgui_mouse_button(h,0,0);license_frame(h,0,1);game_imgui_test_license_state(h,visual,8);
    check(visual[0]==0,COZY_TEXT_TEST_BRIDGE_OUTSIDE_CLICK_REMOVES_THE_NATIVE_CARET_FOCUS_0A479CDA);
    for(float scale:{0.75f,1.0f,1.25f,1.5f,2.0f})for(int n:{0,1,30,31,100}){
      license_frame(h,0,n,0,scale);game_imgui_test_license_state(h,visual,8);
      check(visual[3]>=88*scale&&visual[3]<=279*scale,COZY_TEXT_TEST_BRIDGE_ALL_MASKED_LENGTHS_KEEP_THE_CARET_INSIDE_THE_INP_B2FC5368);
      check(visual[4]<=31&&visual[4]<=n,COZY_TEXT_TEST_BRIDGE_THE_VISIBLE_MASK_IS_BOUNDED_WHILE_THE_HOST_RETAI_3209A3D0);}
    float water[10]={};
    license_frame(h,0,0);game_imgui_test_wave_state(h,water,10);
    check(water[9]==1,COZY_TEXT_TEST_BRIDGE_EMPTY_UNFOCUSED_INPUT_DISPLAYS_ITS_HINT_2FC21C2C);
    license_click(h,0,0,170,206);game_imgui_test_wave_state(h,water,10);
    check(water[9]==0,COZY_TEXT_TEST_BRIDGE_EMPTY_FOCUSED_INPUT_HIDES_ITS_HINT_9AC749D0);
    license_frame(h,0,1);game_imgui_test_wave_state(h,water,10);
    check(water[9]==0,COZY_TEXT_TEST_BRIDGE_ENTERED_KEY_HIDES_ITS_HINT_FCD5F5ED);
    license_click(h,0,1,20,320);game_imgui_test_wave_state(h,water,10);
    check(water[9]==0,COZY_TEXT_TEST_BRIDGE_UNFOCUSED_ENTERED_KEY_STILL_HIDES_ITS_HINT_04D5739B);
    license_frame(h,0,0);game_imgui_test_wave_state(h,water,10);
    check(water[9]==1,COZY_TEXT_TEST_BRIDGE_CLEARED_UNFOCUSED_INPUT_RESTORES_ITS_HINT_DC6BBDAA);
    license_frame(h,1,40,0);game_imgui_test_license_state(h,visual,8);
    check(visual[5]==0&&visual[6]==1&&visual[7]==1,COZY_TEXT_TEST_BRIDGE_AUTHENTICATION_STARTS_A_MODERATE_PANEL_BLUR_AND__557594C0);
    for(int i=0;i<80;++i)check(license_frame(h,1,40,0)==0,COZY_TEXT_TEST_BRIDGE_TIME_ALONE_CANNOT_ADVANCE_PENDING_WORK_OR_EMIT_A_619FAE49);
    game_imgui_test_wave_state(h,water,10);check(water[1]==0&&water[2]==0,COZY_TEXT_TEST_BRIDGE_PENDING_PERCENTAGE_STAYS_ZERO_WITHOUT_HOST_PROGR_442D29DD);
    for(int i=0;i<80;++i)license_frame(h,1,40,0.5f);
    game_imgui_test_wave_state(h,water,10);check(water[1]==0.5f&&water[2]==50,COZY_TEXT_TEST_BRIDGE_ACTUAL_HOST_MILESTONE_CONVERGES_TO_ITS_PERCENTAG_E9AF33B6);
    license_frame(h,1,40,0.25f);game_imgui_test_wave_state(h,water,10);check(water[1]==0.5f,COZY_TEXT_TEST_BRIDGE_AN_OLDER_PROGRESS_PUBLICATION_CANNOT_MOVE_WATER__3C710601);
    const float geometry=water[8];license_frame(h,1,40,0.5f);game_imgui_test_wave_state(h,water,10);
    check(water[1]==0.5f&&water[2]==50&&water[8]!=geometry,COZY_TEXT_TEST_BRIDGE_WATER_MOVES_WITHOUT_INVENTING_FURTHER_WORK_PROGR_126C2795);
    for(int i=0;i<80;++i)license_frame(h,1,40,1);
    game_imgui_test_wave_state(h,water,10);check(water[1]==0.99f&&water[2]==99,COZY_TEXT_TEST_BRIDGE_PENDING_AUTHENTICATION_CANNOT_DISPLAY_COMPLETION_1D333EF6);
    license_frame(h,3,40,1);game_imgui_test_wave_state(h,water,10);check(water[2]==99,COZY_TEXT_TEST_BRIDGE_GENERIC_CLOSING_CANNOT_INVENT_SUCCESS_95774C97);
    license_frame(h,2,0);game_imgui_test_license_state(h,visual,8);game_imgui_test_wave_state(h,water,10);
    check(visual[0]==1&&visual[6]==0&&visual[7]==0&&water[0]==0&&water[9]==0,COZY_TEXT_TEST_BRIDGE_SILENT_RETRY_FOCUSES_EMPTY_INPUT_HIDES_HINT_AND__B408D918);
    license_frame(h,0,0);game_imgui_test_license_state(h,visual,8);check(visual[0]==1,COZY_TEXT_TEST_BRIDGE_RETRY_FOCUS_REMAINS_WHEN_NORMAL_IDLE_RESUMES_AB95CF3A);
    license_frame(h,1,40,0);game_imgui_test_license_state(h,visual,8);check(visual[5]==0,COZY_TEXT_TEST_BRIDGE_A_LATER_ATTEMPT_RESETS_ITS_ACTUAL_PROGRESS_0C2F2AC9);
    for(float scale:{0.75f,1.0f,1.25f,1.5f,2.0f})for(float progress:{0.0f,0.01f,0.25f,0.5f,0.99f,1.0f}){
      license_frame(h,2,0,0,scale);
      for(int frame=0;frame<80;++frame)license_frame(h,1,40,progress,scale);
      game_imgui_test_wave_state(h,water,10);
      check(water[0]==1&&water[3]==170*scale&&water[4]==190*scale,COZY_TEXT_TEST_BRIDGE_B_LIQUID_STAYS_CENTERED_AT_EVERY_SUPPORTED_DPI_319C6107);
      check(water[7]<=water[5]*water[5]+0.02f&&std::isfinite(water[8]),COZY_TEXT_TEST_BRIDGE_ALL_B_LIQUID_VERTICES_STAY_INSIDE_THE_CLIPPED_CI_3E73DDD8);
      check(water[2]<=99&&water[1]<=0.99f,COZY_TEXT_TEST_BRIDGE_B_PENDING_PERCENTAGE_NEVER_REACHES_COMPLETION_AT_A0831771);}
    check(game_imgui_destroy(h)==1&&allocations==0,COZY_TEXT_TEST_BRIDGE_LICENSE_PANEL_RELEASES_EVERY_OWNED_ALLOCATION_A2D56F17);
    uint32_t font_bytes=0;unsigned char* font=read_test_font(COZY_TEXT_TEST_BRIDGE_COZY_IMGUI_MAX_FONT_TEST_FONT_C73391AE,&font_bytes);
    if(font){
      check(game_imgui_create_license_korean_v1(reinterpret_cast<void*>(1),&host,font,font_bytes,&h)==1,COZY_TEXT_TEST_BRIDGE_B_CREATES_ITS_REAL_KOREAN_FONT_CONTEXT_WITHIN_TH_3DA733D8);
      memset(font,0,font_bytes);free(font);
      game_imgui_focus(h,1);game_imgui_clear_input(h);
      for(int frame=0;frame<90;++frame)license_frame(h,0,0);
      game_imgui_test_license_state(h,visual,8);game_imgui_test_wave_state(h,water,10);
      check(visual[0]==0&&water[9]==1,COZY_TEXT_TEST_BRIDGE_REAL_B_CREATION_AND_FOCUS_RESET_EVENTS_KEEP_THE__2B077F19);
      check(license_click(h,0,0,170,206)==4,COZY_TEXT_TEST_BRIDGE_NORMAL_MOUSE_RELEASE_PRESERVES_INPUT_FOCUS_B90A7375);
      game_imgui_clear_input(h);license_frame(h,0,0);game_imgui_test_license_state(h,visual,8);game_imgui_test_wave_state(h,water,10);
      check(visual[0]==0&&water[9]==1,COZY_TEXT_TEST_BRIDGE_CAPTURE_CANCELLATION_CLEARS_NATIVE_FOCUS_TOGETHE_AB42D2E1);
      check(license_click(h,0,0,170,206)==4,COZY_TEXT_TEST_BRIDGE_INPUT_CAN_FOCUS_AGAIN_AFTER_CANCELLATION_ABB45349);
      game_imgui_focus(h,0);license_frame(h,0,0);game_imgui_focus(h,1);license_frame(h,0,0);
      game_imgui_test_license_state(h,visual,8);game_imgui_test_wave_state(h,water,10);
      check(visual[0]==0&&water[9]==1,COZY_TEXT_TEST_BRIDGE_WINDOW_REFOCUS_DOES_NOT_REVIVE_STALE_INPUT_FOCUS_61FDAEB2);
      int tab_actions=0;game_imgui_key(h,9,1);tab_actions|=license_frame(h,0,0);
      game_imgui_key(h,9,0);for(int frame=0;frame<3;++frame)tab_actions|=license_frame(h,0,0);
      game_imgui_test_license_state(h,visual,8);game_imgui_test_wave_state(h,water,10);
      check((tab_actions&4)!=0&&visual[0]==1&&water[9]==0,COZY_TEXT_TEST_BRIDGE_TAB_EXPLICITLY_FOCUSES_EMPTY_INPUT_AND_SYNCHRONI_1CE8D54C);
      for(float scale:{0.75f,1.0f,1.25f,1.5f,2.0f})for(int phase:{0,1,2,3}){
        check(game_imgui_set_dpi(h,scale)==1,COZY_TEXT_TEST_BRIDGE_B_SUPPORTS_THE_EXISTING_FONT_DPI_SETTINGS_ED8F225C);
        check(license_frame(h,phase,100,0.5f,scale)>=0,COZY_TEXT_TEST_BRIDGE_B_RENDERS_MAXIMUM_MASKED_LENGTH_IN_EVERY_PHASE_U_C7E7DFAE);
        check(game_imgui_test_arena_largest()>=32u*1024u*1024u,COZY_TEXT_TEST_BRIDGE_B_COUNTDOWN_AND_INPUT_EFFECTS_PRESERVE_THE_FULL__6640ED02);
      }
      check(game_imgui_destroy(h)==1&&allocations==0,COZY_TEXT_TEST_BRIDGE_B_KOREAN_FONT_SCENE_RELEASES_THE_ATLAS_AND_ALL_H_EB251A6D);
    }
}
static void liquid_scene_contracts(const GameImGuiHost& host) {
    GameImGuiHandle h=0;check(game_imgui_create(reinterpret_cast<void*>(1),&host,&h)==1,COZY_TEXT_TEST_BRIDGE_LIQUID_SCENE_OWNS_A_BOUNDED_CONTEXT_50FF8730);
    float water[10]={};
    for(float scale:{0.75f,1.0f,1.25f,1.5f,2.0f})for(float progress:{0.0f,0.01f,0.25f,0.5f,0.99f,1.0f}){
      for(int frame=0;frame<81;++frame){
        check(game_imgui_new_frame(h,680*scale,440*scale,1.0f/60)==1,COZY_TEXT_TEST_BRIDGE_LIQUID_SCENE_STARTS_A_SCALED_REAL_FRAME_4F5BC1E1);game_imgui_begin_canvas(h);
        check(game_imgui_scene_v3(h,frame?2:1,0,6,2,0,0,frame?progress:0)==0,COZY_TEXT_TEST_BRIDGE_PENDING_AND_RUNNING_LIQUID_SCENE_DENY_EVERY_ACTI_B3E97F7A);
        game_imgui_end_canvas(h);game_imgui_render_present(h);}
      game_imgui_test_wave_state(h,water,10);
      check(water[0]==1&&water[3]==340*scale&&water[4]==220*scale,COZY_TEXT_TEST_BRIDGE_O_LIQUID_STAYS_CENTERED_AT_EVERY_SUPPORTED_DPI_6C4AD94E);
      check(water[7]<=water[5]*water[5]+0.02f&&std::isfinite(water[8]),COZY_TEXT_TEST_BRIDGE_ALL_O_LIQUID_VERTICES_STAY_INSIDE_THE_CLIPPED_CI_967A8243);
      check(water[1]==progress&&water[2]==static_cast<int>(floorf(progress*100+0.0001f)),COZY_TEXT_TEST_BRIDGE_O_PERCENTAGE_FOLLOWS_HOST_PROGRESS_INCLUDING_COM_6C5DA008);
    }
    scene_frame(h,0,0,6,0);game_imgui_test_wave_state(h,water,10);check(water[0]==0,COZY_TEXT_TEST_BRIDGE_IDLE_REMOVES_THE_LIQUID_FOREGROUND_1180767E);
    check(game_imgui_destroy(h)==1&&allocations==0,COZY_TEXT_TEST_BRIDGE_LIQUID_CONTEXT_RELEASES_ALL_ALLOCATIONS_D7DA33A0);
}
static void entitlement_title_contracts(const GameImGuiHost& host) {
    GameImGuiHandle h=0;check(game_imgui_create(reinterpret_cast<void*>(1),&host,&h)==1,COZY_TEXT_TEST_BRIDGE_ENTITLEMENT_TITLE_TEST_CONTEXT_DB115E68);
    float baseline[5]={},observed[5]={};
    for(float scale:{0.75f,1.0f,1.25f,1.5f,2.0f})for(int license=-1;license<18;++license)for(int tab=0;tab<3;++tab){
      const int selected=tab+2;
      check(game_imgui_new_frame(h,680*scale,440*scale,1.0f/60)==1,COZY_TEXT_TEST_BRIDGE_ENTITLEMENT_TITLE_STARTS_A_REAL_SCALED_FRAME_98A9B05B);game_imgui_begin_canvas(h);
      check(game_imgui_scene_v3(h,0,selected,6u|(tab<<4),2.0f,static_cast<float>(selected),license,0)==0,COZY_TEXT_TEST_BRIDGE_BROWSING_ANOTHER_CATEGORY_CANNOT_AUTHORIZE_OR_CH_140056A9);
      game_imgui_end_canvas(h);game_imgui_render_present(h);
      check(game_imgui_test_scene_entitlement(h,observed,5)==1,COZY_TEXT_TEST_BRIDGE_ENTITLEMENT_GEOMETRY_COMES_FROM_THE_ACTUAL_IMGUI_40EB1B5C);
      if(license<0)check(observed[0]==0,COZY_TEXT_TEST_BRIDGE_AN_ABSENT_LICENSE_NEVER_INVENTS_A_HEADER_PRODUCT_7EBC4FC9);
      else {
        check(observed[0]>0&&observed[1]>=488*scale&&observed[3]<=656*scale&&observed[2]>=24*scale&&observed[4]<=62*scale,COZY_TEXT_TEST_BRIDGE_EVERY_GRANTED_PRODUCT_NAME_STAYS_IN_THE_FAR_RIGH_F2AB34E8);
        if(tab==0)for(int i=0;i<5;++i)baseline[i]=observed[i];
        else for(int i=0;i<5;++i)check(baseline[i]==observed[i],COZY_TEXT_TEST_BRIDGE_HEADER_ENTITLEMENT_GEOMETRY_STAYS_UNCHANGED_WHIL_8B4C336B);
      }
    }
    check(game_imgui_destroy(h)==1&&allocations==0,COZY_TEXT_TEST_BRIDGE_ENTITLEMENT_TITLE_CONTEXT_RELEASES_ALL_ALLOCATIO_F4653592);
}

// Emulate a classic Delphi caller: native entry must tolerate enabled FP
// traps, and return that exact caller environment after every call. These
// checks execute the production font baker, scene and lifetime, not a mock.
static unsigned short fp_x87_control(){unsigned short value;__asm__ __volatile__(COZY_TEXT_TEST_BRIDGE_FNSTCW_0_10618951 : COZY_TEXT_TEST_BRIDGE_M_ACCE2C7E(value));return value;}
static void fp_control(unsigned mxcsr,unsigned short x87){__asm__ __volatile__(COZY_TEXT_TEST_BRIDGE_FNCLEX_N_TFLDCW_0_EDAB1CB2 : : COZY_TEXT_TEST_BRIDGE_M_06AFED35(x87) : COZY_TEXT_TEST_BRIDGE_MEMORY_46CBAB37);__builtin_ia32_ldmxcsr(mxcsr);}
static void fp_environment_contracts(GameImGuiHost host){
    const unsigned original_mxcsr=__builtin_ia32_stmxcsr();const unsigned short original_x87=fp_x87_control();
    // Preserve every other control, exercise a non-default rounding mode/FTZ,
    // and leave invalid/divide/overflow exceptions enabled in the caller.
    const unsigned caller_mxcsr=((original_mxcsr&~0x603fu)|0x2000u|0x1f80u)^0x8000u;
    // Keep a pre-existing masked underflow status flag as well: the native
    // call must not erase caller status or leak its own overflow flag back.
    const unsigned delphi_mxcsr=(caller_mxcsr&~0x0680u)|0x0010u;
    const unsigned short delphi_x87=static_cast<unsigned short>((original_x87|0x003fu)&~0x000du);
    fp_control(delphi_mxcsr,delphi_x87);
    const auto unchanged=[&]{check(__builtin_ia32_stmxcsr()==delphi_mxcsr && fp_x87_control()==delphi_x87,COZY_TEXT_TEST_BRIDGE_NATIVE_CALL_RESTORES_EXACT_CALLER_FP_CONTROLS_AN_B4F3A409);};
    GameImGuiHandle h=0;
    check(game_imgui_create(reinterpret_cast<void*>(1),&host,&h)==1 && h,COZY_TEXT_TEST_BRIDGE_FONT_CREATION_TOLERATES_DELPHI_UNMASKED_OVERFLOW_7AAF0D5E);unchanged();
    const uint32_t nan_bits=0x7fc00000u;float invalid_dpi;memcpy(&invalid_dpi,&nan_bits,sizeof(invalid_dpi));
    check(game_imgui_set_dpi(h,invalid_dpi)==0,COZY_TEXT_TEST_BRIDGE_NONFINITE_INPUT_REFUSES_WITHOUT_LEAKING_A_NATIVE_E942E73D);unchanged();
    check(game_imgui_resize(h,680,440)==1 && game_imgui_set_dpi(h,1.0f)==1,COZY_TEXT_TEST_BRIDGE_FP_SCOPE_COVERS_RESIZE_AND_DPI_FED7EB22);unchanged();
    reentry_handle=h;trigger_reentry=true;
    check(game_imgui_resize(h,680,440)==1 && reentry_result==0,COZY_TEXT_TEST_BRIDGE_REENTRANT_REJECTION_KEEPS_ENCLOSING_FP_ENVIRONME_8CDBEA72);unchanged();
    check(game_imgui_new_frame(h,680,440,1.0f/60.0f)==1,COZY_TEXT_TEST_BRIDGE_FP_SCOPE_COVERS_REAL_CORE_FRAME_725AF77D);unchanged();
    game_imgui_begin_canvas(h);check(game_imgui_scene_v2(h,0,1,6,0,1)==0,COZY_TEXT_TEST_BRIDGE_FP_SCOPE_COVERS_COMPACT_SCENE_DA55CA4F);unchanged();
    game_imgui_end_canvas(h);check(game_imgui_render_present(h)==-1,COZY_TEXT_TEST_BRIDGE_PORTABLE_SCENE_HAS_NO_FABRICATED_GPU_PRESENT_F0CAC678);unchanged();
    check(game_imgui_test_draw_vertices(h)>0,COZY_TEXT_TEST_BRIDGE_UNMASKED_CALLER_GETS_ACTUAL_NATIVE_DRAW_DATA_41937F7A);unchanged();
    for(int phase=1;phase<=2;++phase){
      check(game_imgui_new_frame(h,680,440,1.0f/60.0f)==1,COZY_TEXT_TEST_BRIDGE_UNMASKED_CALLER_STARTS_LIQUID_FRAME_64434F7F);unchanged();
      game_imgui_begin_canvas(h);check(game_imgui_scene_v3(h,phase,0,6,0,0,0,0.5f)==0,COZY_TEXT_TEST_BRIDGE_LIQUID_MATH_PRESERVES_DELPHI_FLOATING_CONTROLS_CF22E5A5);unchanged();
      game_imgui_end_canvas(h);game_imgui_render_present(h);unchanged();}
    unsigned foreign_mxcsr=0;unsigned short foreign_x87=0;int foreign_result=-1;
    std::thread foreign([&]{
        const unsigned before=__builtin_ia32_stmxcsr();const unsigned short before_x87=fp_x87_control();
        fp_control(delphi_mxcsr,delphi_x87);foreign_result=game_imgui_resize(h,680,440);
        foreign_mxcsr=__builtin_ia32_stmxcsr();foreign_x87=fp_x87_control();fp_control(before,before_x87);
    });foreign.join();
    check(foreign_result==0 && foreign_mxcsr==delphi_mxcsr && foreign_x87==delphi_x87,COZY_TEXT_TEST_BRIDGE_FOREIGN_THREAD_REFUSAL_RESTORES_ITS_INDEPENDENT__5DD6AE9F);unchanged();
    check(game_imgui_destroy(h)==1 && allocations==0,COZY_TEXT_TEST_BRIDGE_FP_SCOPE_COVERS_NATIVE_CLEANUP_A3CB474C);unchanged();
    check(game_imgui_resize(h,680,440)==0 && game_imgui_destroy(h)==0,COZY_TEXT_TEST_BRIDGE_INVALID_EARLY_RETURNS_REMAIN_FAIL_CLOSED_6C63A477);unchanged();
    uint32_t korean_bytes=0;unsigned char* korean=read_test_font(COZY_TEXT_TEST_BRIDGE_COZY_IMGUI_KOREAN_TEST_FONT_946453CB,&korean_bytes);
    if(korean){
        h=0;check(game_imgui_create_korean_v1(reinterpret_cast<void*>(1),&host,korean,korean_bytes,&h)==1 && h,COZY_TEXT_TEST_BRIDGE_REVIEWED_KOREAN_FONT_BAKES_WITH_CALLER_FP_TRAPS__DE90768E);unchanged();
        memset(korean,0,korean_bytes);free(korean);
        check(game_imgui_new_frame(h,680,440,1.0f/60.0f)==1,COZY_TEXT_TEST_BRIDGE_UNMASKED_KOREAN_SCENE_FRAME_STARTS_E103A686);unchanged();
        game_imgui_begin_canvas(h);check(game_imgui_scene_v2(h,2,1,6,0,1)==0,COZY_TEXT_TEST_BRIDGE_UNMASKED_KOREAN_RECEIPT_BUILDS_ACTUAL_SCENE_932F48A4);game_imgui_end_canvas(h);unchanged();
        check(game_imgui_render_present(h)==-1 && game_imgui_test_draw_vertices(h)>0,COZY_TEXT_TEST_BRIDGE_UNMASKED_KOREAN_SCENE_PRODUCES_REAL_PORTABLE_DRA_E7B2A54E);unchanged();
        check(game_imgui_destroy(h)==1 && allocations==0,COZY_TEXT_TEST_BRIDGE_UNMASKED_KOREAN_LIFECYCLE_RELEASES_OWNED_FONT_AN_B6AE0826);unchanged();
    }
    host.abi_version=1;h=0;
    check(game_imgui_create(reinterpret_cast<void*>(1),&host,&h)==0 && !h && allocations==0,COZY_TEXT_TEST_BRIDGE_CREATION_ADMISSION_EARLY_RETURN_PRESERVES_FP_ENV_9E6949BC);unchanged();
    fp_control(original_mxcsr,original_x87);
    check(__builtin_ia32_stmxcsr()==original_mxcsr && fp_x87_control()==original_x87,COZY_TEXT_TEST_BRIDGE_TEST_RESTORES_ITS_OWN_ORIGINAL_FP_ENVIRONMENT_58F3FCA1);
}

static void texture_strip_contracts(){
    unsigned char input[256],rgba[1024];for(unsigned i=0;i<256;++i)input[i]=static_cast<unsigned char>(i);
    check(game_texture_expand_alpha8(input,sizeof(input),16,16,16,rgba,sizeof(rgba)),COZY_TEXT_TEST_BRIDGE_ALL_ALPHA8_COVERAGE_VALUES_EXPAND_651D23CB);
    for(unsigned i=0;i<256;++i)check(rgba[i*4]==255&&rgba[i*4+1]==255&&rgba[i*4+2]==255&&rgba[i*4+3]==i,COZY_TEXT_TEST_BRIDGE_RGBA8_EXPANSION_PRESERVES_EXACT_COVERAGE_AND_WHI_07AD807B);
    unsigned char atlas[73*11],guarded[16+23*7*4+16];
    for(unsigned i=0;i<sizeof(atlas);++i)atlas[i]=static_cast<unsigned char>((i*37u+11u)&255u);
    memset(guarded,0xA7,sizeof(guarded));
    check(game_texture_expand_alpha8(atlas+2*73+5,sizeof(atlas)-(2*73+5),73,23,7,guarded+16,23*7*4),COZY_TEXT_TEST_BRIDGE_PARTIAL_RECT_READS_EXACT_SOURCE_PITCH_3F1477C0);
    for(unsigned y=0;y<7;++y)for(unsigned x=0;x<23;++x){const size_t at=16+(y*23+x)*4;check(guarded[at]==255&&guarded[at+1]==255&&guarded[at+2]==255&&guarded[at+3]==atlas[(y+2)*73+x+5],COZY_TEXT_TEST_BRIDGE_PARTIAL_RECT_EXPANSION_KEEPS_ROW_AND_COLUMN_OFFS_887B4D08);}
    for(unsigned i=0;i<16;++i)check(guarded[i]==0xA7&&guarded[sizeof(guarded)-1-i]==0xA7,COZY_TEXT_TEST_BRIDGE_STRIP_OUTPUT_CANARIES_INTACT_50744522);
    for(unsigned width : {1u,13u,256u,1024u,16384u}){
        const unsigned height=17;const size_t bytes=static_cast<size_t>(width)*height;
        unsigned char* alpha=static_cast<unsigned char*>(malloc(bytes));unsigned char* strip=static_cast<unsigned char*>(malloc(GameTextureUploadBytes));
        check(alpha&&strip,COZY_TEXT_TEST_BRIDGE_BOUNDED_UPLOAD_FIXTURE_STORAGE_5040BFB8);for(size_t i=0;i<bytes;++i)alpha[i]=static_cast<unsigned char>(i*13u);
        unsigned done=0;
        while(done<height){const unsigned rows=game_texture_strip_rows(width,height-done);check(rows>0&&rows<=height-done&&static_cast<size_t>(rows)*width*4<=GameTextureUploadBytes,COZY_TEXT_TEST_BRIDGE_EVERY_UPLOAD_STRIP_STAYS_WITHIN_THE_FIXED_256KIB_AFAC88AB);
            check(game_texture_expand_alpha8(alpha+static_cast<size_t>(done)*width,bytes-static_cast<size_t>(done)*width,width,width,rows,strip,GameTextureUploadBytes),COZY_TEXT_TEST_BRIDGE_LAST_PARTIAL_STRIP_EXPANDS_1777F45E);
            for(size_t i=0;i<static_cast<size_t>(rows)*width;++i)check(strip[i*4+3]==alpha[static_cast<size_t>(done)*width+i],COZY_TEXT_TEST_BRIDGE_STRIP_SEQUENCE_RECONSTRUCTS_ORIGINAL_ALPHA_ROWS_195F7272);
            done+=rows;
        }
        check(done==height,COZY_TEXT_TEST_BRIDGE_STRIP_SEQUENCE_COVERS_ALL_ROWS_EXACTLY_ONCE_3EDC2974);free(strip);free(alpha);
    }
    memset(rgba,0xA7,sizeof(rgba));
    check(!game_texture_expand_alpha8(input,sizeof(input),16,0,1,rgba,sizeof(rgba))&&
          !game_texture_expand_alpha8(input,sizeof(input),16,16,0,rgba,sizeof(rgba))&&
          !game_texture_expand_alpha8(0,sizeof(input),16,16,1,rgba,sizeof(rgba))&&
          !game_texture_expand_alpha8(input,sizeof(input),16,16,1,0,sizeof(rgba))&&
          !game_texture_expand_alpha8(input,15,16,16,1,rgba,sizeof(rgba))&&
          !game_texture_expand_alpha8(input,sizeof(input),15,16,1,rgba,sizeof(rgba))&&
          !game_texture_expand_alpha8(input,sizeof(input),SIZE_MAX,16,3,rgba,sizeof(rgba))&&
          !game_texture_expand_alpha8(input,sizeof(input),16,16,1,rgba,63)&&
          !game_texture_strip_rows(0,10)&&!game_texture_strip_rows(16385,10)&&!game_texture_strip_rows(10,0),COZY_TEXT_TEST_BRIDGE_MALFORMED_AND_ZERO_SIZED_UPLOAD_SPANS_FAIL_BEFOR_3203CD94);
    for(unsigned i=0;i<sizeof(rgba);++i)check(rgba[i]==0xA7,COZY_TEXT_TEST_BRIDGE_REJECTED_EXPANSION_LEAVES_OUTPUT_UNTOUCHED_85218FA4);
}
static void maximum_font_contracts(const GameImGuiHost& host){
    uint32_t bytes=0;unsigned char* source=read_test_font(COZY_TEXT_TEST_BRIDGE_COZY_IMGUI_MAX_FONT_TEST_FONT_C73391AE,&bytes);if(!source)return;
    const uint32_t maximum=16u*1024u*1024u;
    unsigned char* font=static_cast<unsigned char*>(realloc(source,maximum));check(font!=0,COZY_TEXT_TEST_BRIDGE_MAXIMUM_ACCEPTED_FONT_FIXTURE_ALLOCATION_DA1A28E7);
    memset(font+bytes,0,maximum-bytes);GameImGuiHandle h=0;
    check(game_imgui_create_korean_v1(reinterpret_cast<void*>(1),&host,font,maximum,&h)==1&&h,COZY_TEXT_TEST_BRIDGE_MAXIMUM_ACCEPTED_REAL_KOREAN_FONT_INITIALIZES_WI_8720180D);
    memset(font,0,maximum);free(font);
    check(game_imgui_test_arena_largest()>=32u*1024u*1024u,COZY_TEXT_TEST_BRIDGE_MAXIMUM_FONT_RETAINS_FULL_32MIB_CONTIGUOUS_FRAME_CD17120B);
    for(float scale : {0.5f,0.75f,1.0f,1.25f,1.5f,1.75f,2.0f,2.5f,3.0f,4.0f,6.0f,8.0f}){
        check(game_imgui_set_dpi(h,scale)==1,COZY_TEXT_TEST_BRIDGE_ALL_EXISTING_DPI_SCALES_STAY_SUPPORTED_07F5D284);
        for(int phase=0;phase<4;++phase){
            check(game_imgui_new_frame(h,static_cast<int>(680*scale),static_cast<int>(440*scale),1.0f/60)==1,COZY_TEXT_TEST_BRIDGE_MAXIMUM_FONT_STARTS_EVERY_BOUNDED_SCENE_PHASE_32F434DF);
            game_imgui_mouse_pos(h,638*scale,396*scale);game_imgui_begin_canvas(h);
            check(game_imgui_scene_v2(h,phase,1,6,10.0f,1.0f)>=0,COZY_TEXT_TEST_BRIDGE_MAXIMUM_FONT_DRAWS_KOREAN_SCENE_AND_RECEIPT_AT_E_B0AF650D);
            game_imgui_end_canvas(h);check(game_imgui_render_present(h)==-1,COZY_TEXT_TEST_BRIDGE_PORTABLE_MAXIMUM_FONT_NEVER_PRETENDS_GPU_VISIBIL_8B6A5E05);
            check(game_imgui_test_draw_vertices(h)>0&&game_imgui_test_arena_largest()>=32u*1024u*1024u,COZY_TEXT_TEST_BRIDGE_ALL_DPI_FRAMES_KEEP_REAL_GEOMETRY_AND_UNCHANGED__FCBCB5DF);
        }
        const auto catalogue_frame=[&](int selected){
          check(game_imgui_new_frame(h,static_cast<int>(680*scale),static_cast<int>(440*scale),1.0f/120)==1,COZY_TEXT_TEST_BRIDGE_MAXIMUM_FONT_CATALOGUE_FRAME_STARTS_AT_EACH_DPI_CBFDA35A);
          game_imgui_begin_canvas(h);check(game_imgui_scene_v2(h,0,selected,6,12.0f,static_cast<float>(selected))>=0,COZY_TEXT_TEST_BRIDGE_MAXIMUM_FONT_RENDERS_BOTH_STATIC_INFORMATION_CAT_EFEC3FC7);
          game_imgui_end_canvas(h);check(game_imgui_render_present(h)==-1,COZY_TEXT_TEST_BRIDGE_CATALOGUE_CPU_FIXTURE_NEVER_CLAIMS_A_GPU_PRESENT_4C82CC14);
        };
        for(int tab=0;tab<2;++tab){
          game_imgui_mouse_pos(h,(tab?400:290)*scale,52*scale);catalogue_frame(1);
          game_imgui_mouse_button(h,0,1);catalogue_frame(1);game_imgui_mouse_button(h,0,0);catalogue_frame(1);
          for(int card=0;card<6;++card){
            catalogue_frame(card);game_imgui_mouse_pos(h,340*scale,224*scale);catalogue_frame(card);
            game_imgui_mouse_button(h,0,1);catalogue_frame(card);game_imgui_mouse_button(h,0,0);catalogue_frame(card);catalogue_frame(card);
            float detail[7]={};check(game_imgui_test_scene_detail(h,detail,7)==1&&detail[0]==1&&detail[1]==tab*6+card&&detail[2]==1,COZY_TEXT_TEST_BRIDGE_EVERY_INFORMATION_CARD_RENDERS_ITS_REAL_BLURRED__2CD1C899);
            check(game_imgui_test_arena_largest()>=32u*1024u*1024u,COZY_TEXT_TEST_BRIDGE_INFORMATION_TITLES_AND_DESCRIPTIONS_PRESERVE_THE_17DADC91);
          }
        }
    }
    printf(COZY_TEXT_TEST_BRIDGE_MAXIMUM_ACCEPTED_FONT_ARENA_PEAK_ZU_BYTES_LARGES_4F45BCDC,game_imgui_test_arena_peak(),game_imgui_test_arena_largest());
    check(game_imgui_destroy(h)==1&&allocations==0,COZY_TEXT_TEST_BRIDGE_MAXIMUM_FONT_LIFECYCLE_FREES_EVERY_OWNED_ALLOCAT_7F5D4028);
}

int main(){
    check(sizeof(GameImGuiHost)==32,COZY_TEXT_TEST_BRIDGE_WIN64_C_ABI_HOST_SIZE_38260527);check(game_imgui_abi_version()==3,COZY_TEXT_TEST_BRIDGE_BRIDGE_ABI_VERSION_BFBB4147);
    check(game_imgui_test_utf8(COZY_TEXT_TEST_BRIDGE_ASCII_LABEL_5A16CF02)==1,COZY_TEXT_TEST_BRIDGE_PRINTABLE_ASCII_RETAINED_454EF759);
    check(game_imgui_test_utf8(COZY_TEXT_TEST_BRIDGE_TEXT_D74439DE)==1,COZY_TEXT_TEST_BRIDGE_REVIEWED_KOREAN_UTF_8_ACCEPTED_D5BBEA59);
    check(game_imgui_test_utf8(COZY_TEXT_TEST_BRIDGE_TEXT_6B2DAF9B)==1,COZY_TEXT_TEST_BRIDGE_FULL_KOREAN_STATUS_ACCEPTED_CD5A4A33);
    check(game_imgui_test_utf8(COZY_TEXT_TEST_BRIDGE_XC0_XAF_5D0BC853)==0,COZY_TEXT_TEST_BRIDGE_OVERLONG_UTF8_REJECTED_0AD88A05);
    check(game_imgui_test_utf8(COZY_TEXT_TEST_BRIDGE_XED_XA0_X80_06B83949)==0,COZY_TEXT_TEST_BRIDGE_UTF8_SURROGATE_REJECTED_E51E5C4F);
    check(game_imgui_test_utf8(COZY_TEXT_TEST_BRIDGE_XE3_X80_44EAAFD2)==0,COZY_TEXT_TEST_BRIDGE_TRUNCATED_UTF8_REJECTED_E70E2769);
    check(game_imgui_test_utf8(COZY_TEXT_TEST_BRIDGE_LINE_NFEED_3EFFE4BF)==0,COZY_TEXT_TEST_BRIDGE_CONTROL_REJECTED_4197BB91);
    check(game_imgui_test_utf8(COZY_TEXT_TEST_BRIDGE_TEXT_AE79F8BA)==0,COZY_TEXT_TEST_BRIDGE_UNREVIEWED_GLYPH_CACHE_GROWTH_REJECTED_287DC687);
    char long_text[129];memset(long_text,'a',128);long_text[128]=0;
    check(game_imgui_test_utf8(long_text)==0,COZY_TEXT_TEST_BRIDGE_128_BYTE_ITEM_REJECTED_135B9F42);
    const struct{const char* text;int value;} values[]={{COZY_TEXT_TEST_BRIDGE_0_52C5CF58,0},{COZY_TEXT_TEST_BRIDGE_1_1FD7276C,-1},{COZY_TEXT_TEST_BRIDGE_2147483640_F5588044,2147483640},{COZY_TEXT_TEST_BRIDGE_2147483647_2AA1D361,INT_MAX},{COZY_TEXT_TEST_BRIDGE_2147483648_36F0B9D6,INT_MAX},{COZY_TEXT_TEST_BRIDGE_2147483648_37A63C80,INT_MIN},{COZY_TEXT_TEST_BRIDGE_2147483649_15086436,INT_MIN},{COZY_TEXT_TEST_BRIDGE_23X_B3106ACB,23}};
    for(size_t i=0;i<sizeof(values)/sizeof(values[0]);++i)check(game_imgui_test_atoi(values[i].text)==values[i].value,COZY_TEXT_TEST_BRIDGE_INTEGER_PARSER_BOUNDARY_B1B195E2);
    GameImGuiHost host={3,sizeof(GameImGuiHost),host_get,host_alloc,host_free};GameImGuiHandle h=0;
    texture_strip_contracts();maximum_font_contracts(host);
    fp_environment_contracts(host);
    // The rest of the independent caller model intentionally compares NaNs.
    // A trap-enabled process can isolate this native-boundary regression
    // without asking that unrelated model code to use C++'s masked defaults.
    if(getenv(COZY_TEXT_TEST_BRIDGE_COZY_IMGUI_FP_ONLY_3F4759BF)){printf(COZY_TEXT_TEST_BRIDGE_PASS_D_CORE_AND_UNMASKED_FP_BOUNDARY_CHECKS_GPU__29C73F85,checks);return 0;}
    unsigned char invalid_font[256]={};
    check(game_imgui_create_korean_v1(reinterpret_cast<void*>(1),&host,invalid_font,sizeof(invalid_font),&h)==static_cast<int32_t>(0x8007000Du)&&!h&&allocations==0,COZY_TEXT_TEST_BRIDGE_MALFORMED_FONT_REJECTED_BEFORE_ALLOCATION_D7382471);
    check(game_imgui_create_korean_v1(reinterpret_cast<void*>(1),&host,0,0,&h)==static_cast<int32_t>(0x8007000Du)&&!h&&allocations==0,COZY_TEXT_TEST_BRIDGE_MISSING_KOREAN_FONT_CANNOT_SILENTLY_FALL_BACK_7CDBC9DC);
    check(game_imgui_create_korean_v1(reinterpret_cast<void*>(1),&host,invalid_font,16u*1024u*1024u+1,&h)==static_cast<int32_t>(0x8007000Du)&&!h&&allocations==0,COZY_TEXT_TEST_BRIDGE_OVERSIZED_FONT_REJECTED_BEFORE_READING_CALLER_DA_B73B68D9);
    uint32_t font_bytes=0;unsigned char* font=read_test_font(COZY_TEXT_TEST_BRIDGE_COZY_IMGUI_MISSING_KOREAN_TEST_FONT_60D067A0,&font_bytes);
    if(font){check(game_imgui_create_korean_v1(reinterpret_cast<void*>(1),&host,font,font_bytes,&h)==static_cast<int32_t>(0x8007000Du)&&!h&&allocations==0,COZY_TEXT_TEST_BRIDGE_MISSING_KOREAN_GLYPH_RETURNS_SAFE_FAILURE_AND_FR_89DCE534);free(font);}
    font=read_test_font(COZY_TEXT_TEST_BRIDGE_COZY_IMGUI_KOREAN_TEST_FONT_946453CB,&font_bytes);
    if(font){
        check(game_imgui_create_korean_v1(reinterpret_cast<void*>(1),&host,font,font_bytes,&h)==1&&h,COZY_TEXT_TEST_BRIDGE_KOREAN_FONT_COPIED_AND_REVIEWED_GLYPHS_BAKED_553356BE);
        memset(font,0,font_bytes);free(font); // caller storage is retired immediately
        check(game_imgui_new_frame(h,640,320,1.0f/60)==1,COZY_TEXT_TEST_BRIDGE_KOREAN_FRAME_INDEPENDENT_OF_CALLER_FONT_LIFETIME_9A289E1D);
        game_imgui_begin_canvas(h);game_imgui_text(h,COZY_TEXT_TEST_BRIDGE_TEXT_6B2DAF9B);game_imgui_end_canvas(h);game_imgui_render_present(h);
        check(game_imgui_test_draw_vertices(h)>0,COZY_TEXT_TEST_BRIDGE_REVIEWED_KOREAN_GLYPHS_PRODUCE_REAL_DRAW_VERTICE_0C3C1135);
        check(game_imgui_text_input_enable_v1(h,1)==1,COZY_TEXT_TEST_BRIDGE_KOREAN_EDITOR_OPTS_IN_E12A5AC9);game_imgui_focus(h,1);
        check(game_imgui_new_frame(h,640,320,1.0f/60)==1,COZY_TEXT_TEST_BRIDGE_BOUNDED_ENTERED_KOREAN_FRAME_A9108AD9);game_imgui_begin_canvas(h);
        check(game_imgui_text_input_display_v1(h,COZY_TEXT_TEST_BRIDGE_TEXT_C87C6586,13)==1,COZY_TEXT_TEST_BRIDGE_ENTERED_KOREAN_GLYPHS_BAKED_WITHIN_EXPLICIT_BUDG_FE4E3631);
        game_imgui_end_canvas(h);game_imgui_render_present(h);
        printf(COZY_TEXT_TEST_BRIDGE_KOREAN_FIXTURE_ARENA_PEAK_ZU_BYTES_FONT_BYTES_U__0EE5C9B4,game_imgui_test_arena_peak(),font_bytes);
        check(game_imgui_test_arena_peak()<32u*1024u*1024u,COZY_TEXT_TEST_BRIDGE_KOREAN_REVIEWED_VOCABULARY_AND_BOUNDED_FONT_RETA_1C213E1A);
        check(game_imgui_destroy(h)==1&&allocations==0,COZY_TEXT_TEST_BRIDGE_KOREAN_CONTEXT_DESTROYS_ALL_OWNED_MEMORY_67C709CA);h=0;
    }
    deny_id=GI_PROC_D3D_COMPILE;check(!game_imgui_create(reinterpret_cast<void*>(1),&host,&h)&&!h&&allocations==0,COZY_TEXT_TEST_BRIDGE_MISSING_PROCEDURE_REJECTED_BEFORE_ALLOCATION_27B884F2);deny_id=0;
    host.abi_version=1;check(!game_imgui_create(reinterpret_cast<void*>(1),&host,&h)&&!h,COZY_TEXT_TEST_BRIDGE_BAD_ABI_VERSION_REJECTED_907C0FB0);host.abi_version=3;
    host.abi_version=2;check(!game_imgui_create(reinterpret_cast<void*>(1),&host,&h)&&!h,COZY_TEXT_TEST_BRIDGE_OLD_ANIMATION_COUNTDOWN_ABI2_IS_REJECTED_D115306E);host.abi_version=3;
    host.struct_size=24;check(!game_imgui_create(reinterpret_cast<void*>(1),&host,&h)&&!h,COZY_TEXT_TEST_BRIDGE_WRONG_HOST_SIZE_REJECTED_616A4E44);host.struct_size=sizeof(GameImGuiHost);
    fail_next_allocation=true;
    check(game_imgui_create(reinterpret_cast<void*>(1),&host,&h)==GI_ERROR_HOST_CONTEXT&&!h&&allocations==0,COZY_TEXT_TEST_BRIDGE_INITIAL_ALLOCATION_FAILURE_RETAINS_OOM_WITHOUT_L_11BC8942);
    check(game_imgui_create(reinterpret_cast<void*>(1),&host,&h)==1&&h&&allocations>0,COZY_TEXT_TEST_BRIDGE_CONTEXT_CREATE_USING_HOST_MEMORY_54B1A561);
    check(game_imgui_text_input_version()==1,COZY_TEXT_TEST_BRIDGE_VERSIONED_OPTIONAL_TEXT_ABI_5B001FA9);
    check(game_imgui_text_input_status_v1(h)==0,COZY_TEXT_TEST_BRIDGE_DISPLAY_ONLY_CONTEXT_HAS_NO_TEXT_INPUT_ALLOCATIO_6909754B);
    check(!game_imgui_text_input_utf16_v1(h,0xD55C),COZY_TEXT_TEST_BRIDGE_DISPLAY_ONLY_INPUT_IGNORED_5AD2E776);
    check(game_imgui_text_input_enable_v1(h,1)==1,COZY_TEXT_TEST_BRIDGE_EXPLICIT_EDITOR_OPT_IN_6382B9E1);
    check(!game_imgui_text_input_utf16_v1(h,'a'),COZY_TEXT_TEST_BRIDGE_OPT_IN_STILL_REQUIRES_FOCUS_7BE1B3B2);
    game_imgui_focus(h,1);
    check(game_imgui_text_input_utf8_v1(h,0,0,2)==1,COZY_TEXT_TEST_BRIDGE_REAL_BRIDGE_BEGINS_COMPOSITION_4AA9A8C5);
    check(game_imgui_text_input_utf8_v1(h,COZY_TEXT_TEST_BRIDGE_TEXT_BEC8E29C,3,1)==1,COZY_TEXT_TEST_BRIDGE_REAL_BRIDGE_RECEIVES_UTF8_PREEDIT_CD718970);
    char committed[513];
    check(game_imgui_text_input_read_v1(h,committed,sizeof(committed),0)==0,COZY_TEXT_TEST_BRIDGE_REAL_BRIDGE_NEVER_COMMITS_PREEDIT_9C6EF4BF);
    check(game_imgui_text_input_utf16_v1(h,0xD55C)==1,COZY_TEXT_TEST_BRIDGE_REAL_BRIDGE_CONSUMES_COMMITTED_UTF16_5BB33140);
    check(game_imgui_text_input_utf8_v1(h,0,0,3)==1,COZY_TEXT_TEST_BRIDGE_REAL_BRIDGE_ENDS_COMPOSITION_F3869C6B);
    check(game_imgui_text_input_read_v1(h,committed,sizeof(committed),0)==3&&!strcmp(committed,COZY_TEXT_TEST_BRIDGE_TEXT_BEC8E29C),COZY_TEXT_TEST_BRIDGE_REAL_BRIDGE_DELIVERS_EXACT_KOREAN_ONCE_C6FD841B);
    check(game_imgui_text_input_read_v1(h,committed,sizeof(committed),0)==0,COZY_TEXT_TEST_BRIDGE_REAL_BRIDGE_CONSUMES_COMMITTED_TEXT_F5B5D834);
    check(game_imgui_text_input_utf16_v1(h,0xD800)==1,COZY_TEXT_TEST_BRIDGE_REAL_BRIDGE_PENDING_SURROGATE_00BB2DF1);
    game_imgui_clear_input(h);check((game_imgui_text_input_status_v1(h)&12)==0,COZY_TEXT_TEST_BRIDGE_CLEAR_INPUT_RESETS_COMPOSITION_AND_SURROGATE_BE672778);
    check(game_imgui_text_input_utf16_v1(h,'a')==1,COZY_TEXT_TEST_BRIDGE_TEXT_QUEUED_BEFORE_FOCUS_LOSS_63578CFA);
    game_imgui_focus(h,0);game_imgui_focus(h,1);
    check(game_imgui_text_input_read_v1(h,committed,sizeof(committed),0)==0,COZY_TEXT_TEST_BRIDGE_FOCUS_TRANSITION_DISCARDS_QUEUED_TEXT_63ADE4B7);
    int foreign_text=-1;std::thread text_thread([&]{foreign_text=game_imgui_text_input_utf16_v1(h,'x');});text_thread.join();
    check(foreign_text==0,COZY_TEXT_TEST_BRIDGE_TEXT_INPUT_RESPECTS_OWNER_THREAD_178DD0C3);
    check(game_imgui_new_frame(h,320,160,1.0f/60)==1,COZY_TEXT_TEST_BRIDGE_TEXT_DISPLAY_FRAME_10B12765);game_imgui_begin_canvas(h);
    check(game_imgui_text_input_display_v1(h,COZY_TEXT_TEST_BRIDGE_BOUNDED_INPUT_CA557B02,13)==1,COZY_TEXT_TEST_BRIDGE_OPT_IN_TEXT_DISPLAY_USES_BOUNDED_REAL_IMGUI_DRAW_6319DFAA);
    check(game_imgui_text_input_display_v1(h,COZY_TEXT_TEST_BRIDGE_BAD_N_C49EE42A,4)==0,COZY_TEXT_TEST_BRIDGE_DISPLAY_REJECTS_CONTROL_TEXT_BEFORE_DRAW_FB692B1E);
    game_imgui_end_canvas(h);game_imgui_render_present(h);
    check(game_imgui_text_input_enable_v1(h,0)==1&&game_imgui_text_input_status_v1(h)==0,COZY_TEXT_TEST_BRIDGE_DISABLE_FREES_AND_WIPES_INPUT_STORAGE_4A5B1377);
    int foreign[4]={-2,-2,-2,-2};
    std::thread other([&]{foreign[0]=game_imgui_new_frame(h,320,160,1.0f/60);foreign[1]=game_imgui_resize(h,320,160);foreign[2]=game_imgui_destroy(h);foreign[3]=game_imgui_last_error(h);game_imgui_mouse_button(h,0,1);});
    other.join();check(foreign[0]==0&&foreign[1]==0&&foreign[2]==0&&foreign[3]==-1,COZY_TEXT_TEST_BRIDGE_FOREIGN_THREAD_REJECTED_WITHOUT_DESTROYING_OWNER_457832DE);
    check(allocations>0,COZY_TEXT_TEST_BRIDGE_FOREIGN_DESTROY_RETAINS_OWNER_RESOURCES_FB3FFB03);
    reentry_handle=h;trigger_reentry=true;check(game_imgui_resize(h,320,160)==1&&reentry_result==0,COZY_TEXT_TEST_BRIDGE_CALLBACK_REENTRY_REJECTED_WITHOUT_DEADLOCK_327B7B3B);
    check(game_imgui_test_no_files(h)==1,COZY_TEXT_TEST_BRIDGE_INI_AND_LOG_DISABLED_DC1B0094);
    uint32_t gpu_words[8]={1,1,1,1,1,1,1,1};
    check(game_imgui_gpu_identity(h,gpu_words,sizeof(gpu_words))==0,COZY_TEXT_TEST_BRIDGE_PORTABLE_CORE_CANNOT_INVENT_A_GPU_IDENTITY_A630A4AD);
    for(unsigned i=0;i<8;++i)check(gpu_words[i]==0,COZY_TEXT_TEST_BRIDGE_UNAVAILABLE_GPU_IDENTITY_ZEROES_OUTPUT_57D52171);
    check(game_imgui_gpu_identity(h,gpu_words,31)==0,COZY_TEXT_TEST_BRIDGE_GPU_OUTPUT_ABI_SIZE_MISMATCH_REJECTED_060FCF35);
    GameImGuiHandle second=0;check(!game_imgui_create(reinterpret_cast<void*>(1),&host,&second)&&!second,COZY_TEXT_TEST_BRIDGE_SECOND_SINGLETON_CONTEXT_REJECTED_46264DC9);
    check(game_imgui_set_dpi(h,0)==0&&game_imgui_set_dpi(h,9)==0,COZY_TEXT_TEST_BRIDGE_DPI_INVALID_RANGE_REJECTED_A4F993A0);
    check(game_imgui_set_dpi(h,1.5f)==1,COZY_TEXT_TEST_BRIDGE_DPI_150_PERCENT_ACCEPTED_BEFORE_FRAME_3484796B);
    check(game_imgui_set_dpi(h,1.0f)==1,COZY_TEXT_TEST_BRIDGE_DPI_RESETS_WITHOUT_ACCUMULATING_STYLE_SCALING_45B0F3D1);
    frame(h);frame(h); // Allow initial keyboard-navigation focus to settle.
    game_imgui_mouse_pos(h,100,70);game_imgui_mouse_button(h,0,1);check(!frame(h),COZY_TEXT_TEST_BRIDGE_BUTTON_NOT_ACTIVATED_ON_MOUSE_DOWN_29303D98);
    game_imgui_mouse_button(h,0,0);check(frame(h),COZY_TEXT_TEST_BRIDGE_ACTUAL_IMGUI_CLICK_DELIVERED_ON_MOUSE_UP_221FE4BA);
    game_imgui_mouse_button(h,0,1);game_imgui_mouse_button(h,0,0);check(!frame(h),COZY_TEXT_TEST_BRIDGE_QUEUED_DOWN_UP_TRICKLE_DOWN_FIRST_8771A37C);check(frame(h),COZY_TEXT_TEST_BRIDGE_QUEUED_DOWN_UP_TRICKLE_UP_NEXT_FRAME_603E3860);
    game_imgui_mouse_button(h,0,1);check(!frame(h,false),COZY_TEXT_TEST_BRIDGE_DISABLED_BUTTON_DOWN_REJECTED_252DC908);game_imgui_mouse_button(h,0,0);check(!frame(h,false),COZY_TEXT_TEST_BRIDGE_DISABLED_BUTTON_UP_REJECTED_1C91931D);
    frame(h);game_imgui_mouse_button(h,0,1);frame(h);game_imgui_clear_input(h);game_imgui_focus(h,0);check(!frame(h),COZY_TEXT_TEST_BRIDGE_FOCUS_CANCELLATION_PREVENTS_ACTIVATION_9D6D3384);game_imgui_focus(h,1);frame(h);frame(h);
    game_imgui_key(h,0x0D,1);bool key_click=frame(h);game_imgui_key(h,0x0D,0);key_click=frame(h)||key_click;check(key_click,COZY_TEXT_TEST_BRIDGE_ENTER_ACTIVATES_REAL_DEFAULT_FOCUSED_BUTTON_9E0E770B);
    check(game_imgui_resize(h,640,320)==1,COZY_TEXT_TEST_BRIDGE_RESIZE_CONTRACT_OUTSIDE_FRAME_4A47B615);check(game_imgui_new_frame(h,320,160,0)==0,COZY_TEXT_TEST_BRIDGE_ZERO_DELTA_REJECTED_8E5386FB);
    check(game_imgui_new_frame(h,320,160,1.0f/60)==1,COZY_TEXT_TEST_BRIDGE_FRAME_BEGINS_BEFORE_SHUTDOWN_0D0414E3);check(game_imgui_set_dpi(h,2)==0,COZY_TEXT_TEST_BRIDGE_DPI_MUTATION_REJECTED_INSIDE_FRAME_EA223F86);game_imgui_begin_canvas(h);game_imgui_button(h,COZY_TEXT_TEST_BRIDGE_INJECTION_B9D51FDC,256,44,1);
    check(game_imgui_destroy(h)==1,COZY_TEXT_TEST_BRIDGE_OWNER_DESTROY_SUCCEEDS_B23796F8);check(allocations==0,COZY_TEXT_TEST_BRIDGE_SHUTDOWN_CLOSES_OPEN_CANVAS_AND_FREES_ALL_HOST_M_446920FA);
    check(game_imgui_destroy(h)==0,COZY_TEXT_TEST_BRIDGE_STALE_DESTROY_REJECTED_9E0C6281);check(allocations==0,COZY_TEXT_TEST_BRIDGE_REPEAT_DESTROY_HARMLESS_C8C5DFD5);GameImGuiHandle old=h;h=0;
    check(game_imgui_create(reinterpret_cast<void*>(1),&host,&h)==1,COZY_TEXT_TEST_BRIDGE_CONTEXT_RECREATES_AFTER_CLEAN_SHUTDOWN_08F60326);check(h!=old&&game_imgui_resize(old,320,160)==0&&game_imgui_destroy(old)==0,COZY_TEXT_TEST_BRIDGE_GENERATION_TOKEN_PREVENTS_STALE_HANDLE_REUSE_8DA5EBE8);frame(h);game_imgui_destroy(h);check(allocations==0,COZY_TEXT_TEST_BRIDGE_SECOND_LIFECYCLE_FREES_ALL_MEMORY_F4B75976);
    for(uint32_t code : {0x8007000Eu,0x887A0005u,0x887A0006u,0x887A0007u}) {
        h=0;check(game_imgui_create(reinterpret_cast<void*>(1),&host,&h)==1,COZY_TEXT_TEST_BRIDGE_FRESH_GPU_DIAGNOSTIC_LIFECYCLE_032902F9);
        check(game_imgui_test_gpu_error(h,static_cast<int32_t>(code))==1,COZY_TEXT_TEST_BRIDGE_INJECT_BACKEND_HRESULT_USING_PRODUCTION_RECORDER_414AF01A);
        game_imgui_test_gpu_error(h,0);game_imgui_test_gpu_error(h,static_cast<int32_t>(0x80004005u));
        check(game_imgui_last_error(h)==static_cast<int32_t>(code),COZY_TEXT_TEST_BRIDGE_FIRST_GPU_HRESULT_SURVIVES_SUCCESS_SECONDARY_CLE_16CC99E0);
        check(game_imgui_new_frame(h,320,160,1.0f/60)==0&&game_imgui_resize(h,320,160)==0,COZY_TEXT_TEST_BRIDGE_FAILED_BACKEND_CANNOT_START_ANOTHER_FRAME_OR_RES_1DEA8FAF);
        check(game_imgui_destroy(h)==1&&allocations==0,COZY_TEXT_TEST_BRIDGE_FAILED_BACKEND_IS_STILL_DESTRUCTIBLE_BY_ITS_UI_O_DA629A84);
    }
    fail_at_call=allocation_calls+2;h=0;
    check(game_imgui_create(reinterpret_cast<void*>(1),&host,&h)==GI_ERROR_HOST_ARENA&&!h&&allocations==0,COZY_TEXT_TEST_BRIDGE_RESERVATION_OOM_FREES_CONTEXT_BEFORE_ANY_IMGUI_C_DACE07B9);fail_at_call=0;
    check(game_imgui_create(reinterpret_cast<void*>(1),&host,&h)==1,COZY_TEXT_TEST_BRIDGE_RESERVED_HEAP_CONTEXT_21DDD97A);
    const int calls_after_create=allocation_calls;fail_next_allocation=true;
    for(int scale=48;scale<=768;scale+=12){check(game_imgui_set_dpi(h,scale/96.0f)==1,COZY_TEXT_TEST_BRIDGE_BOUNDED_DPI_SWEEP_0871E0C3);frame(h);}
    for(int i=0;i<2000;++i)game_imgui_mouse_pos(h,float(i%320),float(i%160));
    frame(h);check(allocation_calls==calls_after_create&&fail_next_allocation,COZY_TEXT_TEST_BRIDGE_LATE_HOST_HEAP_FAILURE_CANNOT_OCCUR_ON_IMGUI_STA_88AF4381);fail_next_allocation=false;
    for(int cycle=0;cycle<100;++cycle){
        for(int i=0;i<256;++i)game_imgui_mouse_button(h,0,i%2);
        check(game_imgui_test_queue_size()<=256,COZY_TEXT_TEST_BRIDGE_TRICKLED_BACKLOG_STAYS_BOUNDED_ACROSS_REPEATED_F_912F9C7A);
        check(game_imgui_new_frame(h,16384,16384,1.0f/60)==1,COZY_TEXT_TEST_BRIDGE_MAXIMUM_CANVAS_ADMISSION_26466CAB);game_imgui_begin_canvas(h);
        for(int item=0;item<8;++item){game_imgui_set_cursor_pos(h,32,float(52+item*50));game_imgui_text(h,COZY_TEXT_TEST_BRIDGE_ABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFGHIJKLMNOPQRSTUV_6FF38EF9);}
        game_imgui_text(h,COZY_TEXT_TEST_BRIDGE_OVER_BUDGET_IGNORED_C49AAD6D);game_imgui_end_canvas(h);game_imgui_render_present(h);
    }
    printf(COZY_TEXT_TEST_BRIDGE_MEASURED_BOUNDED_REAL_CORE_ARENA_PEAK_ZU_BYTES_N_81441A02,game_imgui_test_arena_peak());
    check(game_imgui_test_arena_peak()<16u*1024u*1024u,COZY_TEXT_TEST_BRIDGE_BOUNDED_REAL_CORE_PEAK_FITS_VALIDATED_RESERVATIO_F46D904C);
    void* pressure=game_imgui_test_arena_pressure(game_imgui_test_arena_largest()-1024);
    check(pressure!=0,COZY_TEXT_TEST_BRIDGE_FORCE_LOW_ARENA_ADMISSION_WITHOUT_INTERRUPTING_I_6610FDA0);
    check(game_imgui_new_frame(h,320,160,1.0f/60)==0&&game_imgui_last_error(h)==GI_ERROR_FRAME_RESERVE,COZY_TEXT_TEST_BRIDGE_RESERVE_EXHAUSTION_REFUSED_BEFORE_FRAME_MUTATION_0D72235D);
    game_imgui_test_arena_release(pressure);
    check(game_imgui_destroy(h)==1&&allocations==0,COZY_TEXT_TEST_BRIDGE_LOW_RESERVE_CONTEXT_CLOSES_SAFELY_A9CA4ADE);
    scene_contracts(host);
    license_contracts(host);liquid_scene_contracts(host);
    entitlement_title_contracts(host);
    seeded_public_api_sequences(host);
    printf(COZY_TEXT_TEST_BRIDGE_PASS_D_CORE_ABI_INPUT_OWNERSHIP_CHECKS_GPU_RENDE_EA6198E5,checks);return 0;
}
