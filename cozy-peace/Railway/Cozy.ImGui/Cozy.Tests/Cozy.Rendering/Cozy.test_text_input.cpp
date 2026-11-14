/* Cozy central native text imports. */
#include "../../Cozy.Strings/Cozy.Strings.Tests.h"
#line 1
/* Cozy central native text imports. */
#line 1
/* Cozy central native text imports. */
#line 1
/* Portable executable tests of the exact production input-state implementation.
   This is not a Windows IME/message delivery or GPU execution attestation. */
#include "../../Cozy.Bridge/Cozy.Core/Cozy.game_imgui_text_input.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
static unsigned checks=0;
static void check(bool value,const char* name){++checks;if(!value){fprintf(stderr,COZY_TEXT_TEST_TEXT_INPUT_FAIL_S_N_0A30451E,name);exit(1);}}
int main(){
    CozyTextInput state;char output[513];cozy_text_reset(&state,false);
    check(!cozy_text_event(&state,0,COZY_TEXT_TEST_TEXT_INPUT_A_14CE93E0,1),COZY_TEXT_TEST_TEXT_INPUT_UNFOCUSED_INPUT_REJECTED_C9F6BF61);
    check(cozy_text_read(&state,0,output,sizeof(output))==-1,COZY_TEXT_TEST_TEXT_INPUT_UNFOCUSED_READ_REJECTED_5B3E1B77);
    cozy_text_reset(&state,true);
    check(cozy_text_event(&state,2,0,0),COZY_TEXT_TEST_TEXT_INPUT_COMPOSITION_STARTS_EXPLICITLY_706BCA45);
    check(cozy_text_event(&state,1,COZY_TEXT_TEST_TEXT_INPUT_TEXT_87328713,3),COZY_TEXT_TEST_TEXT_INPUT_KOREAN_PREEDIT_ACCEPTED_6922B936);
    check(cozy_text_event(&state,1,COZY_TEXT_TEST_TEXT_INPUT_TEXT_59D90ED8,3),COZY_TEXT_TEST_TEXT_INPUT_PREEDIT_REPLACES_RATHER_THAN_APPENDS_BAF8BE55);
    check(cozy_text_read(&state,1,output,sizeof(output))==3&&!strcmp(output,COZY_TEXT_TEST_TEXT_INPUT_TEXT_59D90ED8),COZY_TEXT_TEST_TEXT_INPUT_PREEDIT_SNAPSHOT_EXACT_E21950F2);
    check(cozy_text_read(&state,0,output,sizeof(output))==0,COZY_TEXT_TEST_TEXT_INPUT_PREEDIT_IS_NEVER_COMMITTED_3E8B539A);
    check(cozy_text_event(&state,0,COZY_TEXT_TEST_TEXT_INPUT_TEXT_59D90ED8,3),COZY_TEXT_TEST_TEXT_INPUT_FINAL_KOREAN_COMMIT_ACCEPTED_0A763105);
    check(cozy_text_event(&state,3,0,0)&&!state.composing,COZY_TEXT_TEST_TEXT_INPUT_COMPOSITION_END_726DDC48);
    check(cozy_text_read(&state,0,output,sizeof(output))==3&&!strcmp(output,COZY_TEXT_TEST_TEXT_INPUT_TEXT_59D90ED8),COZY_TEXT_TEST_TEXT_INPUT_END_RETAINS_EXACT_COMMITTED_RESULT_ONCE_B403734B);
    check(cozy_text_read(&state,0,output,sizeof(output))==0,COZY_TEXT_TEST_TEXT_INPUT_COMMIT_READ_CONSUMES_45DCF713);
    check(cozy_text_read(&state,1,output,sizeof(output))==0,COZY_TEXT_TEST_TEXT_INPUT_COMMIT_WIPES_PREEDIT_B513DA3B);
    check(!cozy_text_event(&state,1,COZY_TEXT_TEST_TEXT_INPUT_TEXT_59D90ED8,3),COZY_TEXT_TEST_TEXT_INPUT_PREEDIT_WITHOUT_COMPOSITION_REJECTED_200E80CF);
    check(cozy_text_event(&state,2,0,0)&&cozy_text_event(&state,1,COZY_TEXT_TEST_TEXT_INPUT_TEXT_59D90ED8,3),COZY_TEXT_TEST_TEXT_INPUT_NEW_COMPOSITION_776B53C4);
    check(cozy_text_event(&state,4,0,0)&&!state.composing,COZY_TEXT_TEST_TEXT_INPUT_CANCEL_DROPS_PREEDIT_6218F9B7);
    check(cozy_text_read(&state,0,output,sizeof(output))==0,COZY_TEXT_TEST_TEXT_INPUT_CANCEL_NEVER_PROMOTES_PREEDIT_11CE1A85);
    const char* malformed[]={COZY_TEXT_TEST_TEXT_INPUT_XC0_XAF_4C5C04BE,COZY_TEXT_TEST_TEXT_INPUT_XE1_X80_3734657A,COZY_TEXT_TEST_TEXT_INPUT_XED_XA0_X80_09DB8BB4,COZY_TEXT_TEST_TEXT_INPUT_XF4_X90_X80_X80_F4EF33EB,COZY_TEXT_TEST_TEXT_INPUT_X80_32F36E21,COZY_TEXT_TEST_TEXT_INPUT_A_N_DF8575A0,COZY_TEXT_TEST_TEXT_INPUT_XEF_XBB_XBF_21FA8DE3};
    for(const char* p:malformed)check(!cozy_text_event(&state,0,p,static_cast<uint32_t>(strlen(p))),COZY_TEXT_TEST_TEXT_INPUT_MALFORMED_CONTROL_UTF8_REJECTED_A9B4F3FE);
    check(!cozy_text_event(&state,0,COZY_TEXT_TEST_TEXT_INPUT_A_0B_77ED824D,3),COZY_TEXT_TEST_TEXT_INPUT_EMBEDDED_NUL_REJECTED_8894CD73);
    check(cozy_text_utf16(&state,0xD800)&&state.high_surrogate==0xD800,COZY_TEXT_TEST_TEXT_INPUT_HIGH_SURROGATE_RETAINED_ONLY_UNTIL_NEXT_UNIT_1F40711B);
    check(!cozy_text_utf16(&state,'a')&&state.high_surrogate==0,COZY_TEXT_TEST_TEXT_INPUT_UNPAIRED_HIGH_REJECTED_WITHOUT_SUBSTITUTING_A_911A69A4);
    check(!cozy_text_utf16(&state,0xDC00),COZY_TEXT_TEST_TEXT_INPUT_UNPAIRED_LOW_REJECTED_B7828369);
    check(cozy_text_utf16(&state,0xD83D)&&!cozy_text_utf16(&state,0xDE00),COZY_TEXT_TEST_TEXT_INPUT_WELL_FORMED_SUPPLEMENTARY_CHARACTER_OUTSIDE_KORE_FA568C03);
    check(cozy_text_utf16(&state,0xD55C),COZY_TEXT_TEST_TEXT_INPUT_UTF16_KOREAN_COMMIT_AD9FE63A);
    check(cozy_text_read(&state,0,output,sizeof(output))==3&&!strcmp(output,COZY_TEXT_TEST_TEXT_INPUT_TEXT_59D90ED8),COZY_TEXT_TEST_TEXT_INPUT_UTF16_PRODUCES_EXACT_UTF8_0CC3DCD6);
    char full[513];memset(full,'x',512);full[512]=0;
    check(cozy_text_event(&state,0,full,512),COZY_TEXT_TEST_TEXT_INPUT_EXACT_BUFFER_BOUNDARY_ACCEPTED_36FC60F9);
    check(!cozy_text_event(&state,0,COZY_TEXT_TEST_TEXT_INPUT_Y_9797BB16,1)&&state.committed_bytes==512,COZY_TEXT_TEST_TEXT_INPUT_OVERFLOW_REJECTS_WHOLE_APPEND_896D35B4);
    check(cozy_text_read(&state,0,output,512)==-1&&state.committed_bytes==512,COZY_TEXT_TEST_TEXT_INPUT_SHORT_OUTPUT_DOES_NOT_CONSUME_DATA_BA38F1D7);
    check(cozy_text_read(&state,0,output,sizeof(output))==512&&!memcmp(full,output,513),COZY_TEXT_TEST_TEXT_INPUT_EXACT_BOUNDED_OUTPUT_E6A6D652);
    check(cozy_text_event(&state,0,COZY_TEXT_TEST_TEXT_INPUT_TEXT_672ACBE0,6)&&cozy_text_utf16(&state,0xD800),COZY_TEXT_TEST_TEXT_INPUT_PENDING_COMMIT_AND_SURROGATE_BEFORE_FOCUS_LOSS_F723D6E7);
    cozy_text_reset(&state,false);
    const unsigned char* bytes=reinterpret_cast<const unsigned char*>(&state);
    bool zero=true;for(size_t i=0;i<sizeof(state);++i)if(bytes[i])zero=false;
    check(zero,COZY_TEXT_TEST_TEXT_INPUT_FOCUS_LOSS_WIPES_ALL_STATE_INCLUDING_PADDING_B4757E77);
    // Every accepted single BMP scalar roundtrips under the documented alphabet.
    for(uint32_t cp=0;cp<=0xFFFF;++cp){
        cozy_text_reset(&state,true);bool ok=cozy_text_utf16(&state,cp);
        if(cp>=0xD800&&cp<=0xDBFF){check(ok&&state.committed_bytes==0,COZY_TEXT_TEST_TEXT_INPUT_HIGH_SURROGATE_NEVER_A_COMMIT_E7EE195D);continue;}
        check(ok==cozy_text_scalar(cp),COZY_TEXT_TEST_TEXT_INPUT_UTF16_EXACT_ALPHABET_EDBBD648);
        if(ok){uint32_t at=0,decoded=0;check(cozy_text_decode(state.committed,state.committed_bytes,at,decoded)&&at==state.committed_bytes&&decoded==cp,COZY_TEXT_TEST_TEXT_INPUT_SCALAR_ROUNDTRIP_7475D1D4);}
    }
    printf(COZY_TEXT_TEST_TEXT_INPUT_PASS_U_PRODUCTION_TEXT_INPUT_CONTRACTS_WINDOWS_I_141877CD,checks);
}
