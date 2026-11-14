/* Cozy central native text imports. */
#include "../../Cozy.Strings/Cozy.Strings.Bridge.h"
#line 1
/* Cozy central native text imports. */
#line 1
/* Bounded, separable Gaussian blur for the complete owned ImGui canvas.
   Two half-resolution GPU targets (at most 2048 x 2048 each), no CPU image
   copy, external resource or additional host/API callback. Foreground status
   is rendered after this pass and therefore stays sharp. */
#ifndef COZY_GAME_IMGUI_BLUR_H
#define COZY_GAME_IMGUI_BLUR_H
struct GameSceneBlurGpu {
    ID3D11Texture2D* textures[2];
    ID3D11RenderTargetView* targets[2];
    ID3D11ShaderResourceView* views[2];
    ID3D11VertexShader* vertex;
    ID3D11PixelShader* pixel;
    ID3D11SamplerState* sampler;
    ID3D11RasterizerState* rasterizer;
    ID3D11DepthStencilState* depth;
    ID3D11Buffer* constants;
    unsigned width,height;
};
static void game_blur_release_targets(GameSceneBlurGpu& b) {
    for(unsigned i=0;i<2;++i){
        if(b.views[i]){b.views[i]->Release();b.views[i]=0;}
        if(b.targets[i]){b.targets[i]->Release();b.targets[i]=0;}
        if(b.textures[i]){b.textures[i]->Release();b.textures[i]=0;}}
    b.width=b.height=0;
}
static void game_blur_release(GameSceneBlurGpu& b) {
    game_blur_release_targets(b);
    if(b.vertex){b.vertex->Release();b.vertex=0;}
    if(b.pixel){b.pixel->Release();b.pixel=0;}
    if(b.sampler){b.sampler->Release();b.sampler=0;}
    if(b.rasterizer){b.rasterizer->Release();b.rasterizer=0;}
    if(b.depth){b.depth->Release();b.depth=0;}
    if(b.constants){b.constants->Release();b.constants=0;}
}
static HRESULT game_blur_prepare(GameSceneBlurGpu& b,ID3D11Device* device,unsigned width,unsigned height) {
    if(!device||!width||!height)return E_INVALIDARG;
    HRESULT hr=S_OK;
    if(!b.vertex){
        static const char shader[]=
            COZY_TEXT_GAME_IMGUI_BLUR_TEXTURE2D_IMAGE_REGISTER_T0_SAMPLERSTATE_LINEAR__36FF2330
            COZY_TEXT_GAME_IMGUI_BLUR_CBUFFER_PARAMETERS_REGISTER_B0_FLOAT2_STEP_UV_FL_EBDF6E97
            COZY_TEXT_GAME_IMGUI_BLUR_STRUCT_OUT_FLOAT4_POSITION_SV_POSITION_FLOAT2_UV_E8415B30
            COZY_TEXT_GAME_IMGUI_BLUR_OUT_VS_UINT_ID_SV_VERTEXID_OUT_O_FLOAT2_UV_FLOAT_DDF8F605
            COZY_TEXT_GAME_IMGUI_BLUR_O_UV_UV_O_POSITION_FLOAT4_UV_FLOAT2_2_2_FLOAT2_1_8BDD0C48
            COZY_TEXT_GAME_IMGUI_BLUR_FLOAT4_PS_OUT_I_SV_TARGET_FLOAT4_C_IMAGE_SAMPLE__E610A091
            COZY_TEXT_GAME_IMGUI_BLUR_C_IMAGE_SAMPLE_LINEAR_CLAMP_I_UV_STEP_UV_IMAGE_S_E89FE626
            COZY_TEXT_GAME_IMGUI_BLUR_C_IMAGE_SAMPLE_LINEAR_CLAMP_I_UV_STEP_UV_2_IMAGE_6CAEEF10
            COZY_TEXT_GAME_IMGUI_BLUR_C_IMAGE_SAMPLE_LINEAR_CLAMP_I_UV_STEP_UV_3_IMAGE_72FCF534
            COZY_TEXT_GAME_IMGUI_BLUR_C_IMAGE_SAMPLE_LINEAR_CLAMP_I_UV_STEP_UV_4_IMAGE_4CCAE707;
        ID3DBlob* code=0;ID3DBlob* errors=0;
        hr=game_d3d_compile(shader,sizeof(shader)-1,0,0,0,COZY_TEXT_GAME_IMGUI_BLUR_VS_CD707950,COZY_TEXT_GAME_IMGUI_BLUR_VS_4_0_6663D4C8,D3DCOMPILE_OPTIMIZATION_LEVEL3,0,&code,&errors);
        if(errors){errors->Release();errors=0;}
        if(SUCCEEDED(hr)&&code)hr=device->CreateVertexShader(code->GetBufferPointer(),code->GetBufferSize(),0,&b.vertex);
        if(code){code->Release();code=0;}
        if(SUCCEEDED(hr))hr=game_d3d_compile(shader,sizeof(shader)-1,0,0,0,COZY_TEXT_GAME_IMGUI_BLUR_PS_CB4D0610,COZY_TEXT_GAME_IMGUI_BLUR_PS_4_0_4ADF516C,D3DCOMPILE_OPTIMIZATION_LEVEL3,0,&code,&errors);
        if(errors){errors->Release();errors=0;}
        if(SUCCEEDED(hr)&&code)hr=device->CreatePixelShader(code->GetBufferPointer(),code->GetBufferSize(),0,&b.pixel);
        if(code){code->Release();code=0;}
        D3D11_SAMPLER_DESC sample={};sample.Filter=D3D11_FILTER_MIN_MAG_MIP_LINEAR;
        sample.AddressU=sample.AddressV=sample.AddressW=D3D11_TEXTURE_ADDRESS_CLAMP;sample.MaxLOD=D3D11_FLOAT32_MAX;
        if(SUCCEEDED(hr))hr=device->CreateSamplerState(&sample,&b.sampler);
        D3D11_RASTERIZER_DESC raster={};raster.FillMode=D3D11_FILL_SOLID;raster.CullMode=D3D11_CULL_NONE;raster.DepthClipEnable=TRUE;
        if(SUCCEEDED(hr))hr=device->CreateRasterizerState(&raster,&b.rasterizer);
        D3D11_DEPTH_STENCIL_DESC depth={};depth.DepthEnable=FALSE;depth.StencilEnable=FALSE;
        if(SUCCEEDED(hr))hr=device->CreateDepthStencilState(&depth,&b.depth);
        D3D11_BUFFER_DESC buffer={};buffer.ByteWidth=16;buffer.Usage=D3D11_USAGE_DEFAULT;buffer.BindFlags=D3D11_BIND_CONSTANT_BUFFER;
        if(SUCCEEDED(hr))hr=device->CreateBuffer(&buffer,0,&b.constants);
        if(FAILED(hr)||!b.vertex||!b.pixel||!b.sampler||!b.rasterizer||!b.depth||!b.constants){game_blur_release(b);return FAILED(hr)?hr:E_FAIL;}
    }
    const unsigned w=ImMin(2048u,ImMax(1u,(width+1)/2)),h=ImMin(2048u,ImMax(1u,(height+1)/2));
    if(b.width==w&&b.height==h)return S_OK;
    game_blur_release_targets(b);
    D3D11_TEXTURE2D_DESC desc={};desc.Width=w;desc.Height=h;desc.MipLevels=1;desc.ArraySize=1;
    desc.Format=DXGI_FORMAT_B8G8R8A8_UNORM;desc.SampleDesc.Count=1;desc.Usage=D3D11_USAGE_DEFAULT;
    desc.BindFlags=D3D11_BIND_RENDER_TARGET|D3D11_BIND_SHADER_RESOURCE;
    for(unsigned i=0;i<2&&SUCCEEDED(hr);++i){
        hr=device->CreateTexture2D(&desc,0,&b.textures[i]);
        if(SUCCEEDED(hr))hr=device->CreateRenderTargetView(b.textures[i],0,&b.targets[i]);
        if(SUCCEEDED(hr))hr=device->CreateShaderResourceView(b.textures[i],0,&b.views[i]);}
    if(FAILED(hr)){game_blur_release_targets(b);return hr;}
    b.width=w;b.height=h;return S_OK;
}
static void game_blur_pass(GameSceneBlurGpu& b,ID3D11DeviceContext* context,
 ID3D11ShaderResourceView* source,ID3D11RenderTargetView* target,unsigned width,unsigned height,float dx,float dy) {
    ID3D11ShaderResourceView* empty=0;context->PSSetShaderResources(0,1,&empty);
    context->OMSetRenderTargets(1,&target,0);
    const float parameters[4]={dx,dy,0,0};context->UpdateSubresource(b.constants,0,0,parameters,0,0);
    D3D11_VIEWPORT viewport={};viewport.Width=static_cast<float>(width);viewport.Height=static_cast<float>(height);viewport.MaxDepth=1;
    context->RSSetViewports(1,&viewport);context->RSSetState(b.rasterizer);
    context->IASetInputLayout(0);context->IASetPrimitiveTopology(D3D11_PRIMITIVE_TOPOLOGY_TRIANGLELIST);
    context->VSSetShader(b.vertex,0,0);context->PSSetShader(b.pixel,0,0);context->GSSetShader(0,0,0);
    context->HSSetShader(0,0,0);context->DSSetShader(0,0,0);
    context->PSSetConstantBuffers(0,1,&b.constants);context->PSSetSamplers(0,1,&b.sampler);
    context->PSSetShaderResources(0,1,&source);context->OMSetBlendState(0,0,0xffffffffu);context->OMSetDepthStencilState(b.depth,0);
    context->Draw(3,0);context->PSSetShaderResources(0,1,&empty);
}
#endif
