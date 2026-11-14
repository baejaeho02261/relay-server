#!/usr/bin/env python3
"""Rebuild losslessly QOI-packed RGBA8 portraits and frosted-image derivatives.

Normal RAD Studio builds use the checked-in headers and do not need Python.
After replacing a source PNG, run this optional tool with Pillow installed.
Each generated translation-unit include remains below the source-size guard.
"""
from pathlib import Path
import argparse,hashlib,struct,sys

ROOT=Path(__file__).resolve().parent.parent
NAMES=('PUBG','TalesRunner','LostSaga','Apex','Overwatch','CounterStrike',
       'BattlEye','XIGNCODE3','EasyAntiCheat','Vanguard','RICOCHET','ACE',
       'Roblox','BrawlStars','PUBGMobile','GenshinImpact','PokemonGO','ClashRoyale')
WIDTH,HEIGHT=512,768
BLUR_WIDTH,BLUR_HEIGHT=128,192
BLUR_RADIUS=5.0


def encode_qoi(payload,width,height):
    """QOI v1 RGBA/sRGB stream; preserve all four source bytes exactly."""
    if len(payload)!=width*height*4:raise ValueError('SCENE_QOI_RGBA_SIZE')
    output=bytearray(b'qoif'+struct.pack('>IIBB',width,height,4,0))
    index=[(0,0,0,0)]*64;previous=(0,0,0,255);run=0
    for at in range(0,len(payload),4):
        pixel=tuple(payload[at:at+4])
        if pixel==previous:
            run+=1
            if run==62 or at+4==len(payload):output.append(0xc0|(run-1));run=0
            continue
        if run:output.append(0xc0|(run-1));run=0
        r,g,b,a=pixel;slot=(r*3+g*5+b*7+a*11)%64
        if index[slot]==pixel:output.append(slot)
        else:
            index[slot]=pixel
            if a!=previous[3]:output.extend((0xff,r,g,b,a))
            else:
                dr,dg,db=(((pixel[i]-previous[i]+128)%256)-128 for i in range(3))
                dr_dg,db_dg=dr-dg,db-dg
                if -2<=dr<=1 and -2<=dg<=1 and -2<=db<=1:
                    output.append(0x40|((dr+2)<<4)|((dg+2)<<2)|(db+2))
                elif -32<=dg<=31 and -8<=dr_dg<=7 and -8<=db_dg<=7:
                    output.extend((0x80|(dg+32),((dr_dg+8)<<4)|(db_dg+8)))
                else:output.extend((0xfe,r,g,b))
        previous=pixel
    output.extend(b'\x00\x00\x00\x00\x00\x00\x00\x01')
    return bytes(output)

def packed_header(index,payload,blur=False):
    kind='BLUR' if blur else 'ART';symbol='Blur' if blur else 'Image'
    guard=f'COZY_GAME_IMGUI_SCENE_{kind}{index}_H'
    lines=[f'/* Generated lossless QOI v1 {symbol.lower()} {index}; decoded pixels remain RGBA8. */',
           f'#ifndef {guard}',f'#define {guard}',f'static const unsigned char GameScene{symbol}{index}[]={{']
    lines.extend(','.join(f'0x{value:02x}' for value in payload[start:start+24])+',' for start in range(0,len(payload),24))
    return ('\n'.join(lines+['};','#endif',''])).encode('utf8')

def generated_headers():
    try:
        from PIL import Image,ImageOps,ImageFilter
    except ImportError:
        raise ValueError('SCENE_ASSET_GENERATION_REQUIRES_PILLOW: install Pillow in your development Python environment')
    lines=['/* Generated lossless QOI v1 artwork; decoded immutable RGBA8 pixels. Source PNGs and provenance live in Cozy.Assets/Cozy.Cards. */',
           '#ifndef COZY_GAME_IMGUI_SCENE_ASSETS_H','#define COZY_GAME_IMGUI_SCENE_ASSETS_H',
           f'static const unsigned GameSceneImageWidth={WIDTH},GameSceneImageHeight={HEIGHT};',
           f'static const unsigned GameSceneImageCount={len(NAMES)};',
           f'static const unsigned GameSceneBlurWidth={BLUR_WIDTH},GameSceneBlurHeight={BLUR_HEIGHT};']
    output={}
    for index,name in enumerate(NAMES):
        source=ROOT/'Cozy.Assets/Cozy.Cards'/f'Cozy.Card-{name}.png'
        with Image.open(source) as image:
            if image.format!='PNG' or image.width<1 or image.height<1 or image.width>4096 or image.height>4096:
                raise ValueError('SCENE_ARTWORK_PNG_INVALID: '+name)
            rgba=ImageOps.fit(image.convert('RGBA'),(WIDTH,HEIGHT),method=Image.Resampling.LANCZOS)
            payload=rgba.tobytes()
            # Actual spatial blur is baked once, never recomputed during a frame.
            blurred=rgba.resize((BLUR_WIDTH,BLUR_HEIGHT),Image.Resampling.LANCZOS).filter(ImageFilter.GaussianBlur(BLUR_RADIUS))
            blur_payload=blurred.tobytes()
        lines.append(f'/* source-sha256-{index}: {hashlib.sha256(source.read_bytes()).hexdigest()} */')
        lines.append(f'/* rgba8-sha256-{index}: {hashlib.sha256(payload).hexdigest()} */')
        lines.append(f'/* blur8-sha256-{index}: {hashlib.sha256(blur_payload).hexdigest()} */')
        packed=encode_qoi(payload,WIDTH,HEIGHT);blur_packed=encode_qoi(blur_payload,BLUR_WIDTH,BLUR_HEIGHT)
        lines.append(f'/* qoi-sha256-{index}: {hashlib.sha256(packed).hexdigest()} */')
        lines.append(f'/* blur-qoi-sha256-{index}: {hashlib.sha256(blur_packed).hexdigest()} */')
        file=f'Cozy.game_imgui_scene_art{index}.h';lines.append(f'#include "{file}"')
        output[file]=packed_header(index,packed)
        blur_file=f'Cozy.game_imgui_scene_blur{index}.h';lines.append(f'#include "{blur_file}"')
        output[blur_file]=packed_header(index,blur_packed,True)
    output['Cozy.game_imgui_scene_assets.h']=('\n'.join(lines+['#endif'])+'\n').encode('utf8')
    return output

def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--check',action='store_true');args=parser.parse_args()
    target=ROOT/'Cozy.Bridge/Cozy.Core'
    try:
        for name,output in generated_headers().items():
            file=target/name
            if args.check:
                if file.read_bytes()!=output:raise ValueError('SCENE_ASSET_HEADER_STALE: regenerate the scene artwork headers')
            else:file.write_bytes(output)
        print('SCENE ASSETS '+('CHECK' if args.check else 'GENERATED')+f' PASS: {len(NAMES)} immutable portraits 512x768 and {len(NAMES)} bounded frosted textures 128x192 RGBA8')
        return 0
    except (OSError,ValueError) as error:
        print(str(error),file=sys.stderr);return 1

if __name__=='__main__':raise SystemExit(main())
