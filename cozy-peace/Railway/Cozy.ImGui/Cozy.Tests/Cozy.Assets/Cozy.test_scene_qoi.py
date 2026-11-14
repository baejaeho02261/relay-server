#!/usr/bin/env python3
"""Compile the native bounded decoder and verify every original RGBA8 manifest hash.
Run with --sanitize to include AddressSanitizer and UndefinedBehaviorSanitizer.
Only development tests need Python/a C++ compiler; normal builds do not.
"""
import argparse,hashlib,json,os,re,subprocess,tempfile
from pathlib import Path

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--sanitize',action='store_true')
    parser.add_argument('--compiler',default=os.environ.get('CXX','g++'))
    args=parser.parse_args()
    here=Path(__file__).resolve().parent
    manifest=(here/'../../Cozy.Bridge/Cozy.Core/Cozy.game_imgui_scene_assets.h').resolve().read_text()
    image_count=int(re.search(r'GameSceneImageCount=(\d+);',manifest).group(1))
    if image_count!=18:raise ValueError('SCENE_CATALOG_REQUIRES_18_IMAGES')
    with tempfile.TemporaryDirectory(prefix='cozy-qoi-test-') as directory:
        temporary=Path(directory);binary=temporary/'scene-qoi-test'
        command=[args.compiler,'-std=c++11','-O1','-g','-Wall','-Wextra','-Werror']
        if args.sanitize:command+=['-fsanitize=address,undefined','-fno-omit-frame-pointer','-fno-pie','-no-pie']
        command+=[str(here/'Cozy.test_scene_qoi.cpp'),'-o',str(binary)]
        subprocess.run(command,check=True)
        subprocess.run([str(binary),str(temporary)],check=True)
        records=[]
        for index in range(image_count):
            for kind,tag in [('art','rgba8'),('blur','blur8')]:
                payload=(temporary/f'{kind}{index}.rgba').read_bytes()
                digest=hashlib.sha256(payload).hexdigest()
                expected=re.search(r'/\* '+tag+'-sha256-'+str(index)+r': ([a-f0-9]{64}) \*/',manifest).group(1)
                if digest!=expected:raise ValueError(f'RGBA8_DECODE_MISMATCH: {kind}{index}')
                records.append(dict(asset=f'{kind}{index}',bytes=len(payload),sha256=digest))
        print(json.dumps(dict(status='PASS',sanitizers=args.sanitize,assets=len(records),decodedBytes=sum(item['bytes'] for item in records))))
    return 0
if __name__=='__main__':raise SystemExit(main())
