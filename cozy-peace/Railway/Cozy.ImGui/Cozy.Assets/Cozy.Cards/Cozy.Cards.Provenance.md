# Cozy game and security-information card artwork

Six distinct game artworks were retrieved from public publisher-controlled assets on 2026-11-03 (Asia/Seoul). Four are Steam publisher library capsules. TalesRunner uses an official character illustration; Lost Saga uses an official wallpaper. These are game artwork selections, not a claim that every image is the newest box cover.

The original source JPEGs were losslessly decoded to RGB pixels and saved as the initial PNGs. The later in-cover-title revision below replaces TalesRunner and LostSaga with AI-edited portrait compositions derived from those artworks; the other four game PNGs remain byte-identical. Original source hashes and retrieval records below are retained as historical provenance, not a claim that the edited PNG is the original publisher file. `Cozy.Generate-SceneAssets.py` performs an aspect-preserving center crop and Lanczos resize to 512×768 RGBA8; the title revision supplies portrait compositions for the two originally landscape references. The UI adds no caption or title beneath the cards.

Artwork and trademarks remain the property of their respective rights holders. Public availability is not a grant of general redistribution rights. No sponsorship, endorsement, game integration, or permission to redistribute is asserted by this asset inventory.

## Runtime budget

Eighteen normal textures contain 393,216 pixels / 1,572,864 bytes each. Eighteen frosted derivatives contain 24,576 pixels / 98,304 bytes each. Together they occupy 30,081,024 bytes (28.6875 MiB), excluding driver bookkeeping. Decoding still reuses one 1,572,864-byte scratch buffer; the Mobile catalog adds six normal/blur pairs without expanding the bounded font arena. Textures are immutable, outside the bounded font arena, and do not download content at runtime. The image assets do not require a new operating-system API or bridge export.

Frosted derivatives are real spatial blurs: the exact normalized 512×768 image is Lanczos-downsampled to 128×192 and Gaussian-blurred with radius 5. The generator records separate source, normal-pixel and blurred-pixel SHA-256 digests. No full-size frame blur, GPU readback or per-frame image allocation is required by these card assets.

## Sources

### 0 · Cozy.Card-PUBG.png

- Game: PUBG: BATTLEGROUNDS
- Kind: Steam publisher library capsule
- Rights holder: KRAFTON / PUBG Corporation
- Publisher page: https://store.steampowered.com/app/578080/
- Retrieved asset: https://cdn.akamai.steamstatic.com/steam/apps/578080/library_600x900_2x.jpg
- Source dimensions: 600×900
- Downloaded JPEG SHA-256: `bb6dcbc2d4dce34d4eeb790b907b66524b11d8077043cba38d25512c9821f6c1`
- Checked-in PNG SHA-256: `3f18e9d6748c3fd4aa49741109eedde0d6d74c16ed0107ce9933d04596dde89e`

### 1 · Cozy.Card-TalesRunner.png

- Game: 테일즈런너 / TalesRunner
- Kind: Official Harang character illustration from Smilegate Newsroom
- Rights holder: RHAON Entertainment / Smilegate
- Publisher page: https://newsroom.smilegate.com/main/multigallery_talesrunner.html
- Retrieved asset: https://newsroom.smilegate.com/s3/multi/%ED%95%98%EB%9E%91.jpg
- Source dimensions: 4034×2270
- Downloaded JPEG SHA-256: `a74f5fe05a5dc0a41c7dfe0306a52348234d0536c4796b6ef6e1830d2e7fa902`
- Checked-in PNG SHA-256: `8a5c779813116b29e1c7960ae87f3b05aee3f8b7c0b4c071b664e26d12176cc5`

### 2 · Cozy.Card-LostSaga.png

- Game: 로스트사가 / Lost Saga
- Kind: Official Camping wallpaper
- Rights holder: IO Entertainment / VALOFE
- Publisher page: https://lostsaga.hangame.com/guide/wallpaper.asp
- Retrieved asset: https://lostsagakr-cdn-image.valofe.com/2014_grand/wallpaper/20160817_camping_1920x1200.jpg
- Source dimensions: 1920×1200
- Downloaded JPEG SHA-256: `84c855cc854368d6193c04a8e5ee9854111bf156000b996990f39592a74cf4dc`
- Checked-in PNG SHA-256: `783d18e793b55ecf5a409caa1de8134216ee2ec5b69c77629c9887bf0f3fa867`

### 3 · Cozy.Card-Apex.png

- Game: Apex Legends
- Kind: Steam publisher library capsule
- Rights holder: Electronic Arts / Respawn Entertainment
- Publisher page: https://store.steampowered.com/app/1172470/
- Retrieved asset: https://cdn.akamai.steamstatic.com/steam/apps/1172470/library_600x900_2x.jpg
- Source dimensions: 600×900
- Downloaded JPEG SHA-256: `46cb3e9fa8e3a0188175dc005e122221db12424a7b64f98a452a198e8e0be8e9`
- Checked-in PNG SHA-256: `fbc698953b601f31704117bbbc9b5bb7d43cc747612e4ed3ead278498ef7c04f`

### 4 · Cozy.Card-Overwatch.png

- Game: Overwatch
- Kind: Steam publisher library capsule
- Rights holder: Blizzard Entertainment
- Publisher page: https://store.steampowered.com/app/2357570/
- Retrieved asset: https://cdn.akamai.steamstatic.com/steam/apps/2357570/library_600x900_2x.jpg
- Source dimensions: 600×900
- Downloaded JPEG SHA-256: `cbd79c1e522db77025640306d311216a495e23f03902d16493625b2bbd4c9834`
- Checked-in PNG SHA-256: `765b3aa0f68927cb5adabed84b5243ecc5697fa81aa015f4d5fa2e37f99c1bd1`

### 5 · Cozy.Card-CounterStrike.png

- Game: Counter-Strike 2
- Kind: Steam publisher library capsule
- Rights holder: Valve Corporation
- Publisher page: https://store.steampowered.com/app/730/
- Retrieved asset: https://cdn.akamai.steamstatic.com/steam/apps/730/library_600x900_2x.jpg
- Source dimensions: 600×900
- Downloaded JPEG SHA-256: `97b3d55cef58f6602dbfb1470cd8089100fdd1f7bb40bd32b2424382eb405d8b`
- Checked-in PNG SHA-256: `b76831c76caf11b2f1a35d3bc30ddecc17435d2be70a906e47db13b882c459f0`

## Security information card compositions · 2026-11-03

Indices 6–11 are static product-information cards in the Spoofer presentation tab. They do not claim integration, compatibility, detection results, bypass support, or a running security operation. The card compositions combine the actual official brand mark with a deterministic dark gradient and subtle geometric backdrop. These compositions are application UI assets, not official vendor posters. The initial six game assets used the published artwork selections described above. See the later in-cover-title revision for edits to indices 1 and 2.

SVG marks were rasterized at 900-pixel width; transparent image bounds were trimmed without altering the mark. XIGNCODE3 uses the vendor-provided product wordmark hosted on KOCCA WelCon, cropped to its red wordmark band. RICOCHET preserves the black background of the official hero artwork. The checked-in composed PNGs are the complete sources for the normal and frosted generated headers.

### 6 · Cozy.Card-BattlEye.png

- Product: BattlEye
- Source page: https://www.battleye.com/
- Retrieved mark: https://www.battleye.com/wp-content/themes/battleye/images/logo-large.png
- Retrieved source SHA-256: `0c5f7b127d13ddac2e142bd3615f87bd2157eba16ca9fad948400685b6561cd0`
- Composition SHA-256: `59bf328055f9743de499f649c1adeb789f4e5cac34543ffb82f580d4ec2dd04c`
- Composition dimensions: 512×768 RGB PNG

### 7 · Cozy.Card-XIGNCODE3.png

- Product: XIGNCODE3
- Source page: https://welcon.kocca.kr/emp/product/xigncode3--1583---en
- Retrieved mark: https://welcon.kocca.kr/emp/cmm/getImage.do?atchFileId=FILE_7a3e26ea-1d3a-4f0a-b1c9-52dec2e4d1e2&fileSn=1
- Retrieved source SHA-256: `fa862b9d354c08177162dd7fc131fe80ad78e96a3219aa931607af9be8f77583`
- Composition SHA-256: `82dddd0247d5a3cf6d6fe9ac9d8b77581e6468e76610e9b701f1c98cc8d963e6`
- Composition dimensions: 512×768 RGB PNG

### 8 · Cozy.Card-EasyAntiCheat.png

- Product: Easy Anti-Cheat
- Source page: https://www.easy.ac/
- Retrieved mark: https://cms-assets.unrealengine.com/ADJUngP4LRSSXxtIH9SDJz/cmq5fkk3o0mkp07odj40qnxde
- Retrieved source SHA-256: `bda41e3329ab7b2e95c1edc28790d86aacf019e0120908c84b5e8baaa4386691`
- Composition SHA-256: `fb982477c767a57910f586b52f765899517fda833889f46cd81ba9e986dca6bd`
- Composition dimensions: 512×768 RGB PNG

### 9 · Cozy.Card-Vanguard.png

- Product: Riot Vanguard
- Source page: https://www.riotgames.com/en/news/vanguard-on-demand
- Retrieved mark: https://www.riotgames.com/darkroom/390/f32bf076f5f8c93d608867d8faf891ed:ea4ed48eae58a1ed31baffe93d975bc9/vg-red-cropped.png
- Retrieved source SHA-256: `029dd85053371ed97c2c998ffa60ce2df32dac5fd1b6a133b2e8052cbcae4d27`
- Composition SHA-256: `3fcec8e63b2f4053204d87f9ef2858ea1d6174475063af4670cccbb6362a9fb2`
- Composition dimensions: 512×768 RGB PNG

### 10 · Cozy.Card-RICOCHET.png

- Product: RICOCHET Anti-Cheat
- Source page: https://www.callofduty.com/ricochet
- Retrieved mark: https://www.callofduty.com/content/dam/atvi/callofduty/cod-touchui/global/ricochet/COD_Ricochet_Hero.webp
- Retrieved source SHA-256: `3322cb4d5673a43c6eec0191007582bda7301052d1631a2481ceee3188e3373f`
- Composition SHA-256: `6578446e5b73d85adb006a353cd8bfdac30a03b3f587117d11e777cf6bbe234b`
- Composition dimensions: 512×768 RGB PNG

### 11 · Cozy.Card-ACE.png

- Product: Anti-Cheat Expert
- Source page: https://intl.anticheatexpert.com/
- Retrieved mark: https://down.anticheatexpert.com/static/iegssibox/ace-intl-web/cloud_100260_oper/2611021620/img/ace-logo.57ed761.svg
- Retrieved source SHA-256: `8570955c8cc615d0f3480acf26737bad0f36b8bc2feabaaae9a6f8f83a167bd1`
- Composition SHA-256: `59876f7431c6dc8bf5962f5bccc31cd9370780e1118e77d4a3077e8490d79523`
- Composition dimensions: 512×768 RGB PNG


## Fixed information text and accent palette

The following short descriptions are paraphrases of official product pages. Accent values are visual design choices based on the selected artwork and marks, not claims of canonical brand color specifications.

| Index | Card | Text line 1 | Text line 2 | Accent RGB | Official source |
| :-- | :-- | :-- | :-- | :-- | :-- |
| 0 | PUBG | 최후의 생존자를 가리는 전장 | 파밍과 전술이 만나는 배틀로얄 | 236,176,74 | https://www.pubg.com/en/game-info/overview |
| 1 | TalesRunner | 동화나라를 달리는 모험 | 라온의 캐주얼 어드벤처 레이싱 | 92,189,246 | https://www.rhaone.com/page/sub02_1 |
| 2 | Lost Saga | 자신만의 용병단으로 팀 전투 | 다양한 영웅을 교체하는 대전 액션 | 154,103,218 | https://lostsaga.hangame.com/guide/introduce.asp |
| 3 | Apex Legends | 고유한 능력의 레전드와 팀 플레이 | 리스폰의 히어로 배틀로얄 | 216,71,75 | https://www.ea.com/games/apex-legends/apex-legends / https://news.ea.com/press-releases/press-releases-details/2019/Respawn-Launches-Apex-Legends-a-Free-to-Play-Battle-Royale-Experience-Available-Now-on-PC-PS4-and-Xbox-One/default.aspx |
| 4 | Overwatch | 개성 있는 영웅이 펼치는 팀 액션 | 블리자드의 팀 기반 액션 게임 | 248,160,61 | https://overwatch.blizzard.com/ / https://www.blizzard.com/en-us/games |
| 5 | Counter-Strike 2 | 팀 전술과 정밀한 사격의 승부 | 밸브의 경쟁형 FPS | 232,144,53 | https://www.counter-strike.net/ / https://store.steampowered.com/app/730/CounterStrike_2/ |
| 6 | BattlEye | 온라인 게임을 위한 안티치트 | 게임의 부정행위를 탐지·방지 | 224,188,28 | https://www.battleye.com/ |
| 7 | XIGNCODE3 | 웰비아의 게임 보안 솔루션 | 온라인 플레이의 공정성을 보호 | 239,44,58 | https://www.wellbia.com/?action=SiteComp&module=Html&sSubNo=4 |
| 8 | Easy Anti-Cheat | 에픽게임즈의 안티치트 서비스 | 게임 속 공정한 플레이를 지원 | 35,161,221 | https://www.easy.ac/ai-info?lang=ko / https://www.easy.ac/services?lang=ko |
| 9 | Riot Vanguard | 라이엇게임즈의 보안 소프트웨어 | 라이엇 게임의 공정한 경쟁 지원 | 255,71,87 | https://support.riotgames.com/en-us/riot/performance/what-is-vanguard / https://www.riotgames.com/en/news/vanguard-on-demand |
| 10 | RICOCHET | 콜 오브 듀티의 안티치트 체계 | 클라이언트·서버 보안을 함께 사용 | 111,184,201 | https://www.callofduty.com/ricochet |
| 11 | ACE | 게임 보안을 위한 통합 솔루션 | PC·모바일 부정행위 방지 지원 | 73,137,248 | https://intl.anticheatexpert.com/ko/ |

## In-cover titles · 2026-11-03 follow-up

The UI caption/footer band was removed. Only four covers whose portrait composition lacked a visible name were edited with the built-in image-generation edit tool: TalesRunner, Lost Saga, BattlEye and Vanguard. The existing character/scene/brand references and palette were supplied as edit targets; title typography is part of the poster pixels, with no footer box or caption strip. These are AI-edited application display compositions, not newly published official game covers or official vendor wordmarks. Generative edits may also change fine illustration details; they are not pixel-identical text-only edits. The original source attribution and hashes above remain the provenance of the references. The other eight PNGs were verified byte-identical to the prior source package.

The four edited source PNGs are 1024×1536. The normal and spatially blurred runtime textures are regenerated using the existing bounded pipeline; runtime dimensions, texture count, API slots and public bridge exports remain unchanged.

| Asset | Visible in-image title | Original PNG SHA-256 | Edited PNG SHA-256 |
| --- | --- | --- | --- |
| Cozy.Card-TalesRunner.png | TALESRUNNER | `8a5c779813116b29e1c7960ae87f3b05aee3f8b7c0b4c071b664e26d12176cc5` | `42b448974468c3a4ee506136618c0c03a545cc9b6508730e71d0d1b49b94f387` |
| Cozy.Card-LostSaga.png | LOST SAGA | `783d18e793b55ecf5a409caa1de8134216ee2ec5b69c77629c9887bf0f3fa867` | `54f5f2995a65ac4a057581f9e3992c594ea267a083981220d42de2f38af2414f` |
| Cozy.Card-BattlEye.png | BattlEye | `59bf328055f9743de499f649c1adeb789f4e5cac34543ffb82f580d4ec2dd04c` | `38275e9fc35ced437ce3ba76636a6ed4bbdf65a15a77d2c0e8675340012dea72` |
| Cozy.Card-Vanguard.png | VANGUARD | `3fcec8e63b2f4053204d87f9ef2858ea1d6174475063af4670cccbb6362a9fb2` | `fc905f78dd8a771079988e006b8213fc38503c389c39cc7abe9984553952d554` |

### Edit prompt specifications

- **TalesRunner:** Preserve the central white-haired character, hat, face, outfit and blue moonlit style; create a 2:3 portrait composition and integrate `TALESRUNNER` in the lower quarter as readable fantasy poster lettering. No footer strip, frame or other text.
- **Lost Saga:** Preserve the camping scene, chibi characters, campfire and violet sky; create a 2:3 portrait composition and integrate `LOST SAGA` in the lower quarter using warm gold-orange poster lettering. No footer, border or UI caption.
- **BattlEye:** Preserve the owl mark and dark olive composition; add centered `BattlEye` below the mark inside the image in bold near-white lettering. No box, strip, frame or extra text.
- **Vanguard:** Preserve the red emblem and red-black composition; add centered `VANGUARD` beneath the emblem in near-white geometric lettering. No footer, border, box or extra text.


## Mobile catalog · 2026-11-03

Indices 12–17 append six mobile-game covers to the existing catalog. Every selected source already contains its game title inside the artwork; no external caption, title band, AI-generated replacement, or game functionality is added. These are popular mobile-game catalog selections, not a claim that they are the current top six games or their latest official cover editions.

The complete portrait covers were retrieved from the third-party game-art hosts recorded below. Publisher pages verify the game identity; they are not claimed to be the download origin. Decoding the retrieved image to RGB and saving it as PNG is lossless relative to its decoded pixels. The existing build pipeline supplies the aspect-preserving center crop, 512×768 normal texture and bounded 128×192 spatial-blur derivative. All six normalized covers were visually checked to retain their in-image titles. The twelve prior PNGs and twenty-four prior generated texture headers remain byte-for-byte unchanged.

### 12 · Cozy.Card-Roblox.png

- Game: Roblox
- Kind: Existing titled portrait cover, retrieved through a third-party game-art host
- Rights holder: Roblox Corporation
- Publisher page: https://www.roblox.com/
- Retrieval page: https://www.igdb.com/games/roblox
- Retrieved image: https://images.igdb.com/igdb/image/upload/t_original/cociyw.webp
- Source dimensions: 1798×2396
- Downloaded source SHA-256: `03285166c14e38e7275b50ed03550fe7ca7e799dcbfd1d4107e39cbac24a2d89`
- Checked-in PNG SHA-256: `c61c33202fa5bcc1b83f0d131634f210a86b0421942eaf7411f3cd9e35e5c034`

### 13 · Cozy.Card-BrawlStars.png

- Game: Brawl Stars
- Kind: Existing titled portrait cover, retrieved through a third-party game-art host
- Rights holder: Supercell
- Publisher page: https://supercell.com/en/games/brawlstars/
- Retrieval page: https://www.dexerto.com/gaming/db/game/brawl-stars/
- Retrieved image: https://images.igdb.com/igdb/image/upload/t_1080p/co1mb9.jpg
- Source dimensions: 810×1080
- Downloaded source SHA-256: `4e1f6a19d081df78b501772f8c5464a7476202f9d56036adb0fa557d87978c61`
- Checked-in PNG SHA-256: `7971cd0dd8a01c7b3f097b4c9d7636697745c02847c952a41eb1d54363780f54`

### 14 · Cozy.Card-PUBGMobile.png

- Game: PUBG MOBILE
- Kind: Existing titled portrait cover, retrieved through a third-party game-art host
- Rights holder: KRAFTON / LIGHTSPEED STUDIOS / Level Infinite
- Publisher page: https://www.pubgmobile.com/
- Retrieval page: https://www.igdb.com/games/pubg-mobile
- Retrieved image: https://images.igdb.com/igdb/image/upload/t_original/co1njn.webp
- Source dimensions: 600×800
- Downloaded source SHA-256: `a19133a6dade76c08f02f3994e236f9464412a2951017784e56b3a08d84bfb92`
- Checked-in PNG SHA-256: `a0e47f7aa3de770ef6116e218b82005b1931ef3ea17cae0d390b0de4a85afaa9`

### 15 · Cozy.Card-GenshinImpact.png

- Game: Genshin Impact
- Kind: Existing titled portrait cover, retrieved through a third-party game-art host
- Rights holder: HoYoverse
- Publisher page: https://genshin.hoyoverse.com/en/
- Retrieval page: https://www.jeuxvideo.com/jeux/ps4/jeu-1170037/
- Retrieved image: https://image.jeuxvideo.com/medias/163299/1632994029-269-jaquette-avant.png
- Source dimensions: 600×900
- Downloaded source SHA-256: `039a066258b7a4e517b2f2edee1ba64056d2e0b80338f4184922b72d783952a3`
- Checked-in PNG SHA-256: `fffb07a2d2ec5c45f581bb5649546b6fe89e1de515df0405829ba621648f2740`

### 16 · Cozy.Card-PokemonGO.png

- Game: Pokémon GO
- Kind: Existing titled portrait cover, retrieved through a third-party game-art host
- Rights holder: Niantic / The Pokémon Company / Nintendo / Creatures / GAME FREAK
- Publisher page: https://pokemongo.com/
- Retrieval page: https://www.igdb.com/games/pokemon-go
- Retrieved image: https://images.igdb.com/igdb/image/upload/t_original/co9gmb.webp
- Source dimensions: 600×800
- Downloaded source SHA-256: `4f395145162b72fde543bfc4d9528b9281f1807c616e6a6ed9b8785ff1ae0fc1`
- Checked-in PNG SHA-256: `48756902728fae3daaa4ef48c038184d7decf178b3a8bf7c6b530b7e91b49b9f`

### 17 · Cozy.Card-ClashRoyale.png

- Game: Clash Royale
- Kind: Existing titled portrait cover, retrieved through a third-party game-art host
- Rights holder: Supercell
- Publisher page: https://supercell.com/en/games/clashroyale/
- Retrieval page: https://screenwiseapp.com/media/clash-royale-game
- Retrieved image: https://images.igdb.com/igdb/image/upload/t_1080p/co1mb7.jpg
- Source dimensions: 810×1080
- Downloaded source SHA-256: `0a889ec8b5a81a49436123e4f1cebe39021411cdaa39c0504f84138d6bc4b1e2`
- Checked-in PNG SHA-256: `89e375ecbf89e2866b92d29da1e3c1b2b2aa7bdada5b1dada84daf41468c0ecb`
