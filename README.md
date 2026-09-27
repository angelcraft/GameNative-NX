# GameNative NX

Experimental Nintendo Switch homebrew project exploring a Switch-side runtime for the open-source GameNative stack.

## What this repository is right now

This is **not yet a working GameNative/Winlator port**. It is the first bootstrap stage: a Switch NRO that uses `libsolder` to try loading an Android ARM64 shared object (`libwinlator.so`) in lazy mode.

The purpose of this stage is to turn the first linker failure into concrete work on the Android/Bionic compatibility layer.

## GitHub-only build

You do **not** need devkitPro installed on your PC.

The included GitHub Actions workflow builds inside the `devkitpro/devkita64` container. The workflow fetches the upstream `fgsfdsfgs/libsolder` repository automatically, then runs `make` and uploads the resulting `.nro` as a GitHub Actions artifact.

After uploading this repository to GitHub:

1. Open **Actions**.
2. Select **Build GameNative NX**.
3. Press **Run workflow** (or push to `main`).
4. Wait for the job to finish.
5. Download the `gamenative-nx` artifact.

The artifact contains:

```text
switch/
└── gamenative_nx/
    ├── gamenative_nx.nro
    ├── gamenative_nx.nacp
    ├── README.md
    └── THIRD_PARTY_NOTICES.md
```

## What you still need to provide later

The GameNative v1.2.1 Android runtime is **not committed to this repository**. The APK contains proprietary/project runtime binaries and large compressed runtime blobs. Keep those outside Git unless you have the right to redistribute them.

For the current probe, the Switch SD layout is:

```text
sdmc:/switch/gamenative_nx/
├── gamenative_nx.nro
├── native/
│   └── arm64-v8a/
│       └── libwinlator.so
├── runtime/
│   ├── box64/
│   ├── fexcore/
│   ├── proton/
│   └── wowbox64/
└── games/
```

Only `libwinlator.so` is needed for the first loader probe. The other runtime files come later.

## First test

Launch `gamenative_nx.nro` in a full-memory homebrew context.

The program will:

- initialize `libsolder`;
- add `sdmc:/switch/gamenative_nx/native/arm64-v8a` as a shared-object search path;
- wait for **A**;
- lazily attempt to load `libwinlator.so`;
- print the loader error or the loaded ELF base/text addresses;
- append diagnostics to `sdmc:/switch/gamenative_nx/debug.log`.

A successful lazy ELF load does **not** mean Winlator is executable on Switch yet. Android/Bionic imports still need to be replaced or shimmed.

## Current GameNative v1.2.1 runtime map

The analyzed APK contains these relevant component families:

- Box64: up to `0.4.2-bionic`
- FEXCore: up to `2605`
- Proton 9.0: ARM64EC and x86_64 container patterns
- WoWBox64: up to `0.4.2`
- Winlator native helpers
- Vulkan / Vortek / VirGL renderers
- PulseAudio
- Steam bootstrap

The Android `lib/arm64-v8a` directory includes `libwinlator.so`, `libwinlator_11.so`, `libsteambootstrap.so`, `libhook_impl.so`, `libmain_hook.so`, `libvulkan_renderer.so`, `libvortekrenderer.so`, `libvirglrenderer.so`, and `libdummyvk.so` among others.

## Roadmap

```text
Android ARM64 .so
        |
        v
     libsolder
        |
        +--> Bionic / Android compatibility shims
        |
        +--> Android graphics -> Switch graphics
        |
        v
      Winlator
        |
        v
   Box64 / FEX / Wine
        |
        v
   Proton + Windows game
```

The next useful milestone is to load `libwinlator.so`, enumerate its unresolved Android symbols, and implement only the minimum Switch-side exports needed to progress.

## Licensing

`libsolder` is fetched at build time from its upstream MIT-licensed repository. See `THIRD_PARTY_NOTICES.md` and the upstream project for its license and credits.

Do not commit APKs, game data, proprietary game files, or redistributed runtime data that you are not allowed to distribute.
