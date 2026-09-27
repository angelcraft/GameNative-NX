# GameNative v1.2.1 runtime analysis

This note records observations from the user-supplied runtime subset extracted from the APK.

## ARM64 native libraries

The runtime subset contains 11 selected AArch64 Android shared objects relevant to the compatibility layer:

- libwinlator.so
- libwinlator_11.so
- libsteambootstrap.so
- libhook_impl.so
- libmain_hook.so
- libasurface_renderer.so
- libdummyvk.so
- libkgslshim.so
- libvirglrenderer.so
- libvortekrenderer.so
- libvulkan_renderer.so

These are ELF64 AArch64 shared objects rather than Switch NROs.

## Dynamic dependencies observed

The Winlator/rendering helpers reference Android platform libraries including:

- libandroid.so
- libjnigraphics.so
- libEGL.so
- libGLESv2.so / libGLESv3.so
- libvulkan.so
- liblog.so
- libdl.so
- libc.so
- libm.so

`libvortekrenderer.so` also references `libc++_shared.so` and `libwinlator_11.so`.

## Box64

`box64-0.4.2-bionic.tzst` expands to a single `usr/bin/box64` ELF64 AArch64 PIE executable. Its interpreter is `/system/bin/linker64`, and its dynamic dependencies are Android `libc.so`, `libm.so`, and `libdl.so`.

This means the bundled Box64 binary itself is not a Switch executable. Porting Box64 as source, or rebuilding its platform layer, is preferable to trying to run the Android binary unchanged.

## FEXCore

`fexcore-2605.tzst` contains two Wine PE DLLs:

- libwow64fex.dll
- libarm64ecfex.dll

This is runtime payload for the Wine/ARM64EC side rather than a standalone Switch binary.

## WoWBox64

`wowbox64-0.4.2.tzst` contains `wowbox64.dll`, also a Wine PE DLL.

## Proton

The Proton 9.0 arm64ec container pattern is primarily a filesystem/container template containing `.wine`, `drive_c`, Windows DLLs and configuration files. It should be treated as a rootfs/prefix payload, not as one native binary to port.

## Consequence for the Switch plan

The first hard boundary is:

```text
GameNative Android UI
            X
            |
            v
Winlator native bridge
            |
            v
Android API compatibility layer
            |
            v
Switch/native graphics + POSIX services
            |
            v
Box64 / FEX / Wine / Proton
```

The v0.2.0 loader probe is intentionally placed at the first boundary so we can collect exact unresolved-symbol/loader failures before writing large compatibility layers.
