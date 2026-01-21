[![Linux](https://github.com/fwbuilder/fwbuilder/workflows/Linux/badge.svg)](https://github.com/fwbuilder/fwbuilder/actions?query=workflow%3ALinux)
[![macOS](https://github.com/fwbuilder/fwbuilder/workflows/macOS/badge.svg)](https://github.com/fwbuilder/fwbuilder/actions?query=workflow%3AmacOS)
[![w32-mxe](https://github.com/fwbuilder/fwbuilder/workflows/w32-mxe/badge.svg)](https://github.com/fwbuilder/fwbuilder/actions?query=workflow%3Aw32-mxe)

fwbuilder
=========

Firewall Builder is a GUI firewall management application for nftables, iptables, PF, Cisco ASA/PIX/FWSM, Cisco router ACL and more. Firewall configuration data is stored in a central file that can scale to hundreds of firewalls managed from a single UI.

Firewall Builder includes an nftables compiler (fwb_nft). To use it, select the **nftables** platform in the firewall object (New Firewall wizard or the firewall properties dialog). The generated scripts use the `nft` binary and support optional atomic loading and an optional `nftables.conf` path configured in the firewall platform settings.


Installation instructions
=========================


Ubuntu
---------
```
 sudo apt install git cmake libxml2-dev libxslt-dev libsnmp-dev qt5-default qttools5-dev-tools
 git clone https://github.com/fwbuilder/fwbuilder.git
 mkdir build
 cd build
 cmake ../fwbuilder
 make
 sudo make install
```
Note: default destination is /usr/local. This is configurable:
```
 cmake ../fwbuilder -DCMAKE_INSTALL_PREFIX=/usr
```

Windows
---------
Prerequisites (choose either MSYS2/MinGW or MSVC):
- Toolchain: MSYS2 MinGW-w64 (mingw-w64-x86_64-gcc) **or** Visual Studio 2019/2022 with C++ workload.
- Qt 5 or Qt 6 (Qt Creator/SDK or standalone packages).
- CMake 3.16+ and a build tool (Ninja, MinGW Make, or MSBuild).
- Dependencies: libxml2, libxslt, libsnmp (via MSYS2 packages or prebuilt Windows binaries).

Repository clone:
```
 git clone https://github.com/fwbuilder/fwbuilder.git
 cd fwbuilder
```

Build directory setup:
```
 mkdir build
 cd build
```

CMake configuration examples:
- MSYS2/MinGW (64-bit):
```
 cmake .. -G "MinGW Makefiles" ^
   -DCMAKE_BUILD_TYPE=Release ^
   -DCMAKE_PREFIX_PATH=C:/Qt/6.6.1/mingw_64 ^
   -DLIBXML2_LIBRARY=C:/msys64/mingw64/lib/libxml2.dll.a ^
   -DLIBXML2_INCLUDE_DIR=C:/msys64/mingw64/include/libxml2 ^
   -DLIBXSLT_LIBRARY=C:/msys64/mingw64/lib/libxslt.dll.a ^
   -DLIBXSLT_INCLUDE_DIR=C:/msys64/mingw64/include ^
   -DNETSNMP_LIBRARY=C:/msys64/mingw64/lib/libnetsnmp.dll.a ^
   -DNETSNMP_INCLUDE_DIR=C:/msys64/mingw64/include
```
- MSVC (Visual Studio 2022 x64):
```
 cmake .. -G "Visual Studio 17 2022" -A x64 ^
   -DCMAKE_PREFIX_PATH=C:/Qt/6.6.1/msvc2019_64 ^
   -DLIBXML2_LIBRARY=C:/deps/libxml2/lib/libxml2.lib ^
   -DLIBXML2_INCLUDE_DIR=C:/deps/libxml2/include ^
   -DLIBXSLT_LIBRARY=C:/deps/libxslt/lib/libxslt.lib ^
   -DLIBXSLT_INCLUDE_DIR=C:/deps/libxslt/include ^
   -DNETSNMP_LIBRARY=C:/deps/net-snmp/lib/netsnmp.lib ^
   -DNETSNMP_INCLUDE_DIR=C:/deps/net-snmp/include
```

Build commands:
- MinGW:
```
 mingw32-make -j4
```
- MSVC:
```
 cmake --build . --config Release
```

Create a Windows installer
-------------------------
If CPack is configured for your build, from the build directory run:
```
 cpack -C Release
```
This will produce an installer package (e.g., ZIP or NSIS, depending on your CPack settings).

If CPack is not configured, use a packaging tool such as NSIS or WiX:
1. Stage install files (e.g., `cmake --install . --config Release --prefix C:/staging/fwbuilder`).
2. Use `windeployqt` to copy Qt runtime dependencies into the staging folder.
3. Add any required DLLs for libxml2/libxslt/libsnmp and your compiler runtime (MSVC Redistributable or MinGW runtime).
4. Create the installer with NSIS (`makensis`) or WiX (`candle`/`light`) pointing at the staged folder.

Installing on another Windows machine:
1. Copy the generated installer to the target machine and run it.
2. Ensure runtime dependencies are bundled in the installer or preinstalled (Qt DLLs, libxml2/libxslt/libsnmp, and MSVC/MinGW runtime).
3. Launch Firewall Builder from the installed Start Menu shortcut or installation directory.

Create deb package
---------
```
debuild -us -uc --lintian-opts --profile debian
```
