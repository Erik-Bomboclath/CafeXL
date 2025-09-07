# CafeXL
### v0.0.1
A Work in Progress IDA 9.X Loader for loading rpx/rpl binaries with ghs & ppc-gcc (devkitpro) support (the loader its essentially written in nihongo)

Compiled with IDA SDK 9.1 & Tested with IDA 9.1 in a friend's pc, may support 9.0 or 9.2

### What it does:
- loads rpx/rpl fine
- detects functions, intructions, data, and leaves anything weird for IDA unexplored (TODO: fix that if possible)
- loads it into the dissasembler via 32 bits ppc database (TODO: i don't know if its support pseudo c decompiling due to my lack of HEXPPC decompiler, i only have access to dissasembler lol)
- prints all info to terminal via log(), warn(), and error() (built into loader)

### TODO:
- try to make ghs more compatible due to lack of IDA supporting it
- upgrade UTF16
- add support for devkit/debug/demo rpx/rpl due to different syscalls and probably linker scripts when compiled
- document it more properly (it sucks)