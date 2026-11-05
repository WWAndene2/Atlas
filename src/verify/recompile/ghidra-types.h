/* Ghidra's built-in C types, so its decompiled output compiles. Ghidra writes undefinedN for N bytes of unknown type,
 * and a handful of short integer names; these map each to an integer of the same width. Included before a candidate's
 * source by the recompile check. */
#ifndef ATLAS_GHIDRA_TYPES_H
#define ATLAS_GHIDRA_TYPES_H
typedef unsigned char undefined;
typedef unsigned char undefined1;
typedef unsigned short undefined2;
typedef unsigned int undefined4;
typedef unsigned long long undefined8;
typedef unsigned char byte;
typedef unsigned char uchar;
typedef unsigned short ushort;
typedef unsigned int uint;
typedef unsigned long ulong;
typedef long long longlong;
typedef unsigned long long ulonglong;
typedef unsigned char bool;
typedef unsigned short word;
typedef unsigned int dword;
typedef unsigned long long qword;
typedef unsigned int uint3;
typedef unsigned long long uint5, uint6, uint7, undefined5, undefined6, undefined7;
typedef unsigned short wchar16;
typedef unsigned int wchar32;
typedef unsigned char code;
/* Built-ins of executable formats and the x87 FPU, which Ghidra's type writer refers to (seen on Windows Lua). */
typedef unsigned int pointer32;
typedef unsigned long long pointer64;
typedef unsigned int ImageBaseOffset32;
typedef unsigned long long ImageBaseOffset64;
typedef long double float10;
#define true 1
#define false 0
#endif
