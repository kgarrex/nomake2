@echo off

cl -nologo -c test.c

nasm-2.15.05-win32\nasm-2.15.05\nasm -fwin32 json\json.asm

::-nodefaultlib:libcmt.lib 

link -nologo -subsystem:console -defaultlib:ntdll.lib -defaultlib:kernel32.lib ^
-machine:x86 -incremental:no -entry:mainCRTStartup ^
 test.obj json\json.obj

del json\json.obj test.obj
