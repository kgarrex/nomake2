:: 
:: /NODEFAULTLIB 
:: /DEFAULTLIB:kernel32.lib
:: .\tools\Hostx64\x64\cl
:: /ENTRY:main

@echo off
cl -c -wd4047 -wd4022 -GS- -nologo -D"SUBSYSTEM_CONSOLE" ^
nomake.c helper.c

ml -c -coff -D"SYSCALL_NTQUERYINFORMATIONPROCESS"=b9h -D"SYSCALL_NTCREATEIOCOMPLETION"=177h ^
-nologo -Zf lib.asm test.asm

::nasm-2.15.05-win32\nasm-2.15.05\nasm lib.asm
::nasm-2.15.05-win32\nasm-2.15.05\nasm test.asm


link -NOLOGO  -SUBSYSTEM:CONSOLE -DEFAULTLIB:ntdll.lib -DEFAULTLIB:kernel32.lib ^
-NODEFAULTLIB:libcmt.lib -MACHINE:x86  -INCREMENTAL:NO  -ENTRY:nm_system_entry ^
 nomake.obj test.obj helper.obj lib.obj


del nomake.obj test.obj helper.obj lib.obj
