:: 
:: /NODEFAULTLIB 
:: /DEFAULTLIB:kernel32.lib
:: .\tools\Hostx64\x64\cl
:: /ENTRY:main

@echo off
cl -c -GS- -nologo -D"SUBSYSTEM_CONSOLE" nomake.c helper.c

ml -c -D"SYSCALL_NTQUERYINFORMATIONPROCESS"=b9h -D"SYSCALL_NTCREATEIOCOMPLETION"=177h -nologo -Zf lib.asm test.asm

link -NOLOGO  -SUBSYSTEM:CONSOLE -DEFAULTLIB:ntdll.lib -DEFAULTLIB:kernel32.lib ^
-NODEFAULTLIB:libcmt.lib -MACHINE:x86  -INCREMENTAL:NO  -ENTRY:nm_system_entry nomake.obj test.obj helper.obj


del nomake.obj test.obj helper.obj
