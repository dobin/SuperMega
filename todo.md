# Todo List

+ settings -> project: prep_web() and prepare_project() are weird


# high:

* remove r2 for disassembly? (or make it optional)
* more code size checks when selecting (shellcode 300kb .text small)


# mid:

* remove HACK which finds ascii in IAT, just replace with first Interval (or skip found interval 0)
* do not add 0 reloc (for )
* rename dll change-address-eop to overwrite?

* rename: 
  * sourcestyle (peb, iat): carrier_style?
  * rbrunmode (eop, backdoor): start_mode?
* remove jmp at entry (reorder main first in .asm)

* webapp: rename project
* webapp: delete project

* derbackdoorer test-rwx is fucked? (Could not find section with directory index 5!)
* refactor: ui web start / file make it a mode? enum
* exe_view and other exec/exec_more is shit as it is a path / with cannot be used as get
* get_addr_of_iat_function() and others: write if va or rva or offset in variables


refactor mid:
* REST /project_add is shitty
* is helper::run_process_checkret() in wrong file? (see utils.py, but should be like process.py)
* helper had to be changed because of observer include (utils.py) arrr


low:
* take a look at msf backdooring: -x
* add Executor: Create new thread
* integrate into avred
* use r2 to identify strings, and overwrite them individually (injector::inject_fix_data)
* get return value for debugging
  # it somehow doesnt work? does shellcode exit itself? check with NOP?


# Unit Tests

* each modification:
  * inserting code
  * starting code: EOP
  * starting code: hijack
  * IAT patch
  * inserting .rdata data
  * referencing .rdata data
* features
  * relocation holes (check the shitty one in procexp)
  * read/write .text

* make unittests
  * injector: injected_fix_iat() (asm, needs file)
  * model: exeinfo
  * pehelper:
    * extract_code_from_exe()
    * write_code_section()
    * get_code_section() (a few different ones?)
    * get_rwx_section()


# Done

+ auto replace "supermega_payload" "shcstart"
+ try debugging it with az and cmdline shit
+ virtual alloc params are ok?
/ convert shellcode to exe (so i can debug it)
+ capture subprocess output, show it different color
+ check return values of executed commands
+ configurable payload size!
  / best to template main.c?
  + or replace in source
  # $LN4@main:
  # cmp	DWORD PTR n$1[rsp], 348			; 0000015cH
  # jge	SHORT $LN3@main
+ injector: use redbackdoorer (src) to inject it in a clean exe
+ test if mashm_shc converts strings
+ make it debuggable (stdout, stderr on error)
+ config.yaml for paths and stuff
+ write different encryptors
+ save all stdout/stderr into a file
+ make test for rwx
+ check inject exe first for which we choose: 
  + based on shellcode needs too
  + can be:
    + rwx iat_reuse
    + iat_reuse
    + peb_walk
+ refactor capabilities into project
+ get payload_size earlier (not in supermega before c->asm)
+ order of asm fixups
+ web: also capture logger output into a separate file
+ debug log disassemble with r2
+ check code section size before injecting
+ read from files from alloc_style etc. name
+ find executable section
  + code (0x20)
  + then rx with entry point
+ arg to enable short call patching
+ remove TLS mentioning (as it sucks)
+ read written shellcode out of the exe
  + to verify its correct
+ use redbackdoorer directly (as library)
  + also: return addr of patched call
+ webapp
+ 11223344: {{PAYLOAD_LEN}} too
+ show asm diff (for fixup)
+ peb_walk template.c: also make includes
+ remove project from global completely
  + do settings? -> config
+ remove observer from tests
+ set mode from cmdline
  * also test with other modes
+ fix derbackdoorer debug stuff
/ remove use_templates
+ use iconsext.exe UPX packed binary to test RWX insertion
+ fix goddamn newlines again
+ fix HTML encoding
+ translate masmshc to python
+ fix magic offset in reuse_data for REAL reliably
  + make sure its possible to disable it, and use the other two options
  + holes?
+ :x -> :X
+ check all invocations of pehelper.*get_code_section*()
  + for example exehost, doesnt need it as we have it as superpe
+ rawsize vs. virtualsize
+ merge superpe with mype
  / dont load too much by default (init()) -> Done twice
+ check relocs/basereloc if they fall into my shellcode
  + get relocs'
  # usually in .rdata
+ make xor key configurable
+ patch the additional newlines i stupidly add in the asm
+ fix goddamn vs path -> readme again
+ make log a class
+ when error, no supermega.log is written
+ old ones are not cleaned? (do it on start?)
+ rename env
  / should shellcode just be plugin?
  / and "shellcode" the new shellcode?
  / a lot in /dev, /dev/name shitfuck
+ fix config.yaml with http:// and make it a template
+ standardize in REST
+ rework observer, logger, stdout so they work together
+ helper::run_process_checkret() is ugly, too many conversions
+ observer::add_log() its not clear what log is
/ compile_dev in compiler.py is just a copy - is that necessary?
+ put strings into data
+ web: fix timeout on create
+ observer: will too often write to file instead of doing it in a datastructure

+ give/create directory where everything is stored (per project / invocation)
+ do all asm parsing like datareuse asm parser (in one place?)
  / compiler a class? -> no, no shared stuff
+ put logs into project dir
+ remove AllocStyle
+ remove ExecStyle
+ rename InjectStyle  -> CarrierInvokeStyle    (how to call carrier, EOP/CALL)
  + settings.inject_mode
  + derbackdoorer.runMode
+ rename SourceStyle  -> FunctionInvokeStyle   (how to call functions, IAT/PEB)
  + sourcestyle
  + sourcestyles
/ rename DataRefStyle -> PayloadInjectStyle -> removed
+ view_project::project() does not yet get real export list
+ infect dll's
  + based on redbackdoorer, DLL always use backdoorEntryPoint (not EOP)
    + EOP is DllMain()!
+ hide buttons if corresponding files aint there
+ rename derbackdoorer.runMode to InjectStyle
  + everywhere else too
+ verifier with many exes (filecreate shellcode)

/ ui dropdown exe/dll: add rx section size -> no, performance
+ ui dropdown shellcode: add size 
+ check if dll/exe runs (does not have any unfulfilled dependencies)
+ iat_reuse in dll's seem to be a bit broken? -> fixed, iat and function size
+ do not use jne/jge to recursively search for stuff (only for calls. if even?)
+ test: iatttest-full.exe: 
  + hijack doesnt work
  + eop says "no code section found"
+ things to consider
  + DLL-func EOP: needs to have space in it (relocs? or why?)
  + DLL-func Hijack: always works? (very small functions with no jump?) -> 3 options
    + show: the function, up until the jump
    + make 3 options selectable
+ datareuse::datareusefileparser: move away into compiler
/ can or should i use strlen() for payload instead of hardcode length?
/ add masm_shc, runshc binaries to the repo
/ is reloc generally really necessary?
  # procexp pebwalk hijack: yes
  # procexp pebwalk eop: NO
+ show missing dlls more dominantely
  / make it unable to build?
  + make a way where user can copy his dlls there (dont remove everything from project folder)
+ rw: 0x4  rx: 0x20  rwx: 0x40
+ most exes dont work (because missing dlls), check it
/ remove exes_more/ and dlls/?
+ ui build: will copy new files
  + copy only when not exists? -> del all except nonstandard .exe .dll 
+ list shellcode
+ list exes
+ remotely detonate it on a host (like avred)
+ change func hijack relocatable call to indirect call
+ iat-overwrite/path settings
+ remove exehost? it doesnt do much
  + optimize get_vaddr_of_iatentry() ?
+ remove all unecessary iat* functions in superpe
+ injector: get from carrier
+ change an IAT to the one's we need (existing DLLs only?)
+ merge all Cs keystone disasm into pehelper? (derbackdoorer)
+ put payload into data or other section (consider relocs)
  # note: lea is 7 bytes
  + make webapp checkbox
  + note: fix xor
+ rename AsmParser to AsmTextParser, parse_asm_file
+ use directory name as index instead of Enum?
  + PATH_PEB_WALK, PATH_IAT_REUSE
  + PATH_CARRIER
  + settings.source_style   -> carrier_name
  + settings.template_path
  + args.function_invoke_style
/ remove peb_walk? -> no keep it
+ modify .text or .data memory protection
+ some of the shellcodes require RWX memory -> dedicated template
+ shellcode: Use WinExec(), or CreateProcessA()?
+ set enc key in config (xor_key, xor_key2)
  + random if not set
+ try again with short len for protect, but consider 300kb of pages (loop)
+ IAT with cpuz.exe: no size 3 in .rdata?!




