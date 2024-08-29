# SuperMega - Cordyceps Implementation

> Ophiocordyceps camponoti-balzani is a species of fungus that parasitizes 
> insect hosts of the order Hymenoptera, primarily ants. O. 
> camponoti-balzani infects ants, and eventually kills the hosts after 
> they move to an ideal location for the fungus to spread its spores.


## What

SuperMega is a shellcode loader by injecting it into genuine executables (.exe or .dll).
The loader is programmed in C. 

The idea is that injecting shellcode nicely into a non-malicious executable should make
it less detected.

Features:
* Encrypt payload
* Execution guardrails, so payload is only decrypted on target
* Keep all original properties of the executable (imports etc.)
* Very small carrier loader
* Code execution either through Entry Point modification, or ASM function hijacking
* Patches carrier shellcode so it re-uses the original IAT (IAT-reuse, no peb-walk)
* Patch IAT for missing functions for the carrier


## Usage

```
> ./web.py
```

## Examples

Inject `messagebox.bin` shellcode into `procexp64.exe` executable:

```
(project.py  ) Copy data/source/carrier/iat_reuse/template.c to projects/default/
(payload.py  ) --( Load payload: data/binary/shellcodes/messagebox.bin
(exehost.py  ) --[ Analyzing: data/binary/exes/procexp64.exe
(exehost.py  ) ---[ Injectable: Chosen code section: .text at 0x1000 size: 1159374
(supermega.py) --I FunctionInvokeStyle: iat_reuse  Inject Mode: hijack branching instruction in entrypoint  DecoderStyle: xor_1
(templater.py) --[ Create C from template
(compiler.py ) --[ Compile C to ASM: projects/Verify_1/main.c -> projects/Verify_1/main.asm 
(helper.py   ) --[ Run process: C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Tools\MSVC\14.37.32822\bin\Hostx64\x64\cl.exe /c /FA /GS- /Faprojects/Verify_1/ projects/Verify_1/main.c
(assembler.py) --[ Assemble to exe: projects/Verify_1/main.asm -> projects/Verify_1/main.exe -> projects/Verify_1/main.bin
(helper.py   ) --[ Run process: C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Tools\MSVC\14.37.32822\bin\Hostx64\x64\ml64.exe projects/Verify_1/main.asm /link /OUT:projects/Verify_1/main.exe /entry:AlignRSP
(assembler.py) --[ Merge stager with payload -> projects/Verify_1/main.bin
(assembler.py) ---[ XOR payload with key 0x31
(assembler.py) ---[ Size: Stager: 554 and Payload: 433  Sum: 987 
(injector.py ) --[ Injecting: data/binary/shellcodes/messagebox.bin into data/binary/exes/procexp64.exe -> projects/Verify_1/procexp64.infected.exe
(injector.py ) --( Inject: Shellcode rva:0x8E679 (from offset:0x8DA79)
(injector.py ) ---( Rewire: EXE
(injector.py ) --( Inject EXE: Patch from entrypoint (0xE1D78)
(derbackdoorer.py) Backdooring function at 0xE1D78 (to shellcode 0x8E679)
(derbackdoorer.py) find suitable instr to hijack: off: from 0xE1D78 len:256 depthopt:DEPTH_OPTIONS.LEVEL1
(derbackdoorer.py) 	[000e1d78]	48 83 ec 28            sub	rsp, 0x28
(derbackdoorer.py) 	[000e1d7c]	e8 2f 04 00 00         call	0xe21b0
(derbackdoorer.py) --[ Backdoor 0xE1D7C: MOV RDX, 0x14008E679 ; CALL RDX
(superpe.py  ) Adding 1 relocations for Page RVA 0xE1000 - size of block: 0xA
(superpe.py  ) 	Reloc0 for addr 0xE1D7E: 0xAD7E - 0xD7E - type: 10
(injector.py )     Replace 139cafc9f30d at VA 0x14008E73A with call to IAT at VA 0x14011D848
(injector.py )     Replace 9a16256e76f8 at VA 0x14008E785 with call to IAT at VA 0x14011D958
(injector.py )     Replace 0c2c5edbf8b5 at VA 0x14008E800 with call to IAT at VA 0x14011DBE8
(injector.py )     Add data to .rdata at 0x1401204A9 (off: 1174185): USERPROFILE
(injector.py )     Add data to .rdata at 0x1401206A9 (off: 1174697): C:\Users\hacker
(injector.py )     Replace 46c4ab596ed89c at VA 0x14008E6FD with LEA rcx .rdata 0x1401204A9
(injector.py )     Replace 2c305aac9e56ab at VA 0x14008E716 with LEA rcx .rdata 0x1401206A9
```


## Directories

* `data/binary/shellcodes`: Input: Shellcodes we want to use as input (payload)
* `data/binary/exes/`: Input: Nonmalicious EXE files we inject into
* `data/source/carrier`: Input: Carrier C templates
* `projects/<projectname>`: output: Project directory with all files
* `projects/default`: output: Project directory with all files


## Installation

### Paths

Configure `config.yaml` with: 
* Path to Visual Studio 2022 compiler and assembler
* Path to mash_shc and runshc: https://github.com/hasherezade/masm_shc. 

`config.yaml`:
```yaml
path_cl: 'C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Tools\MSVC\14.37.32822\bin\Hostx64\x64\cl.exe'
path_ml64:  'C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Tools\MSVC\14.37.32822\bin\Hostx64\x64\ml64.exe'

path_masmshc:  'C:\Users\hacker\Source\Repos\masm_shc\out\build\x64-Debug\masm_shc\masm_shc.exe'
path_runshc: 'C:\Users\hacker\Source\Repos\masm_shc\out\build\x64-Debug\runshc\runshc.exe'
```

Make sure its the `Hostx64/x64/` one exe. Make sure to compile
msmshc and runshc as 64bit. You can also replace runshc with
your own shellcode loader. 

### Environment Variables

It needs all the Microsoft Visual Studio specific paths as environment
variables. Either start the "visual studio developer console", or if you are sane, 
use the following commandline to get all the damn env right. 
Use this when `Cannot find Windows.h`.

```
cmd.exe /c "`"C:\Program Files (x86)\Microsoft Visual Studio\<year>\<edition>\Common7\Tools\VsDevCmd.bat`" && powershell"
```

Also make sure radare2 is in path:
```
$Env:PATH += ";C:\Tools\radare2-5.8.8-w64\bin"
```


### Alternative

Use
```
"C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat"
```

or the VS developer console to find the damn environment variables, and set 
it in your python console. In my case:
```
$env:INCLUDE = "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Tools\MSVC\14.37.32822\include;C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Tools\MSVC\14.37.32822\ATLMFC\include;C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\VS\include;C:\Program Files (x86)\Windows Kits\10\include\10.0.22621.0\ucrt;C:\Program Files (x86)\Windows Kits\10\\include\10.0.22621.0\\um;C:\Program Files (x86)\Windows Kits\10\\include\10.0.22621.0\\shared;C:\Program Files (x86)\Windows Kits\10\\include\10.0.22621.0\\winrt;C:\Program Files (x86)\Windows Kits\10\\include\10.0.22621.0\\cppwinrt;C:\Program Files (x86)\Windows Kits\NETFXSDK\4.8\include\um"
$env:LIB="C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Tools\MSVC\14.37.32822\ATLMFC\lib\x64;C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Tools\MSVC\14.37.32822\lib\x64;C:\Program Files (x86)\Windows Kits\NETFXSDK\4.8\lib\um\x64;C:\Program Files (x86)\Windows Kits\10\lib\10.0.22621.0\ucrt\x64;C:\Program Files (x86)\Windows Kits\10\\lib\10.0.22621.0\\um\x64"
$env:LIBPATH="C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Tools\MSVC\14.37.32822\ATLMFC\lib\x64;C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Tools\MSVC\14.37.32822\lib\x64;C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Tools\MSVC\14.37.32822\lib\x86\store\references;C:\Program Files (x86)\Windows Kits\10\UnionMetadata\10.0.22621.0;C:\Program Files (x86)\Windows Kits\10\References\10.0.22621.0;C:\Windows\Microsoft.NET\Framework64\v4.0.30319"
```

### VS2022 Components

A list of packages/components which may be required for Visual Studio 2022:
* C++ 2022 Redistributable Update
* C++ Build Insights
* C++ CMake tools for windows
* C++ /CLI support for v143 build tools (lastest)
* MSBuild
* MSVC v133 - VS 2002 C++ x64/x86 build tools (latest)
* C++ ATL for latest v143 build tools (x86 & x64)
* C++ MFC for latest v143 build tools (x86 & x64)
* Windows 11 SDK