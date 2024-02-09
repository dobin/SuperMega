# SuperMega

## What

SuperMega is a shellcode loader. It will take a shellcode as input, protects it, adds a loader,
and injects the resulting shellcode into an exe. 

And: 
* Only works with 64 bit (shellcode and infectable exe's)

Features: 
* Loader source is C yay
* Execution-Guardrails
  * Environment variables


## Installation

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

Alternatively, you can maybe use a 64bit Visual Studio developer console or insert env paths:
```
"C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat"
```
And just use executable "cl.exe" and "ml64.exe". 


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