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
* Anti emulation, against AV emulators
* EDR deconditioner, against EDR memory scan
* Keep all original properties of the executable (imports etc.)
* Very small carrier loader
* Code execution with main function hijacking
* No PEB walk, reuses IAT to execute windows api functions
* Inject data into .rdata for the carrier shellcode
* Patch IAT for missing functions for the carrier

References: 
* [Slides](https://docs.google.com/presentation/d/1_gwd0M49ObHZO5JtrkZl1NPwRKXWVRm_zHTDdGqRl3Q/edit?usp=sharing) HITB2024 BKK "My first and last shellcode loader"
* [Blog Supermega Loader](https://blog.deeb.ch/posts/supermega/)
* [Blog Cordyceps File injection techniques](https://blog.deeb.ch/posts/exe-injection/)


## Usage

```
> ./web.py
```

Browse to `http://localhost:5001".


Alternatively, use `./supermega.py --help`, but its not well supported.

## Directories

* `data/binary/shellcodes`: Input: Shellcodes we want to use as input (payload)
* `data/binary/exes/`: Input: Nonmalicious EXE files we inject into
* `data/source/carrier`: Input: Carrier C templates
* `projects/<projectname>`: output: Project directory with all files
* `projects/default`: output: Project directory with all files


## Installation

VS2022 compilers.

Required:
* `ml64.exe`
* `cl.exe`

Optional: 
* `r2.exe`

And the python packages:
```
> pip.exe install -r requirements.txt
```

### How to get the right paths

Either start the "visual studio developer console", or 
use the following commandline to get all the env right. 
Use this when `Cannot find Windows.h`.

```
cmd.exe /c "`"C:\Program Files (x86)\Microsoft Visual Studio\<year>\<edition>\Common7\Tools\VsDevCmd.bat`" && powershell"
```

Also make sure radare2 is in path if you wanna use it:
```
$Env:PATH += ";C:\Tools\radare2-5.8.8-w64\bin"
```


### Alternative Path Setup

Try using:
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