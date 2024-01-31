import subprocess
import os
import pefile
import shutil

print("Super Mega")

use_sgn = False


def main():
    print("--[ Compile C source to ASM ]")
    path_cl = r'C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Tools\MSVC\14.37.32822\bin\Hostx64\x64\cl.exe'
    subprocess.run([
        path_cl,
        "/c",
        "/FA",
        "/GS-",
        "source/main.c"
    ])
    if not os.path.isfile("main.asm"):
        print("Error")
        return
    else:
        print("  Generated main.asm")

    print("--[ Cleanup ASM ]")
    path_masmshc =  r'C:\Users\hacker\Source\Repos\masm_shc\out\build\x64-Debug\masm_shc\masm_shc.exe'
    subprocess.run([
        path_masmshc,
        "main.asm",
        "main-clean.asm",
    ])
    if not os.path.isfile("main-clean.asm"):
        print("Error")
        return
    else:
        print("  Generated main-clean.asm")

    print("--[ Compile to exe ]")
    path_ml64 =  r'C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Tools\MSVC\14.37.32822\bin\Hostx64\x64\ml64.exe'
    subprocess.run([
        path_ml64,
        "main-clean.asm",
        "/link",
        "/entry:AlignRSP"
    ])
    if not os.path.isfile("main-clean.exe"):
        print("Error")
        return
    else:
        print("  Generated main-clean.exe")

    print("--[ Get code section from exe ]")
    code = get_code_section("main-clean.exe")
    with open("main-clean.bin", 'wb') as f:
        f.write(code)
    print("--[ Shellcode written to: main-clean.bin size: {} ]".format(len(code)))

    print("--[ Test it with runshc ]")
    path_runshc = r'C:\Users\hacker\Source\Repos\masm_shc\out\build\x64-Debug\runshc\runshc.exe'
    subprocess.run([
        path_runshc,
        "main-clean.bin",
    ])

    if use_sgn:
        print("--[ Convert with SGN ]")
        path_sgn = r'C:\training\tools\sgn\sgn.exe'
        subprocess.run([
            path_sgn,
            "--arch=64",
            "-i", "{}".format("main-clean.bin"),
            "-o", "{}".format("main-clean-sgn.bin"),
        ])
        if not os.path.isfile("main-clean-sgn.bin"):
            print("Error")
            return
        else:
            print("  Generated main-clean-sgn.bin")

        print("--[ Test SGN shellcode ]")
        path_shexec = r'C:\Research\hasherezade\exec_fiber\sh-exec-fiber.exe'
        subprocess.run([
            path_shexec,
            "{}".format("main-clean-sgn.bin"),
        ])
    else:
        shutil.copyfile("main-clean.bin", "main-clean-sgn.bin")

    



# $env:INCLUDE="C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Tools\MSVC\14.37.32822\include;C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Tools\MSVC\14.37.32822\ATLMFC\include;C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\VS\include;C:\Program Files (x86)\Windows Kits\10\include\10.0.22621.0\ucrt;C:\Program Files (x86)\Windows Kits\10\\include\10.0.22621.0\\um;C:\Program Files (x86)\Windows Kits\10\\include\10.0.22621.0\\shared;C:\Program Files (x86)\Windows Kits\10\\include\10.0.22621.0\\winrt;C:\Program Files (x86)\Windows Kits\10\\include\10.0.22621.0\\cppwinrt;C:\Program Files (x86)\Windows Kits\NETFXSDK\4.8\include\um"
# $env:LIB=C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Tools\MSVC\14.37.32822\ATLMFC\lib\x64;C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Tools\MSVC\14.37.32822\lib\x64;C:\Program Files (x86)\Windows Kits\NETFXSDK\4.8\lib\um\x64;C:\Program Files (x86)\Windows Kits\10\lib\10.0.22621.0\ucrt\x64;C:\Program Files (x86)\Windows Kits\10\\lib\10.0.22621.0\\um\x64
# $env:LIBPATH=C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Tools\MSVC\14.37.32822\ATLMFC\lib\x64;C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Tools\MSVC\14.37.32822\lib\x64;C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Tools\MSVC\14.37.32822\lib\x86\store\references;C:\Program Files (x86)\Windows Kits\10\UnionMetadata\10.0.22621.0;C:\Program Files (x86)\Windows Kits\10\References\10.0.22621.0;C:\Windows\Microsoft.NET\Framework64\v4.0.30319

def get_code_section(pe_file):
    try:
        # Load the PE file
        pe = pefile.PE(pe_file)

        # Iterate over the sections
        for section in pe.sections:
            # Check if this is the code section
            if '.text' in section.Name.decode().rstrip('\x00'):
                print("--> Size: {}".format(section.SizeOfRawData))
                return section.get_data()
        else:
            print("Code section not found.")
    
    except FileNotFoundError:
        print(f"File not found: {pe_file}")
    except pefile.PEFormatError:
        print(f"Invalid PE file: {pe_file}")



main()