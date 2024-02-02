import subprocess
import os
import pefile
import shutil

print("Super Mega")

use_cleanup = True
use_compile = True
use_test = False
use_sgn = False
use_append = True


def main():
    if use_cleanup:
        os.remove("main.asm")       # generated from compiling source/main.c
        os.remove("main-clean.asm") # cleaned for being a shellcode
        os.remove("main-clean.exe") # assembled
        os.remove("main-clean.bin")
        os.remove("main-clean-append.bin")

    if use_compile:
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
        clean_asm_file("main-clean.asm")
        if not os.path.isfile("main-clean.asm"):
            print("Error")
            return
        else:
            print("  Generated main-clean.asm")

    print("--[ Assemble to exe ]")
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

    if use_test:
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

    if use_append:
        with open("main-clean.bin", 'rb') as input1:
            data_stager = remove_trailing_null_bytes(input1.read())

        with open("shellcodes/calc64.bin", 'rb') as input2:
            data_payload = input2.read()

        with open("main-clean-append.bin", 'wb') as output:
            output.write(data_stager)
            output.write(data_payload)

        print("--[ Test Append shellcode ]")
        print("---[ Stager: {}  Shellcode: {} ]".format(len(data_stager), len(data_payload)))
        path_shexec = r'C:\Research\hasherezade\exec_fiber\sh-exec-fiber.exe'
        subprocess.run([
            path_shexec,
            "{}".format("main-clean-append.bin"),
        ])


def clean_asm_file(filename):
    with open(filename, 'r') as asmfile:
        lines = asmfile.readlines()

    # $LN1@main:
    # ; Line 82
    # 	add	rsp, 2392				; 00000958H
    # 	ret	0
    # main	ENDP
    # _TEXT	ENDS
    # 
    # ; Line 81
    # 	xor	eax, eax
    # 	jmp testing
    # $LN1@main:
    # ; Line 82
    # ;	add	rsp, 2392				; 00000958H
    # ;	ret	0
    # main	ENDP
    # _TEXT	ENDS
    #for idx, line in enumerate(lines): 
    #    if lines[idx].startswith("main\tENDP"):
    #        print("--( Fix main-end jmp at line: {}) ".format(idx))
    #        lines[idx-1] = "; " + lines[idx-1]
    #        lines[idx-2] = "; " + lines[idx-2]
    #        lines.insert(idx-4, "\tjmp shcstart\r\n")
    #        break
        
    for idx, line in enumerate(lines): 
        if "dobin" in lines[idx]:
            lines[idx] = lines[idx].replace(
                "mov	r8, QWORD PTR dobin",
                "lea	r8, [shcstart]"
            )
            
        
    #   _TEXT	ENDS
    #   END
    # -> 
    #   testing:
    #     nop
    #   _TEXT	ENDS
    #   END
    #
    for idx, line in enumerate(lines): 
        if lines[idx].startswith("END"):
            print("--( Add end of code label at: {})".format(idx))
            lines.insert(idx-1, "shcstart:\r\n")
            lines.insert(idx, "\tnop\r\n")
            break
    
    with open(filename, 'w') as asmfile:
        asmfile.writelines(lines)


def remove_trailing_null_bytes(data):
    for i in range(len(data) - 1, -1, -1):
        if data[i] != b'\x00'[0]:  # Check for a non-null byte
            return data[:i + 1]
    return b''  # If the entire sequence is null bytes

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