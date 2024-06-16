import pefile
import logging

from model.defs import *

logger = logging.getLogger("PEHelper")


# PEHelper
# Work directly on PE files. Not using superpe or other abstractions.
# Its mostly used for verification of what we were doing. 


# PRE-LOAD a dll file into memory
# This will load the DLL file into a memory buffer, already
# loaded at the correct RVA addresses (e.g. sections page aligned).
def preload_dll(payload_path: str) -> bytes:
    dllPe = pefile.PE(payload_path)
    dllImageSize = dllPe.OPTIONAL_HEADER.SizeOfImage
    payload: bytearray = bytearray(dllImageSize)

    # copy PE header sizeofheaders
    payload[:dllPe.OPTIONAL_HEADER.SizeOfHeaders] = dllPe.get_data()[:dllPe.OPTIONAL_HEADER.SizeOfHeaders]

    # copy sections
    for section in dllPe.sections:
        if section.SizeOfRawData == 0:
            continue
        payload[section.VirtualAddress:section.VirtualAddress + section.SizeOfRawData] = section.get_data()

    return bytes(payload)


def extract_code_from_exe_file_ep(exe_file: FilePath, len: int) -> bytes:
    pe = pefile.PE(exe_file)
    section = get_code_section(pe)
    data: bytes = section.get_data()
    data = remove_trailing_null_bytes(data)
    ep = pe.OPTIONAL_HEADER.AddressOfEntryPoint
    ep_raw = get_physical_address_tmp(pe, ep)
    data = data[ep_raw:ep_raw+len]
    pe.close()
    return data


def get_physical_address_tmp(pe, virtual_address):
    for section in pe.sections:
        if section.VirtualAddress <= virtual_address < section.VirtualAddress + section.Misc_VirtualSize:
            virtual_offset = virtual_address - section.VirtualAddress
            physical_address = section.PointerToRawData + virtual_offset
            return physical_address
    return None


def extract_code_from_exe_file(exe_file: FilePath) -> bytes:
    pe = pefile.PE(exe_file)
    section = get_code_section(pe)
    data: bytes = section.get_data()
    data = remove_trailing_null_bytes(data)
    logger.debug("---[ Extract code section size: {} / {}".format(
        len(data), section.Misc_VirtualSize))
    pe.close()
    return data


def write_code_section(exe_file: FilePath, new_data: bytes):
    pe = pefile.PE(exe_file)
    section = get_code_section(pe)
    file_offset = section.PointerToRawData
    with open(exe_file, 'r+b') as f:
        f.seek(file_offset)
        f.write(new_data)
    pe.close()


def get_code_section(pe: pefile.PE) -> pefile.SectionStructure:
    entrypoint = pe.OPTIONAL_HEADER.AddressOfEntryPoint
    for sect in pe.sections:
        if sect.Characteristics & pefile.SECTION_CHARACTERISTICS['IMAGE_SCN_MEM_EXECUTE']:
            if entrypoint >= sect.VirtualAddress and entrypoint <= sect.VirtualAddress + sect.Misc_VirtualSize:
                return sect
    raise Exception("pehelper::get_code_section(): Code section not found")


## Utils

def remove_trailing_null_bytes(data: bytes) -> bytes:
    for i in range(len(data) - 1, -1, -1):
        if data[i] != b'\x00'[0]:  # Check for a non-null byte
            return data[:i + 1]
    return b''  # If the entire sequence is null bytes


def align_to_page_size(rva, offset, page_size=4096):
    # Align to the nearest lower page boundary
    aligned_address = rva & ~(page_size - 1)
    real_address = aligned_address - offset
    logger.debug("      Aligning: 0x{:X} to 0x{:X}".format(aligned_address, real_address))
    return real_address