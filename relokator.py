import sys
import logging

from model.defs import *
from pe.superpe import SuperPe
from log import setup_logging

logger = logging.getLogger("Relokator")


class Relokator():


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
        relocsIndex = self.getSectionIndexByDataDir(SuperPe.IMAGE_DIRECTORY_ENTRY_BASERELOC)
        out = self.pe.sections[relocsIndex].SizeOfRawData - self.pe.sections[relocsIndex].Misc_VirtualSize
        return out
    
    
    def addImageBaseRelocations(self, pageRva, relocs):
        assert pageRva > 0

        if not self.pe.has_relocs():
            logger.error("No .reloc section")
            raise(Exception("No .reloc section"))

        if self.is_64():
            imageBaseRelocType = SuperPe.IMAGE_REL_BASED_DIR64
        else:
            # Not really used
            imageBaseRelocType = SuperPe.IMAGE_REL_BASED_HIGHLOW

        relocsSize = self.pe.OPTIONAL_HEADER.DATA_DIRECTORY[SuperPe.IMAGE_DIRECTORY_ENTRY_BASERELOC].Size
        relocsIndex = self.getSectionIndexByDataDir(SuperPe.IMAGE_DIRECTORY_ENTRY_BASERELOC)
        addr = self.pe.OPTIONAL_HEADER.DATA_DIRECTORY[SuperPe.IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress
        sizeOfReloc = 2 * len(relocs) + 2 * 4

        if sizeOfReloc >= self.getRemainingRelocsDirectorySize():
            self.logger.warning('WARNING! Cannot add any more relocations to this file. Probably TLS Callback execution technique wont work.')
            self.logger.warning('         Will try disabling relocations on output file. Expect corrupted executable though!')

            self.pe.OPTIONAL_HEADER.DATA_DIRECTORY[SuperPe.IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress = 0
            self.pe.OPTIONAL_HEADER.DATA_DIRECTORY[SuperPe.IMAGE_DIRECTORY_ENTRY_BASERELOC].Size = 0
            return

        relocDirRva = self.pe.sections[relocsIndex].VirtualAddress
        self.pe.OPTIONAL_HEADER.DATA_DIRECTORY[SuperPe.IMAGE_DIRECTORY_ENTRY_BASERELOC].Size += sizeOfReloc

        # VirtualAddress
        self.pe.set_dword_at_rva(addr + relocsSize, pageRva)

        # SizeOfBlock
        self.pe.set_dword_at_rva(addr + relocsSize + 4, sizeOfReloc)

        logger.info(f'Adding {len(relocs)} relocations for Page RVA 0x{pageRva:X} - size of block: 0x{sizeOfReloc:X}')
        i = 0
        for reloc in relocs:
            #reloc_offset = (reloc - pageRva)
            reloc_offset = reloc
            reloc_type = imageBaseRelocType << 12
            relocWord = (reloc_type | reloc_offset)

            #if reloc == 0:
            #     reloc_type = 0
            #     relocWord = 0
            #     reloc_offset = 0
            logger.info(f'\tReloc{i} for addr 0x{reloc:X}: 0x{relocWord:X} - 0x{reloc_offset:X} - type: {imageBaseRelocType}')
            self.pe.set_qword_at_rva(relocDirRva + relocsSize + 8 + i * 2, relocWord)
            #self.pe.set_qword_at_rva(relocDirRva + relocsSize + 8 + i * 2, reloc)
            i += 1


    def overwriteImageBaseRelocations(self, pageRva, relocs):
        assert pageRva > 0
        imageBaseRelocType = SuperPe.IMAGE_REL_BASED_DIR64

        addr = self.pe.OPTIONAL_HEADER.DATA_DIRECTORY[SuperPe.IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress
        print("Set at: 0x{:X} / 0x{:X}: 0x{:X}".format(
            addr, 
            self.pe.get_offset_from_rva(addr), 
            pageRva))
        self.pe.set_dword_at_rva(addr, pageRva)
        self.pe.set_bytes_at_offset(
            self.pe.get_offset_from_rva(addr + 4), 
            b'\x00' * 4
        )


    def mywrite(self, filename):
        file_data = bytearray(self.pe.__data__)
        f = open(filename, "wb+")
        f.write(file_data)
        f.close()


def main(filename: str, current_base: int):
    setup_logging(logging.DEBUG)
    print("Handling: {}".format(filename))
    superpe = SuperPe(filename)

    r = {}
    relocation: PeRelocEntry
    for relocation in superpe.get_base_relocs():
        if relocation.base_rva in r:
            r[relocation.base_rva] += 1
        else:
            r[relocation.base_rva] = 1

        #print("Base: 0x{:X}  RVA: 0x{:X}  Offset: {}  Type: {}".format(
        #    relocation.base_rva,
        #    relocation.rva,
        #    relocation.offset,
        #    relocation.type,
        #))

    #sum = 0
    #for base, count in r.items():
    #    print("0x{:X}: {}".format(base, count))
    #    sum += count
    #print("Sum: {}".format(sum))

    print("Image Base  : 0x{:X}".format(superpe.get_image_base()))
    print("Current Base: 0x{:X}".format(current_base))
    diff = current_base - superpe.get_image_base()
    print("Diff        : 0x{:X}".format(diff))

    code_section = superpe.get_code_section()
    print("Text section start: 0x{:X}  size: {}".format(
        code_section.VirtualAddress,
        code_section.SizeOfRawData
    ))

    if False:
        text_start = code_section.VirtualAddress
        text_end   = text_start + 4096 # 10000 # code_section.SizeOfRawData

        # entry point rva: E'1D78
        #            page: E'1000
        # jumps to: 00000001400E'21B0


        # Relocs show
        interval = 32
        page_vaddr = text_start
        relocs = []

        mypage = 0xE2000
        page_vaddr = mypage
        text_end = page_vaddr + 0x1000
        while page_vaddr < text_end:
            print("Relocations for page: 0x{:X}".format(
                page_vaddr
            ))

            i = 1
            while i < 4096:
                # data is 8 bytes (quad word)
                data = superpe.pe.get_qword_at_rva(page_vaddr + i)
                patch_data = data - diff
                if patch_data > 0:
                    print("  Relocation: 0x{:X}  0x{:X}  \tData: 0x{:X} \tPatched: 0x{:X}".format(
                        i+page_vaddr,
                        i,
                        data,
                        patch_data
                    ))
                    relocs.append(i)

                i += int(4096 / interval)
            page_vaddr += 4096
    else:
        mypage = 0x1000 #0x14B000
        relocs = [
            0x8, 
            0x16,
            #0,
        ]

        if False:
            superpe.addImageBaseRelocations(mypage, relocs)
            superpe.write_pe_to_file("tmp/myproc.exe")
            #superpe.overwriteImageBaseRelocations(mypage, relocs)
        else:
            #superpe.overwriteImageBaseRelocations(mypage, relocs)
            relocs = []
            entries_count = 0x8C
            step = int(4096/entries_count)

            page_vaddr = mypage
            text_end = page_vaddr + 0x1000
            while page_vaddr < text_end:
                print("Relocations for page: 0x{:X}".format(
                    page_vaddr
                ))

                i = 16
                while i < 4096:
                    # data is 8 bytes (quad word)
                    data = superpe.pe.get_qword_at_rva(page_vaddr + i)
                    patch_data = data - diff
                    if patch_data > 0:
                        print("  Relocation: 0x{:X}  0x{:X}  \tData: 0x{:X} \tPatched: 0x{:X}".format(
                            i+page_vaddr,
                            i,
                            data,
                            patch_data
                        ))
                        relocs.append(i)
                        superpe.pe.set_qword_at_rva(page_vaddr+i, patch_data)
                    else:
                        print("  SKIP Relocation: 0x{:X}  0x{:X}  \tData: 0x{:X} \tPatched: 0x{:X}".format(
                            i+page_vaddr,
                            i,
                            data,
                            patch_data
                        ))
                    i += step

                    if len(relocs) >= entries_count:
                        break
                page_vaddr += 4096

            print("Added relocs: 0x{:X}".format(len(relocs)))

            relocsSize = superpe.pe.OPTIONAL_HEADER.DATA_DIRECTORY[
                SuperPe.IMAGE_DIRECTORY_ENTRY_BASERELOC].Size
            relocsIndex = superpe.getSectionIndexByDataDir(
                SuperPe.IMAGE_DIRECTORY_ENTRY_BASERELOC)
            addr = superpe.pe.OPTIONAL_HEADER.DATA_DIRECTORY[
                SuperPe.IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress

            print("-> Relocs size: 0x{:X}  Index: {}  Addr: 0x{:X} = 0x{:X}".format(
                relocsSize, relocsIndex, addr, superpe.pe.get_offset_from_rva(addr)
            ))
            superpe.pe.set_dword_at_rva(addr, mypage)
            
            addr_entries = addr + 8
            i = 0
            for reloc in relocs:
                #reloc_offset = (reloc - pageRva)
                reloc_offset = reloc
                reloc_type = SuperPe.IMAGE_REL_BASED_DIR64 << 12
                relocWord = (reloc_type | reloc_offset)

                #if reloc == 0:
                #     reloc_type = 0
                #     relocWord = 0
                #     reloc_offset = 0
                logger.info(f'\tReloc{i} for addr 0x{reloc:X}: 0x{relocWord:X} - 0x{reloc_offset:X}')
                superpe.pe.set_word_at_rva(addr_entries + i * 2, relocWord)
                #self.pe.set_qword_at_rva(relocDirRva + relocsSize + 8 + i * 2, reloc)
                i += 1

            #superpe.pe.set_qword_at_rva(addr, 0x0011223344556677)
            #superpe.pe.set_qword_at_rva(0x11D00, 0x0011223344556677)
            #superpe.pe.set_dword_at_offset(0x11B600, 0x00112233)
            #superpe.pe.set_qword_at_rva(0x1000, 0x0011223344556677)  # works!

            if False:
                # print
                relocation: PeRelocEntry
                n = 0
                for base_reloc in superpe.pe.DIRECTORY_ENTRY_BASERELOC:
                    for entry in base_reloc.entries:
                        if n > 5:
                            break
                    
                        print("Base: 0x{:X}  RVA: 0x{:X}".format(
                            entry.base_rva,
                            entry.rva,
                        ))
                    
                        n += 1
    
            superpe.mywrite("tmp/myproc.exe")


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("./relokator <filename> <base>")
        exit(1)

    filename = sys.argv[1]
    current_base = int(sys.argv[2], 16)
    main(filename, current_base)

