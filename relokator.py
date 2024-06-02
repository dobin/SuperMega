import sys

from model.defs import *
from pe.superpe import SuperPe


def main(filename: str, current_base: int):
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

    sum = 0
    for base, count in r.items():
        print("0x{:X}: {}".format(base, count))
        sum += count
    print("Sum: {}".format(sum))

    print("Image Base  : 0x{:X}".format(superpe.get_image_base()))
    print("Current Base: 0x{:X}".format(current_base))


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("./relokator <filename> <base>")
        exit(1)

    filename = sys.argv[1]
    current_base = int(sys.argv[2], 16)
    main(filename, current_base)

