import sys
import pefile


def extract_iat(pe):
    iat = {}

    # If the PE file was loaded using the fast_load=True argument, we will need to parse the data directories:
    #pe.parse_data_directories()

    # Retrieve the IAT entries from the PE file
    for entry in pe.DIRECTORY_ENTRY_IMPORT:
        for imp in entry.imports:
            dll_name = entry.dll.decode('utf-8')
            imp_name = imp.name.decode('utf-8')
            imp_addr = imp.address

            #print("{}  {} - 0x{:08X}".format(
            #    dll_name,
            #    imp_name,
            #    imp_addr
            #))

            if not dll_name in iat:
                 iat[dll_name] = []

            iat[dll_name].append({
                 "dll_name": dll_name,
                 "func_name": imp_name,
                 "func_addr": imp_addr
            })
    
    return iat


def get_addr_for(iat, func_name):
    for dll_name in iat:
        for entry in iat[dll_name]:
            if entry["func_name"] == func_name:
                return entry["func_addr"]
    return None


def resolve_iat_capabilities(needed_capabilities, inject_exe):
    pe = pefile.PE(inject_exe)
    iat = extract_iat(pe) 

    print("IAT: ")
    for cap in needed_capabilities:
         needed_capabilities[cap] = get_addr_for(iat, cap)
         print("  {}: {}".format(cap, needed_capabilities[cap]))
         


def main():
        pe = pefile.PE(sys.argv[1])
        iat = extract_iat(pe)


if __name__ == "__main__":
    main()