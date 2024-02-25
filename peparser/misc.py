

def get_physical_address(pe, virtual_address):
    # Iterate through the section headers to find which section contains the VA
    for section in pe.sections:
        # Check if the VA is within the range of this section
        if section.VirtualAddress <= virtual_address < section.VirtualAddress + section.Misc_VirtualSize:
            # Calculate the difference between the VA and the section's virtual address
            virtual_offset = virtual_address - section.VirtualAddress
            # Add the difference to the section's pointer to raw data
            return virtual_offset
            #physical_address = section.PointerToRawData + virtual_offset
            #return physical_address
    return None
