import ctypes
from ctypes import wintypes

# Load necessary libraries
kernel32 = ctypes.WinDLL('kernel32')
psapi = ctypes.WinDLL('Psapi.dll')

# Define necessary structures and prototypes
class MODULEINFO(ctypes.Structure):
    _fields_ = [("lpBaseOfDll", wintypes.LPVOID),
                ("SizeOfImage", wintypes.DWORD),
                ("EntryPoint", wintypes.LPVOID)]

GetModuleInformation = psapi.GetModuleInformation
GetModuleInformation.argtypes = [wintypes.HANDLE, wintypes.HMODULE, ctypes.POINTER(MODULEINFO), wintypes.DWORD]
GetModuleInformation.restype = wintypes.BOOL

GetModuleHandle = kernel32.GetModuleHandleW
GetModuleHandle.argtypes = [wintypes.LPCWSTR]
GetModuleHandle.restype = wintypes.HMODULE

GetCurrentProcess = kernel32.GetCurrentProcess
GetCurrentProcess.argtypes = []
GetCurrentProcess.restype = wintypes.HANDLE

# Define function to read memory
def read_memory(address, size):
    buffer = ctypes.create_string_buffer(size)
    if kernel32.ReadProcessMemory(GetCurrentProcess(), address, buffer, size, None):
        return buffer.raw
    return None

# Get module handle and module information
module_handle = GetModuleHandle(None)  # None gets handle to the current module (the executable)
mi = MODULEINFO()
GetModuleInformation(GetCurrentProcess(), module_handle, ctypes.byref(mi), ctypes.sizeof(mi))

# Calculate the address of the PE header based on the DOS header at the base address
pe_header_offset = ctypes.c_int.from_buffer(read_memory(mi.lpBaseOfDll + 0x3C, 4)).value
pe_header_address = mi.lpBaseOfDll + pe_header_offset

# Read the PE header to find the .text section
nt_headers = read_memory(pe_header_address, 248)  # 248 bytes should include the OptionalHeader
optional_header_offset = 24
sections_offset = optional_header_offset + ctypes.c_ushort.from_buffer(nt_headers, 20).value
number_of_sections = ctypes.c_ushort.from_buffer(nt_headers, 6).value

# Loop through the section headers to find the .text section
for i in range(number_of_sections):
    section_header_address = pe_header_address + sections_offset + i * 40  # Each section header is 40 bytes
    section_header = read_memory(section_header_address, 40)
    name = section_header[:8].strip(b'\x00')
    if name == b'.text':
        text_virtual_address = ctypes.c_uint.from_buffer(section_header, 12).value
        text_section_address = mi.lpBaseOfDll + text_virtual_address
        print(f"Address of .text section: 0x{text_section_address:X}")
        break