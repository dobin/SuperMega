# Your input string of escaped hex bytes
#escaped_hex_bytes = "\\x31\\xc0\\x31\\xc9\\x64\\x8b\\x71\\x30\\x8b\\x76\\x0c\\x8b\\x76\\x1c\\x8b\\x56\\x08\\x8b\\x7e\\x20"

import sys

infile = sys.argv[1]
output_file_name = sys.argv[2]

with open(infile, "r") as f:
    escaped_hex_bytes = f.read()
    escaped_hex_bytes = escaped_hex_bytes.replace('\n', '')
    escaped_hex_bytes = escaped_hex_bytes.replace('\\x', '')

print(escaped_hex_bytes)


# Convert the string with escaped hex bytes to actual binary data
binary_data = bytes.fromhex(escaped_hex_bytes)

# Write the binary data to a file
with open(output_file_name, "wb") as binary_file:
    binary_file.write(binary_data)

print(f"Binary file created: {output_file_name}")