import os
from typing import List, Dict

from helper import *
from model.carrier import Carrier, DataReuseEntry, IatRequest
from model.settings import Settings

logger = logging.getLogger("AsmTextParser")


def parse_asm_text_file(carrier: Carrier, asm_text: str, settings: Settings) -> List[str]:
    lines_out = []
    lines = asm_text.split("\n")

    current_segment = None
    current_datareuse_entry= None
    line_idx = -1
    for line in lines:
        line = line.rstrip()
        line_idx += 1
        tokens = line.split()

        # skip irrelevant
        #if not tokens:
        #    lines_out.append(line)
        #    continue
        if len(tokens) <= 1:
            lines_out.append(line)
            continue 

        # TRACK in which segment we currently are
        if tokens[1] == "SEGMENT":
            current_segment = tokens[0]
            lines_out.append(line)
            continue

        if tokens[0] == "COMM":
            # HACK atm. Will be handled by masm_shc
            # gives false positives for supermega_payload
            continue

        # PATCH SHORT
        if "jmp\tSHORT" in line:
            updated_line = line.replace("SHORT", "")
            lines_out.append(updated_line)
            continue

        # REMOVE EXTRN, we dont need it
        ## EXTRN	__imp_GetEnvironmentVariableW:PROC
        ## to
        ## ; EXTRN	__imp_GetEnvironmentVariableW:PROC
        if tokens[0] == "EXTRN":
            updated_line = "; " + line + "; Removed"
            lines_out.append(updated_line)
            continue

        # PATCH external shellcode reference
        ## mov	rdi, QWORD PTR supermega_payload
        ## to
        ## lea  rdi, XXX
        if "supermega_payload" in line:
            string_ref = "supermega_payload"

            # should already exist (added before)
            datareuse_fixup = carrier.get_reusedata_fixup(string_ref)
            if datareuse_fixup == None:
                raise Exception("Data reuse entry not found: {}".format(string_ref))

            # add a reference
            placeholder: bytes = os.urandom(7)  # LEA is 7 bytes
            register = line.split("mov\t")[1].split(",")[0]
            datareuse_fixup.add_reference(placeholder, register)

            # add lines
            line = bytes_to_asm_db(placeholder) + " ; supermega_payload Payload".format()
            lines_out.append(line)
            continue

        # COLLECT AND PATCH all functions that need to be resolved in loader shellcode
        # we replace the function call invocation with a random byte sequence
        ## call	QWORD PTR __imp_GetEnvironmentVariableW
        ## to
        ## DB 07cH, 04cH, 028H, 0b0H, 006H, 07eH ; IAT Reuse for GetEnvironmentVariableW
        if "QWORD PTR __imp_" in line:
            # just the function name, without __imp_
            func_name = line[line.find("__imp_")+6:].rstrip()
            placeholder: bytes = os.urandom(6)  # exact size or the result
            carrier.add_iat_request(func_name, placeholder)
            
            new_line = bytes_to_asm_db(placeholder) + " ; IAT Reuse for {}".format(func_name)
            lines_out.append(new_line)
            continue

        # COLLECT data strings
        # these are usually multi-line, and at the beginning of the file
        # $SG72513 DB	'U', 00H, 'S', 00H, 'E', 00H, 'R', 00H, 'P', 00H, 'R', 00H
        #          DB	'O', 00H, 'F', 00H, 'I', 00H, 'L', 00H, 'E', 00H, 00H, 00H
        if line.startswith("$SG"):
            # fuck me. if we start a new definition, and have an old one, add the old one...
            if current_datareuse_entry != None:
                carrier.add_datareuse_fixup(current_datareuse_entry)
                current_datareuse_entry = None  # reset it here

            var_name = tokens[0]
            data = convert_asm_db_to_bytes(line[line.index("DB"):])
            current_datareuse_entry = DataReuseEntry(var_name)
            current_datareuse_entry.data = data
            lines_out.append("; " + line)
            continue
        if line.startswith("\tDB"):
            if current_datareuse_entry == None:
                raise("Found DB without $SG, corrupted asm file?")
            current_datareuse_entry.data += convert_asm_db_to_bytes(line)
            lines_out.append("; " + line)
            continue
        if current_datareuse_entry != None:
            # when we reach here, $SG with its DB should be done.
            carrier.add_datareuse_fixup(current_datareuse_entry)
            current_datareuse_entry = None  # reset it here

        # PATCH data reuse code (data from C)
        # put $SGxxxxxx into .rdata section
        ## lea	rcx, OFFSET FLAT:$SG72751
        ## to
        ## DB 07cH, 04cH, 028H, 0b0H, 006H, 07eH ; IAT Reuse for GetEnvironmentVariableW
        if "OFFSET FLAT:$SG" in line:
            string_ref = line.split("OFFSET FLAT:")[1]
            datareuse_fixup = carrier.get_reusedata_fixup(string_ref)
            if datareuse_fixup == None:
                raise("Data reuse entry not found: {}".format(string_ref))

            register = line.split("lea\t")[1].split(",")[0]
            placeholder: bytes = os.urandom(7)
            datareuse_fixup.add_reference(placeholder, register)

            line = bytes_to_asm_db(placeholder) + " ; .rdata Reuse for {} ({})".format(
                string_ref, register)
            lines_out.append(line)
            continue
        
        lines_out.append(line)

    return lines_out


def convert_asm_db_to_bytes(line: str) -> bytes:
    value = b''
    parts = line.split()
    for part in parts:
        if part.startswith('\''):
            value += str.encode(part.split('\'')[1])
        elif part.endswith('H') or part.endswith('H,'):
            hex = part.split('H')[0]
            if len(hex) == 3:
                # 09cH,
                hex = hex[1:]
            value += bytes.fromhex(hex)
    return value


def bytes_to_asm_db(byte_data: bytes) -> bytes:
    # Convert each byte to a string in hexadecimal format 
    # prefixed with '0' and suffixed with 'h'
    hex_values = [f"0{byte:02x}H" for byte in byte_data]
    formatted_string = ', '.join(hex_values)
    return "\tDB " + formatted_string
