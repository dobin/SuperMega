    for (int n=0; n<11223344; n++){
        dest[n] = supermega_payload[n];
        dest[n] = dest[n] ^ 0x42;
    }