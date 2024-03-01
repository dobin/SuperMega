    for (int n=0; n<{{PAYLOAD_LEN}}; n++){
        dest[n] = supermega_payload[n];
        dest[n] = dest[n] ^ {{XOR_KEY}};
    }