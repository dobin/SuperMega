    // Multibyte XOR
    char *key = "{{XOR_KEY2}}";
    for ( int i = 0; i < {{PAYLOAD_LEN}}; i++ ) {
        dest[i] = supermega_payload[i] ^ key[i % 2];
    }
