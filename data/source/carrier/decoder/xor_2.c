        // Multibyte XOR (untested)
        // Need: key, key_len
        for ( int i = 0; i < {{PAYLOAD_LEN}}; i++ ) {
            dest[i] = supermega_payload[i] ^ key[i % key_len];
        }
