#pragma OPENCL EXTENSION cl_khr_int64_base_atomics : enable

#define ROTL(x,n) (( (x) << (n) ) | ( (x) >> (32 - (n)) ))

void sha1_compute(const __global uchar *input, int len, __private uint *digest_out) {
    digest_out[0] = 0x67452301;
    digest_out[1] = 0xEFCDAB89;
    digest_out[2] = 0x98BADCFE;
    digest_out[3] = 0x10325476;
    digest_out[4] = 0xC3D2E1F0;


    uchar block[64];
    
    for (int i = 0; i < 64; ++i) block[i] = 0;


    for (int i = 0; i < len; ++i) block[i] = input[i];


    block[len] = (uchar)0x80;


    uint bit_len = (uint)(len * 8u);

    block[56] = 0;
    block[57] = 0;
    block[58] = 0;
    block[59] = 0;

    block[60] = (uchar)((bit_len >> 24) & 0xFF);
    block[61] = (uchar)((bit_len >> 16) & 0xFF);
    block[62] = (uchar)((bit_len >> 8) & 0xFF);
    block[63] = (uchar)((bit_len) & 0xFF);

    uint w[80];

    for (int i = 0; i < 16; ++i) {
        int j = i * 4;
        w[i] = ((uint)block[j] << 24) | ((uint)block[j+1] << 16) | ((uint)block[j+2] << 8) | ((uint)block[j+3]);
    }
    for (int i = 16; i < 80; ++i) {
        uint x = w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16];
        w[i] = ROTL(x, 1);
    }

    uint a = digest_out[0];
    uint b = digest_out[1];
    uint c = digest_out[2];
    uint d = digest_out[3];
    uint e = digest_out[4];

    for (int i = 0; i < 80; ++i) {
        uint f, k;
        if (i < 20) { f = (b & c) | ((~b) & d); k = 0x5A827999; }
        else if (i < 40) { f = b ^ c ^ d; k = 0x6ED9EBA1; }
        else if (i < 60) { f = (b & c) | (b & d) | (c & d); k = 0x8F1BBCDC; }
        else { f = b ^ c ^ d; k = 0xCA62C1D6; }

        uint temp = ROTL(a,5) + f + e + k + w[i];
        e = d; d = c; c = ROTL(b,30); b = a; a = temp;
    }

    digest_out[0] += a;
    digest_out[1] += b;
    digest_out[2] += c;
    digest_out[3] += d;
    digest_out[4] += e;
}


void digest_to_hex_sha1(const __private uint *digest, __private char *hex_out) {
    const char hex_chars[] = "0123456789abcdef";
    for (int w = 0; w < 5; ++w) {
        uint val = digest[w];

        for (int b = 0; b < 4; ++b) {
            uchar byte = (uchar)((val >> (24 - 8*b)) & 0xFF);
            hex_out[w*8 + b*2 + 0] = hex_chars[(byte >> 4) & 0xF];
            hex_out[w*8 + b*2 + 1] = hex_chars[byte & 0xF];
        }
    }
    hex_out[40] = '\0';
}


__kernel void crack(
    __global const char* words,        
    const int word_len,
    __global const char* target_hash,  
    __global int* result_index         
) {
    int gid = get_global_id(0);


    if (*result_index != -1) return;


    __global const uchar *words_u = (__global const uchar*)words;
    __global const uchar *cand = words_u + (size_t)gid * (size_t)word_len;


    int len = 0;
    for (int i = 0; i < word_len; ++i) {
        if (cand[i] == 0) break;
        ++len;
    }


    if (len >= 56) return;

    __private uint digest[5];
    sha1_compute(cand, len, digest);

    __private char hex[41];
    digest_to_hex_sha1(digest, hex);


    for (int i = 0; i < 40; ++i) {
        char t = target_hash[i];
        if (t >= 'A' && t <= 'Z') t = t + 32;
        if (hex[i] != t) return;
    }


    atomic_cmpxchg(result_index, -1, gid);
}

