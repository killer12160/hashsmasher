#pragma OPENCL EXTENSION cl_khr_byte_addressable_store : enable

#define ROTR(x,n) ((x >> n) | (x << (32 - n)))
#define CH(x,y,z) ((x & y) ^ (~x & z))
#define MAJ(x,y,z) ((x & y) ^ (x & z) ^ (y & z))
#define EP0(x) (ROTR(x,2) ^ ROTR(x,13) ^ ROTR(x,22))
#define EP1(x) (ROTR(x,6) ^ ROTR(x,11) ^ ROTR(x,25))
#define SIG0(x) (ROTR(x,7) ^ ROTR(x,18) ^ (x >> 3))
#define SIG1(x) (ROTR(x,17) ^ ROTR(x,19) ^ (x >> 10))

__constant uint k[64] = {
  0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
  0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
  0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
  0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
  0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
  0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
  0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
  0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

void sha256_compute(__global const uchar *input, int len, __private uint *h) {
    h[0]=0x6a09e667; h[1]=0xbb67ae85; h[2]=0x3c6ef372; h[3]=0xa54ff53a;
    h[4]=0x510e527f; h[5]=0x9b05688c; h[6]=0x1f83d9ab; h[7]=0x5be0cd19;

    uchar block[64];
    int cur = 0;
    for (int i = 0; i < len; ++i) block[cur++] = input[i];
    block[cur++] = 0x80;
    if (cur > 56) {
        while (cur < 64) block[cur++] = 0;

    }
    while (cur < 56) block[cur++] = 0;


    ulong bit_len = ((ulong)len) * 8ULL;
    block[56] = (uchar)((bit_len >> 56) & 0xFF);
    block[57] = (uchar)((bit_len >> 48) & 0xFF);
    block[58] = (uchar)((bit_len >> 40) & 0xFF);
    block[59] = (uchar)((bit_len >> 32) & 0xFF);
    block[60] = (uchar)((bit_len >> 24) & 0xFF);
    block[61] = (uchar)((bit_len >> 16) & 0xFF);
    block[62] = (uchar)((bit_len >> 8) & 0xFF);
    block[63] = (uchar)(bit_len & 0xFF);

    uint w[64];
    for (int i = 0, j = 0; i < 16; ++i, j += 4) {
        w[i] = ((uint)block[j] << 24) | ((uint)block[j+1] << 16) |
               ((uint)block[j+2] << 8) | ((uint)block[j+3]);
    }
    for (int i = 16; i < 64; ++i) {
        w[i] = SIG1(w[i-2]) + w[i-7] + SIG0(w[i-15]) + w[i-16];
    }

    uint a = h[0], b = h[1], c = h[2], d = h[3], e = h[4], f = h[5], g = h[6], hh = h[7];
    for (int i = 0; i < 64; ++i) {
        uint t1 = hh + EP1(e) + CH(e,f,g) + k[i] + w[i];
        uint t2 = EP0(a) + MAJ(a,b,c);
        hh = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
    }
    h[0] += a; h[1] += b; h[2] += c; h[3] += d;
    h[4] += e; h[5] += f; h[6] += g; h[7] += hh;
}

void digest_to_hex_sha256(__private const uint *h, __private char *hex_out) {
    const char hex_chars[] = "0123456789abcdef";
    for (int i = 0; i < 8; ++i) {
        uint v = h[i];
        for (int j = 0; j < 4; ++j) {
            uchar byte = (uchar)((v >> (24 - 8*j)) & 0xFF);
            hex_out[i*8 + j*2 + 0] = hex_chars[(byte >> 4) & 0xF];
            hex_out[i*8 + j*2 + 1] = hex_chars[byte & 0xF];
        }
    }
    hex_out[64] = '\0';
}

__kernel void crack(
    __global const char* words,
    const int word_len,
    __global const char* target_hash,
    __global int* result_index
) {
    int gid = get_global_id(0);
    if (*result_index != -1) return;

    __global const uchar *cand = ( __global const uchar*)(words + (size_t)gid * (size_t)word_len);
    int len = 0;
    for (int i = 0; i < word_len; ++i) {
        if (cand[i] == 0) break;
        ++len;
    }

    __private uint h[8];
    sha256_compute(cand, len, h);

    __private char hex[65];
    digest_to_hex_sha256(h, hex);

    bool match = true;
    for (int i = 0; i < 64; ++i) {
        char t = target_hash[i];
        if (t >= 'A' && t <= 'Z') t = t + 32;
        if (hex[i] != t) { match = false; break; }
    }
    if (match) atomic_cmpxchg(result_index, -1, gid);
}

