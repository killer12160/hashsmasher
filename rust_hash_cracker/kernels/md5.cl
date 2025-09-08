#define F(x,y,z) ((x & y) | (~x & z))
#define G(x,y,z) ((x & z) | (y & ~z))
#define H(x,y,z) (x ^ y ^ z)
#define I(x,y,z) (y ^ (x | ~z))

#define ROTATE_LEFT(x, n) ((x << n) | (x >> (32 - n)))

__constant uint T[64] = {
  0xd76aa478,0xe8c7b756,0x242070db,0xc1bdceee,0xf57c0faf,0x4787c62a,0xa8304613,0xfd469501,
  0x698098d8,0x8b44f7af,0xffff5bb1,0x895cd7be,0x6b901122,0xfd987193,0xa679438e,0x49b40821,
  0xf61e2562,0xc040b340,0x265e5a51,0xe9b6c7aa,0xd62f105d,0x02441453,0xd8a1e681,0xe7d3fbc8,
  0x21e1cde6,0xc33707d6,0xf4d50d87,0x455a14ed,0xa9e3e905,0xfcefa3f8,0x676f02d9,0x8d2a4c8a,
  0xfffa3942,0x8771f681,0x6d9d6122,0xfde5380c,0xa4beea44,0x4bdecfa9,0xf6bb4b60,0xbebfbc70,
  0x289b7ec6,0xeaa127fa,0xd4ef3085,0x04881d05,0xd9d4d039,0xe6db99e5,0x1fa27cf8,0xc4ac5665,
  0xf4292244,0x432aff97,0xab9423a7,0xfc93a039,0x655b59c3,0x8f0ccc92,0xffeff47d,0x85845dd1,
  0x6fa87e4f,0xfe2ce6e0,0xa3014314,0x4e0811a1,0xf7537e82,0xbd3af235,0x2ad7d2bb,0xeb86d391
};


__constant int S[64] = {
     7,12,17,22, 7,12,17,22, 7,12,17,22, 7,12,17,22,
     5, 9,14,20, 5, 9,14,20, 5, 9,14,20, 5, 9,14,20,
     4,11,16,23, 4,11,16,23, 4,11,16,23, 4,11,16,23,
     6,10,15,21, 6,10,15,21, 6,10,15,21, 6,10,15,21
};

void md5(const __global uchar *input, int len, uint *digest) {
    uint a0=0x67452301, b0=0xefcdab89, c0=0x98badcfe, d0=0x10325476;

    uchar msg[64] = {0};
    for(int i=0;i<len;i++) msg[i] = input[i];
    msg[len] = 0x80;
    uint bit_len = len * 8;
    msg[56] = bit_len & 0xff;
    msg[57] = (bit_len >> 8) & 0xff;
    msg[58] = (bit_len >> 16) & 0xff;
    msg[59] = (bit_len >> 24) & 0xff;

    uint M[16];
    for(int i=0;i<16;i++) {
        M[i] = (uint)msg[i*4] | ((uint)msg[i*4+1]<<8) | ((uint)msg[i*4+2]<<16) | ((uint)msg[i*4+3]<<24);
    }

    uint A=a0,B=b0,C=c0,D=d0;
    for(int i=0;i<64;i++) {
        uint Fval,g;
        if(i<16){Fval=F(B,C,D);g=i;}
        else if(i<32){Fval=G(B,C,D);g=(5*i+1)%16;}
        else if(i<48){Fval=H(B,C,D);g=(3*i+5)%16;}
        else{Fval=I(B,C,D);g=(7*i)%16;}
        uint temp=D;
        D=C;
        C=B;
        B=B+ROTATE_LEFT(A+Fval+T[i]+M[g], S[i]);
        A=temp;
    }

    a0+=A; b0+=B; c0+=C; d0+=D;
    digest[0]=a0; digest[1]=b0; digest[2]=c0; digest[3]=d0;
}

void to_hex(uint *digest, char *hex_out) {
    const char hex_chars[]="0123456789abcdef";
    uchar *bytes=(uchar*)digest;
    for(int i=0;i<16;i++){
        hex_out[i*2]=hex_chars[(bytes[i]>>4)&0xF];
        hex_out[i*2+1]=hex_chars[bytes[i]&0xF];
    }
    hex_out[32]='\0';
}

__kernel void crack(
    __global const char* words,
    const int word_len,
    __global const char* target_hash,
    __global int* result_index
){
    int gid=get_global_id(0);
    if(*result_index!=-1) return;

    __global const char* cand=words+gid*word_len;
    int len=0; for(int i=0;i<word_len;i++){ if(cand[i]==0) break; len++; }

    uint digest[4]; md5((__global uchar*)cand,len,digest);

    char hex[33]; to_hex(digest,hex);

    bool match=true;
    for(int i=0;i<32;i++){
        char t=target_hash[i]; if(t>='A'&&t<='Z') t+=32;
        if(hex[i]!=t){match=false;break;}
    }
    if(match) atomic_cmpxchg(result_index,-1,gid);
}

