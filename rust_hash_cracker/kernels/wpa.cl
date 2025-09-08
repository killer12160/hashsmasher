#define SHA1_BLOCK_SIZE 64
#define SHA1_DIGEST_SIZE 20
#define PBKDF2_ITERS 4096


#define ROL32(a, n) (((a) << (n)) | ((a) >> (32 - (n))))


#define F0(b,c,d) (((b) & (c)) | ((~b) & (d)))
#define F1(b,c,d) ((b) ^ (c) ^ (d))
#define F2(b,c,d) (((b) & (c)) | ((b) & (d)) | ((c) & (d)))
#define F3(b,c,d) ((b) ^ (c) ^ (d))

inline void sha1_transform(uint *state, const uchar *block) {
    uint w[80];
    for (int i = 0; i < 16; i++) {
        w[i] = ((uint)block[i*4] << 24) |
               ((uint)block[i*4+1] << 16) |
               ((uint)block[i*4+2] << 8) |
               ((uint)block[i*4+3]);
    }
    for (int i = 16; i < 80; i++) {
        w[i] = ROL32(w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16], 1);
    }

    uint a=state[0], b=state[1], c=state[2], d=state[3], e=state[4];
    for (int i = 0; i < 80; i++) {
        uint f, k;
        if (i < 20) { f = F0(b,c,d); k = 0x5A827999; }
        else if (i < 40) { f = F1(b,c,d); k = 0x6ED9EBA1; }
        else if (i < 60) { f = F2(b,c,d); k = 0x8F1BBCDC; }
        else { f = F3(b,c,d); k = 0xCA62C1D6; }
        uint temp = ROL32(a,5) + f + e + k + w[i];
        e = d; d = c; c = ROL32(b,30); b = a; a = temp;
    }
    state[0] += a; state[1] += b; state[2] += c;
    state[3] += d; state[4] += e;
}

inline void sha1(const uchar *msg, int len, uint *digest) {
    digest[0] = 0x67452301;
    digest[1] = 0xEFCDAB89;
    digest[2] = 0x98BADCFE;
    digest[3] = 0x10325476;
    digest[4] = 0xC3D2E1F0;

    uchar block[64];
    int i;
    for (i=0; i+64 <= len; i+=64) {
        sha1_transform(digest, msg+i);
    }

    int rem = len - i;
    for (int j=0;j<64;j++) block[j]=0;
    for (int j=0;j<rem;j++) block[j]=msg[i+j];
    block[rem]=0x80;
    if (rem >= 56) {
        sha1_transform(digest, block);
        for (int j=0;j<64;j++) block[j]=0;
    }
    ulong bitlen = (ulong)len * 8;
    for (int j=0;j<8;j++) block[63-j] = (uchar)(bitlen>>(8*j));
    sha1_transform(digest, block);
}

inline void hmac_sha1(const uchar *key, int keylen, const uchar *msg, int msglen, uint *digest) {
    uchar k_ipad[64], k_opad[64];
    uchar tk[20];

    if (keylen > 64) {
        sha1(key, keylen, digest);
        for(int i=0;i<20;i++) ((uchar*)tk)[i] = ((uchar*)digest)[i];
        key = (uchar*)tk;
        keylen = 20;
    }

    for (int i=0;i<64;i++) {
        k_ipad[i] = (i<keylen)? key[i] ^ 0x36 : 0x36;
        k_opad[i] = (i<keylen)? key[i] ^ 0x5c : 0x5c;
    }

    uchar temp[64+msglen];
    for(int i=0;i<64;i++) temp[i]=k_ipad[i];
    for(int i=0;i<msglen;i++) temp[64+i]=msg[i];
    sha1(temp,64+msglen,digest);

    uchar temp2[64+20];
    for(int i=0;i<64;i++) temp2[i]=k_opad[i];
    for(int i=0;i<20;i++) temp2[64+i]=((uchar*)digest)[i];
    sha1(temp2,64+20,digest);
}

inline void pbkdf2_sha1(const uchar *pass, int passlen, const uchar *ssid, int ssidlen, int iter, uint *output) {
    uint digest[5];
    uchar salt[ssidlen+4];
    for(int i=0;i<ssidlen;i++) salt[i]=ssid[i];
    salt[ssidlen]=0; salt[ssidlen+1]=0; salt[ssidlen+2]=0; salt[ssidlen+3]=1;

    hmac_sha1(pass,passlen,salt,ssidlen+4,digest);
    uint U[5]; for(int i=0;i<5;i++) U[i]=digest[i];
    for(int i=1;i<iter;i++) {
        hmac_sha1(pass,passlen,(uchar*)U,20,digest);
        for(int j=0;j<5;j++) U[j]^=digest[j];
    }
    for(int i=0;i<5;i++) output[i]=U[i];
}

__kernel void wpa_crack(
    __global const char* words,
    const int word_len,
    __global const char* target_hash,
    __global int* result_index
) {
    int gid=get_global_id(0);
    if(*result_index!=-1) return;

    __global const char* cand=words+gid*word_len;
    int len=0; for(int i=0;i<word_len;i++){ if(cand[i]==0) break; len++; }


    uchar ssid[4]={'t','e','s','t'};

    uint pmk[5];
    pbkdf2_sha1((__global uchar*)cand,len,ssid,4,PBKDF2_ITERS,pmk);


    char hex[41]; const char hexchars[]="0123456789abcdef";
    uchar *bytes=(uchar*)pmk;
    for(int i=0;i<20;i++){
        hex[i*2]=hexchars[(bytes[i]>>4)&0xF];
        hex[i*2+1]=hexchars[bytes[i]&0xF];
    }
    hex[40]=0;

    bool match=true;
    for(int i=0;i<32;i++){ 
        char t=target_hash[i]; if(t>='A'&&t<='Z') t+=32;
        if(hex[i]!=t){match=false;break;}
    }
    if(match) atomic_cmpxchg(result_index,-1,gid);
}

