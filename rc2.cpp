#include "rc2.h"

void RC2_cbc_encrypt(const unsigned char *in, unsigned char *out, long length,
                     RC2_KEY *ks, unsigned char *iv, int encrypt)
{//register
    register unsigned long tin0,tin1;
    register unsigned long tout0,tout1,xor0,xor1;
     long l=length;
    unsigned long tin[2];

    if (encrypt)
    {
        c2l(iv,tout0);
        c2l(iv,tout1);
        iv-=8;
        for (l-=8; l>=0; l-=8)
        {
            if( l == 65528 )
            {
                tin0 = 0;
            }
            if( l == 65536 )
            {
                tin0 = 0;
            }

            c2l(in,tin0);
            c2l(in,tin1);
            tin0^=tout0;
            tin1^=tout1;
            tin[0]=tin0;
            tin[1]=tin1;
            RC2_encrypt(tin,ks);
            tout0=tin[0]; l2c(tout0,out);
            tout1=tin[1]; l2c(tout1,out);
        }
        if (l != -8)
        {
            c2ln(in,tin0,tin1,l+8);
            tin0^=tout0;
            tin1^=tout1;
            tin[0]=tin0;
            tin[1]=tin1;
            RC2_encrypt(tin,ks);
            tout0=tin[0]; l2c(tout0,out);
            tout1=tin[1]; l2c(tout1,out);
        }
        l2c(tout0,iv);
        l2c(tout1,iv);
    }
    else
    {
        c2l(iv,xor0);
        c2l(iv,xor1);
        iv-=8;
        for (l-=8; l>=0; l-=8)
        {
            c2l(in,tin0); tin[0]=tin0;
            c2l(in,tin1); tin[1]=tin1;
            RC2_decrypt(tin,ks);
            tout0=tin[0]^xor0;
            tout1=tin[1]^xor1;
            l2c(tout0,out);
            l2c(tout1,out);
            xor0=tin0;
            xor1=tin1;
        }
        if (l != -8)
        {
            c2l(in,tin0); tin[0]=tin0;
            c2l(in,tin1); tin[1]=tin1;
            RC2_decrypt(tin,ks);
            tout0=tin[0]^xor0;
            tout1=tin[1]^xor1;
            l2cn(tout0,tout1,out,l+8);
            xor0=tin0;
            xor1=tin1;
        }
        l2c(xor0,iv);
        l2c(xor1,iv);
    }
    tin0=tin1=tout0=tout1=xor0=xor1=0;
    tin[0]=tin[1]=0;
}

void RC2_encrypt(unsigned long *d, RC2_KEY *key)
{
    int i,n;
     RC2_INT *p0,*p1;
     RC2_INT x0,x1,x2,x3,t;
    unsigned long l;

    l=d[0];
    x0=(RC2_INT)l&0xffff;
    x1=(RC2_INT)(l>>16L);
    l=d[1];
    x2=(RC2_INT)l&0xffff;
    x3=(RC2_INT)(l>>16L);

    n=3;
    i=5;

    p0=p1= &(key->data[0]);
    for (;;)
    {
        t=(x0+(x1& ~x3)+(x2&x3)+ *(p0++))&0xffff;
        x0=(t<<1)|(t>>15);
        t=(x1+(x2& ~x0)+(x3&x0)+ *(p0++))&0xffff;
        x1=(t<<2)|(t>>14);
        t=(x2+(x3& ~x1)+(x0&x1)+ *(p0++))&0xffff;
        x2=(t<<3)|(t>>13);
        t=(x3+(x0& ~x2)+(x1&x2)+ *(p0++))&0xffff;
        x3=(t<<5)|(t>>11);

        if (--i == 0)
        {
            if (--n == 0) break;
            i=(n == 2)?6:5;

            x0+=p1[x3&0x3f];
            x1+=p1[x0&0x3f];
            x2+=p1[x1&0x3f];
            x3+=p1[x2&0x3f];
        }
    }

    d[0]=(unsigned long)(x0&0xffff)|((unsigned long)(x1&0xffff)<<16L);
    d[1]=(unsigned long)(x2&0xffff)|((unsigned long)(x3&0xffff)<<16L);
}

void RC2_decrypt(unsigned long *d, RC2_KEY *key)
{
    int i,n;
    register RC2_INT *p0,*p1;
    register RC2_INT x0,x1,x2,x3,t;
    unsigned long l;

    l=d[0];
    x0=(RC2_INT)l&0xffff;
    x1=(RC2_INT)(l>>16L);
    l=d[1];
    x2=(RC2_INT)l&0xffff;
    x3=(RC2_INT)(l>>16L);

    n=3;
    i=5;

    p0= &(key->data[63]);
    p1= &(key->data[0]);
    for (;;)
    {
        t=((x3<<11)|(x3>>5))&0xffff;
        x3=(t-(x0& ~x2)-(x1&x2)- *(p0--))&0xffff;
        t=((x2<<13)|(x2>>3))&0xffff;
        x2=(t-(x3& ~x1)-(x0&x1)- *(p0--))&0xffff;
        t=((x1<<14)|(x1>>2))&0xffff;
        x1=(t-(x2& ~x0)-(x3&x0)- *(p0--))&0xffff;
        t=((x0<<15)|(x0>>1))&0xffff;
        x0=(t-(x1& ~x3)-(x2&x3)- *(p0--))&0xffff;

        if (--i == 0)
        {
            if (--n == 0) break;
            i=(n == 2)?6:5;

            x3=(x3-p1[x2&0x3f])&0xffff;
            x2=(x2-p1[x1&0x3f])&0xffff;
            x1=(x1-p1[x0&0x3f])&0xffff;
            x0=(x0-p1[x3&0x3f])&0xffff;
        }
    }

    d[0]=(unsigned long)(x0&0xffff)|((unsigned long)(x1&0xffff)<<16L);
    d[1]=(unsigned long)(x2&0xffff)|((unsigned long)(x3&0xffff)<<16L);
}



void RC2_ecb_encrypt(const unsigned char *in, unsigned char *out, RC2_KEY *ks,
                     int encrypt)
{
    unsigned long l,d[2];

    c2l(in,l); d[0]=l;
    c2l(in,l); d[1]=l;
    if (encrypt)
        RC2_encrypt(d,ks);
    else
        RC2_decrypt(d,ks);
    l=d[0]; l2c(l,out);
    l=d[1]; l2c(l,out);
    l=d[0]=d[1]=0;
}


static unsigned char key_table[256]={
    0xd9,0x78,0xf9,0xc4,0x19,0xdd,0xb5,0xed,0x28,0xe9,0xfd,0x79,
    0x4a,0xa0,0xd8,0x9d,0xc6,0x7e,0x37,0x83,0x2b,0x76,0x53,0x8e,
    0x62,0x4c,0x64,0x88,0x44,0x8b,0xfb,0xa2,0x17,0x9a,0x59,0xf5,
    0x87,0xb3,0x4f,0x13,0x61,0x45,0x6d,0x8d,0x09,0x81,0x7d,0x32,
    0xbd,0x8f,0x40,0xeb,0x86,0xb7,0x7b,0x0b,0xf0,0x95,0x21,0x22,
    0x5c,0x6b,0x4e,0x82,0x54,0xd6,0x65,0x93,0xce,0x60,0xb2,0x1c,
    0x73,0x56,0xc0,0x14,0xa7,0x8c,0xf1,0xdc,0x12,0x75,0xca,0x1f,
    0x3b,0xbe,0xe4,0xd1,0x42,0x3d,0xd4,0x30,0xa3,0x3c,0xb6,0x26,
    0x6f,0xbf,0x0e,0xda,0x46,0x69,0x07,0x57,0x27,0xf2,0x1d,0x9b,
    0xbc,0x94,0x43,0x03,0xf8,0x11,0xc7,0xf6,0x90,0xef,0x3e,0xe7,
    0x06,0xc3,0xd5,0x2f,0xc8,0x66,0x1e,0xd7,0x08,0xe8,0xea,0xde,
    0x80,0x52,0xee,0xf7,0x84,0xaa,0x72,0xac,0x35,0x4d,0x6a,0x2a,
    0x96,0x1a,0xd2,0x71,0x5a,0x15,0x49,0x74,0x4b,0x9f,0xd0,0x5e,
    0x04,0x18,0xa4,0xec,0xc2,0xe0,0x41,0x6e,0x0f,0x51,0xcb,0xcc,
    0x24,0x91,0xaf,0x50,0xa1,0xf4,0x70,0x39,0x99,0x7c,0x3a,0x85,
    0x23,0xb8,0xb4,0x7a,0xfc,0x02,0x36,0x5b,0x25,0x55,0x97,0x31,
    0x2d,0x5d,0xfa,0x98,0xe3,0x8a,0x92,0xae,0x05,0xdf,0x29,0x10,
    0x67,0x6c,0xba,0xc9,0xd3,0x00,0xe6,0xcf,0xe1,0x9e,0xa8,0x2c,
    0x63,0x16,0x01,0x3f,0x58,0xe2,0x89,0xa9,0x0d,0x38,0x34,0x1b,
    0xab,0x33,0xff,0xb0,0xbb,0x48,0x0c,0x5f,0xb9,0xb1,0xcd,0x2e,
    0xc5,0xf3,0xdb,0x47,0xe5,0xa5,0x9c,0x77,0x0a,0xa6,0x20,0x68,
    0xfe,0x7f,0xc1,0xad,
};


void RC2_set_key(RC2_KEY *key, int len, const unsigned char *data, int bits)
{
    int i,j;
    unsigned char *k;
    RC2_INT *ki;
    unsigned int c,d;

    k= (unsigned char *)&(key->data[0]);
    *k=0; /* for if there is a zero length key */

    if (len > 128) len=128;
    if (bits <= 0) bits=1024;
    if (bits > 1024) bits=1024;

    for (i=0; i<len; i++)
        k[i]=data[i];

    /* expand table */
    d=k[len-1];
    j=0;
    for (i=len; i < 128; i++,j++)
    {
        d=key_table[(k[j]+d)&0xff];
        k[i]=d;
    }

    /* hmm.... key reduction to 'bits' bits */

    j=(bits+7)>>3;
    i=128-j;
    c= (0xff>>(-bits & 0x07));

    d=key_table[k[i]&c];
    k[i]=d;
    while (i--)
    {
        d=key_table[k[i+j]^d];
        k[i]=d;
    }

    /* copy from bytes into RC2_INT's */
    ki= &(key->data[63]);
    for (i=127; i>=0; i-=2)
        *(ki--)=((k[i]<<8)|k[i-1])&0xffff;
}

