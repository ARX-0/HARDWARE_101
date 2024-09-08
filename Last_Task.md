![image](https://github.com/user-attachments/assets/d083c5ff-f43c-4dee-b8d8-5221a5f39a45)

![image](https://github.com/user-attachments/assets/232c9e93-dbf7-4f54-a448-2579b48c8a7c)

![image](https://github.com/user-attachments/assets/8b73e83e-79ac-4505-8329-450cb98d2883)

![image](https://github.com/user-attachments/assets/3fb684d7-144f-41cd-8f4c-cea24b6bafb5)

![image](https://github.com/user-attachments/assets/66eee1b5-2745-46dc-90e0-15188f1455b2)

![image](https://github.com/user-attachments/assets/5f3cacae-9f03-4072-aebd-7ab48954d5e0)

# Here we are going to replicate our first opensource acclerator (welcome to function accleration and Vitis HLS design flow)

here i aim to teach you the HLS design flow and not the actual Cpp and the #pragma directories used in that so feel free to clt+c and clt+v the below code 
Right click on the "Source" and choose "New source file" 

![image](https://github.com/user-attachments/assets/5f64f814-2800-4dc1-bc6c-366326339e6e)
 
````
/*********************************************************************
* Filename:   sha256.h
* Author:     Brad Conte (brad AT bradconte.com)
* Copyright:
* Disclaimer: This code is presented "as is" without any guarantees.
* Details:    Defines the API for the corresponding SHA1 implementation.
*********************************************************************/

#ifndef SHA256_H
#define SHA256_H

/*************************** HEADER FILES ***************************/
#include <stddef.h>

/****************************** MACROS ******************************/
#define SHA256_BLOCK_SIZE 32            // SHA256 outputs a 32 byte digest

/**************************** DATA TYPES ****************************/
typedef unsigned char BYTE;             // 8-bit byte
typedef unsigned int  WORD;             // 32-bit word, change to "long" for 16-bit machines

typedef struct {
	BYTE data[64];
	WORD datalen;
	unsigned long long bitlen;
	WORD state[8];
} SHA256_CTX;

/*********************** FUNCTION DECLARATIONS **********************/
void sha256_init(SHA256_CTX *ctx);
void sha256_update(SHA256_CTX *ctx, const BYTE data[], size_t len);
void sha256_final(SHA256_CTX *ctx, BYTE hash[]);

#endif   // SHA256_H


/*************************** HEADER FILES ***************************/
#include <string.h>
#include <stdlib.h>
#include <memory.h>
//#include "sha256.h"

/****************************** MACROS ******************************/
#define ROTLEFT(a,b) (((a) << (b)) | ((a) >> (32-(b))))
#define ROTRIGHT(a,b) (((a) >> (b)) | ((a) << (32-(b))))

#define CH(x,y,z) (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x,y,z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define EP0(x) (ROTRIGHT(x,2) ^ ROTRIGHT(x,13) ^ ROTRIGHT(x,22))
#define EP1(x) (ROTRIGHT(x,6) ^ ROTRIGHT(x,11) ^ ROTRIGHT(x,25))
#define SIG0(x) (ROTRIGHT(x,7) ^ ROTRIGHT(x,18) ^ ((x) >> 3))
#define SIG1(x) (ROTRIGHT(x,17) ^ ROTRIGHT(x,19) ^ ((x) >> 10))

/**************************** VARIABLES *****************************/
static const WORD k[64] = {
	0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
	0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
	0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
	0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
	0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
	0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
	0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
	0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

/*********************** FUNCTION DEFINITIONS ***********************/
void sha256_transform(SHA256_CTX *ctx, const BYTE data[])
{
	WORD a, b, c, d, e, f, g, h, i, j, t1, t2, m[64];

	for (i = 0, j = 0; i < 16; ++i, j += 4)
		m[i] = (data[j] << 24) | (data[j + 1] << 16) | (data[j + 2] << 8) | (data[j + 3]);
	for ( ; i < 64; ++i)
		m[i] = SIG1(m[i - 2]) + m[i - 7] + SIG0(m[i - 15]) + m[i - 16];

	a = ctx->state[0];
	b = ctx->state[1];
	c = ctx->state[2];
	d = ctx->state[3];
	e = ctx->state[4];
	f = ctx->state[5];
	g = ctx->state[6];
	h = ctx->state[7];

	for (i = 0; i < 64; ++i) {
		t1 = h + EP1(e) + CH(e,f,g) + k[i] + m[i];
		t2 = EP0(a) + MAJ(a,b,c);
		h = g;
		g = f;
		f = e;
		e = d + t1;
		d = c;
		c = b;
		b = a;
		a = t1 + t2;
	}

	ctx->state[0] += a;
	ctx->state[1] += b;
	ctx->state[2] += c;
	ctx->state[3] += d;
	ctx->state[4] += e;
	ctx->state[5] += f;
	ctx->state[6] += g;
	ctx->state[7] += h;
}

void sha256_init(SHA256_CTX *ctx)
{
	ctx->datalen = 0;
	ctx->bitlen = 0;
	ctx->state[0] = 0x6a09e667;
	ctx->state[1] = 0xbb67ae85;
	ctx->state[2] = 0x3c6ef372;
	ctx->state[3] = 0xa54ff53a;
	ctx->state[4] = 0x510e527f;
	ctx->state[5] = 0x9b05688c;
	ctx->state[6] = 0x1f83d9ab;
	ctx->state[7] = 0x5be0cd19;
}

void sha256_update(SHA256_CTX *ctx, const BYTE data[], size_t len)
{
	WORD i;

	for (i = 0; i < len; ++i) {
		ctx->data[ctx->datalen] = data[i];
		ctx->datalen++;
		if (ctx->datalen == 64) {
			sha256_transform(ctx, ctx->data);
			ctx->bitlen += 512;
			ctx->datalen = 0;
		}
	}
}

void sha256_final(SHA256_CTX *ctx, BYTE hash[])
{
	WORD i;

	i = ctx->datalen;

	// Pad whatever data is left in the buffer.
	if (ctx->datalen < 56) {
		ctx->data[i++] = 0x80;
		while (i < 56)
			ctx->data[i++] = 0x00;
	}
	else {
		ctx->data[i++] = 0x80;
		while (i < 64)
			ctx->data[i++] = 0x00;
		sha256_transform(ctx, ctx->data);
		memset(ctx->data, 0, 56);
	}

	// Append to the padding the total message's length in bits and transform.
	ctx->bitlen += ctx->datalen * 8;
	ctx->data[63] = ctx->bitlen;
	ctx->data[62] = ctx->bitlen >> 8;
	ctx->data[61] = ctx->bitlen >> 16;
	ctx->data[60] = ctx->bitlen >> 24;
	ctx->data[59] = ctx->bitlen >> 32;
	ctx->data[58] = ctx->bitlen >> 40;
	ctx->data[57] = ctx->bitlen >> 48;
	ctx->data[56] = ctx->bitlen >> 56;
	sha256_transform(ctx, ctx->data);

	// Since this implementation uses little endian byte ordering and SHA uses big endian,
	// reverse all the bytes when copying the final state to the output hash.
	for (i = 0; i < 4; ++i) {
		hash[i]      = (ctx->state[0] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 4]  = (ctx->state[1] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 8]  = (ctx->state[2] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 12] = (ctx->state[3] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 16] = (ctx->state[4] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 20] = (ctx->state[5] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 24] = (ctx->state[6] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 28] = (ctx->state[7] >> (24 - i * 8)) & 0x000000ff;
	}
}

/*************************** HLS Code ***************************/

int hash(int text_length, BYTE text_input[1024], BYTE result[SHA256_BLOCK_SIZE]) {
#pragma HLS INTERFACE s_axilite port=text_length
#pragma HLS INTERFACE m_axi depth=1024 port=text_input
#pragma HLS INTERFACE s_axilite port=result
#pragma HLS INTERFACE s_axilite port=return

	SHA256_CTX ctx;
	sha256_init(&ctx);
	sha256_update(&ctx, text_input, text_length);
	sha256_final(&ctx, result);

	return true;
}

````

this is the only part of code that you doing HLS need to type in to make it work :)  (that's what i did)

![image](https://github.com/user-attachments/assets/10e137ac-2bc2-4623-9d50-5b9bb759695c)

well now copy paste this code in your ide

hit run synthesis and you will get an error

![image](https://github.com/user-attachments/assets/6e643a33-58a6-4873-b0f6-6b5cc194d280)

fix that error by yourself or contact me 

### HINT

![IMG20240908095447](https://github.com/user-attachments/assets/5daab779-ca97-4ed9-9b77-6a6f76e498c4)

## Lets look at the Post-synthesis report
After seeing this message (you know you have did everything right till now) *kudos*
![image](https://github.com/user-attachments/assets/92165941-7c39-4de0-97f9-0a6dda2124e3)


![image](https://github.com/user-attachments/assets/3f879dbd-f4c1-4c7d-b058-ffde601f4d22)

## This is the reason pragmas are used (for interfacing)

![image](https://github.com/user-attachments/assets/487a42bc-7030-48d8-9ce0-808e1104edbd)

## This is the resource utilisation and the timing estimates 

the number of LUT's,Flipflops,DSP blocks utilised on the fpga to implement this design is given here 
Its up to you to explore after this (you can play around in the post synthesis Chat-GPT it and understand the tables in it.

click on the export RTL to get this into vivado
![image](https://github.com/user-attachments/assets/f7350ed4-2eb9-47c6-8a58-8f4c4df26a5f)

set the output file location and remember it for the future you will need it ....
![image](https://github.com/user-attachments/assets/7843bd6d-aeb3-4627-a88d-91854b734b77)

## lets export this as a HLS block

I will remember this path

![image](https://github.com/user-attachments/assets/0596f24c-4ea3-4ed4-8f1d-43f0876f1d60)

hit ok to see this 

![image](https://github.com/user-attachments/assets/5bb4ddb3-d2c2-467e-8740-c452ae9a997b)

this is your green signal

![image](https://github.com/user-attachments/assets/c3b8f361-5886-45f5-9a12-41ec05483328)

### Extract the files in that location its given as a .zip file (also available in the main batch in this repo)

![image](https://github.com/user-attachments/assets/44987f8a-a56f-4f6f-8463-213ccb8342b7)

or like this 

![image](https://github.com/user-attachments/assets/57fdb71f-7839-4a8f-88b2-75c0740a59d0)

# Flow in Vivado

Open Vivado

![image](https://github.com/user-attachments/assets/5b4455b2-b01f-42de-b155-cbf351057dea)

open a new project and do what you need but while choosing the boards go into Boards->Kria KV260.

![image](https://github.com/user-attachments/assets/5a3de453-b9e4-4608-999e-6c98612ebe40)

should look like this 

![image](https://github.com/user-attachments/assets/faedab4d-8c64-436f-b2ed-7ffd8ffd36e9)


## Now make a block design 

![image](https://github.com/user-attachments/assets/df88e573-1ac9-4672-bcaa-a16dc6593e11)

click on settings to open up this window

![image](https://github.com/user-attachments/assets/2a2eeacb-c49c-47f4-bcf5-161a60a8dfac)

click on IP->Repository

![image](https://github.com/user-attachments/assets/f7884922-7801-45f0-a774-62742bf8773f)

and on the "+" mark

![image](https://github.com/user-attachments/assets/de999173-c9a8-4969-ae54-1cf5a58362f3)

the path in my system:- /home/arx-0/Documents/new_ip_sha  

![image](https://github.com/user-attachments/assets/9077d570-af34-4a18-9c45-2c78accfde53)

Hit ok and Apply ...

![image](https://github.com/user-attachments/assets/d38948a8-373a-43a3-908c-ed97cb38dbf3)


Now we have our Hls IP in vivado :) 

![image](https://github.com/user-attachments/assets/92863e2d-88d9-4d4f-856b-ce5df22d62fc)

this is your achievement as of now 

![image](https://github.com/user-attachments/assets/04641d08-0c9a-45a9-91c0-4a456c8bb25c)


Under IP Integrator, choose Create Block Diagram. Add the following blocks:

- Zynq UltraScale+ MPSoc (This is the PS)
- Hash (The IP that we have generated from Vitis HLS)
- AXI Interconnect (To interconnect to the m_axi bus from our IP)
![image](https://github.com/user-attachments/assets/d21cb4ab-e237-4b67-ac53-6ea20d6cc7ff)


![image](https://github.com/user-attachments/assets/83f914b7-d03b-4aa1-acfa-0320bb3537b9)

After that, run Connection Automation. Choose all the possible automations and accept the default settings.

![image](https://github.com/user-attachments/assets/74987593-a5e2-4530-a010-7bb2db0fc2f2)

Notice that the interconnect bus for m_axi (Master) is still unconnected. This is because I forgot to enable the Slave interface on the PS.

*Double click on the Zynq UltraScale+ MPSoc block. Enable AXI HP0 FPD (high performance). Check that the data width is 32 bits which is to match what was synthesized in the HLS.*

![image](https://github.com/user-attachments/assets/5d17f500-b799-42b8-93a8-4588a835ba03)

Run connection automation again. This is the final block diagram.

![image](https://github.com/user-attachments/assets/f4cd6dba-3a7f-4f14-afa8-32cc288956d5)

Hit the generate bitstream button (this synthesis might take a good 30 mins make shure to go on break .... (open synthesixed reports and view your design reports)
