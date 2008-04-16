#ifndef _HMAC_MD5_H
#define _HMAC_MD5_H
/* prototypes */

void hmac_md5( unsigned char* text, int text_len, unsigned char* key, 
		int key_len, unsigned char* digest);

/* pointer to data stream */
/* length of data stream */
/* pointer to authentication key */
/* length of authentication key */
/* caller digest to be filled in */

#define MD5_BLOCK_LEN 64
#define MD5_DIGEST_LEN 16

#endif

