/**
 * Author: Alin Tomescu
 * Date: 11:07 PM, August 9th, 2012
 * Location: 5th Ave Laundromat, Park Slope, Brooklyn, NY (for the lulz)
 * Website: http://alinush.is-great.org
 * License: Free to use, copy and distribute
 * Warranty: None
 * Guarantees: None
 *
 * Description: This program demonstrates how to encrypt a file using AES and
 *  the OpenSSL libraries. From it, you can deduce how to use other ciphers
 *  like Blowfish or DES or how to encrypt a buffer instead of a file.
 * 
 * Enjoy! :D
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <assert.h>

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/err.h>

#ifdef DEBUG
#define dbg(...) { fprintf(stderr, "   %s: ", __FUNCTION__); \
    fprintf(stderr, __VA_ARGS__); fflush(stderr); }
#else
#define dbg(...)
#endif

#define NUM_NEEDED_ARGS (7 + 1)
#define AES_DEFAULT_MODE "aes-256-cbc"
#define EVP_CIPHERNAME_AES_CBC "aes-256-cbc"
#define EVP_CIPHERNAME_AES_CTR "aes-256-ctr"

#define HEX2BIN_ERR_INVALID_LENGTH -2
#define HEX2BIN_ERR_MAX_LENGTH_EXCEEDED -1
#define HEX2BIN_ERR_NON_HEX_CHAR 0
#define HEX2BIN_SUCCESS 1

#define AES_ERR_FILE_OPEN -1
#define AES_ERR_CIPHER_INIT -2 
#define AES_ERR_CIPHER_UPDATE -3
#define AES_ERR_CIPHER_FINAL -4
#define AES_ERR_IO -5

#define BUF_SIZE (1024*1024)

typedef struct __cryptomaniac_t {
	const char * infile, * outfile;
	int encrypt;
	const EVP_CIPHER * mode;
	unsigned char key[EVP_MAX_KEY_LENGTH], iv[EVP_MAX_IV_LENGTH];
} cryptomaniac_t;

int aes_encrypt_file(const char * infile, const char * outfile, 
    const void * key, const void * iv, const EVP_CIPHER * cipher, int enc);

int hex2bin(const char * hex, void * bin, int max_length);

int parse_arguments(int argc, char * argv[], cryptomaniac_t * cm);
void print_usage(FILE * out, const char * name);

int main(int argc, char * argv[])
{
	if(argc < NUM_NEEDED_ARGS) {
		print_usage(stderr, argv[0]);
		return 1;
	}
	
	// Initializing the AES cipher in parse_arguments requires this call
	OpenSSL_add_all_algorithms();
	ERR_load_crypto_strings();
	
	// Parse arguments
	cryptomaniac_t cm;
	if(parse_arguments(argc, argv, &cm) <= 0)
		return 1;
	
	// Encrypt/decrypt file
	int st;
	if((st = aes_encrypt_file(cm.infile, cm.outfile, cm.key, cm.iv, cm.mode, cm.encrypt)) <= 0)
	{
		fprintf(stderr, "ERROR: %s failed\n", cm.encrypt ? "Encryption" : "Decryption");
		return 1;
	}
	
	dbg("Exited gracefully!\n");
	return 0;
}

int aes_encrypt_file(const char * infile, const char * outfile, const void * key, const void * iv, const EVP_CIPHER * cipher, int enc)
{
	assert(cipher != NULL);
	
	int rc = -1;
	int cipher_block_size = EVP_CIPHER_block_size(cipher);
	
	assert(cipher_block_size <= BUF_SIZE);
	
	// The output buffer size needs to be bigger to accomodate incomplete blocks
	// See EVP_EncryptUpdate documentation for explanation:
	//		http://lmgtfy.com/?q=EVP_EncryptUpdate
	int insize = BUF_SIZE;
	int outsize = insize + (cipher_block_size - 1);
	
	unsigned char inbuf[insize], outbuf[outsize];
	int ofh = -1, ifh = -1;
	int u_len = 0, f_len = 0;

	EVP_CIPHER_CTX ctx;
	EVP_CIPHER_CTX_init(&ctx);

	// Open the input and output files
	rc = AES_ERR_FILE_OPEN;
	if((ifh = open(infile, O_RDONLY)) == -1) {
		fprintf(stderr, "ERROR: Could not open input file %s, errno = %s\n", infile, strerror(errno));
		goto cleanup;
	}

	if((ofh = open(outfile, O_CREAT | O_TRUNC | O_WRONLY, 0644)) == -1) {
		fprintf(stderr, "ERROR: Could not open output file %s, errno = %s\n", outfile, strerror(errno));
		goto cleanup;
	}
	
	// Initialize the AES cipher for enc/dec
	rc = AES_ERR_CIPHER_INIT;
	if(EVP_CipherInit_ex(&ctx, cipher, NULL, key, iv, enc) == 0) {
		fprintf(stderr, "ERROR: EVP_CipherInit_ex failed. OpenSSL error: %s\n", ERR_error_string(ERR_get_error(), NULL));
		goto cleanup;
	}
	
	// Read, pass through the cipher, write.
	int read_size, len;
	while((read_size = read(ifh, inbuf, BUF_SIZE)) > 0)
	{
		dbg("Read %d bytes, passing through CipherUpdate...\n", read_size);
		if(EVP_CipherUpdate(&ctx, outbuf, &len, inbuf, read_size) == 0) {
			rc = AES_ERR_CIPHER_UPDATE;
			fprintf(stderr, "ERROR: EVP_CipherUpdate failed. OpenSSL error: %s\n", ERR_error_string(ERR_get_error(), NULL));
			goto cleanup;
		}
		dbg("\tGot back %d bytes from CipherUpdate...\n", len);
		
		dbg("Writing %d bytes to %s...\n", len, outfile);
		if(write(ofh, outbuf, len) != len) {
			rc = AES_ERR_IO;
			fprintf(stderr, "ERROR: Writing to the file %s failed. errno = %s\n", outfile, strerror(errno));
			goto cleanup;
		}
		dbg("\tWrote %d bytes\n", len);
		
		u_len += len;
	}
	
	// Check last read succeeded
	if(read_size == -1) {
		rc = AES_ERR_IO;
		fprintf(stderr, "ERROR: Reading from the file %s failed. errno = %s\n", infile, strerror(errno));
		goto cleanup;
	}
	
	// Finalize encryption/decryption
	rc = AES_ERR_CIPHER_FINAL;
	if(EVP_CipherFinal_ex(&ctx, outbuf, &f_len) == 0) {
		fprintf(stderr, "ERROR: EVP_CipherFinal_ex failed. OpenSSL error: %s\n", ERR_error_string(ERR_get_error(), NULL));
		goto cleanup;
	}
	
	dbg("u_len = %d, f_len = %d\n", u_len, f_len);
	
	// Write the final block, if any
	if(f_len) {
		dbg("Writing final %d bytes to %s...\n", f_len, outfile);
		if(write(ofh, outbuf, f_len) != f_len) {
			rc = AES_ERR_IO;
			fprintf(stderr, "ERROR: Final write to the file %s failed. errno = %s\n", outfile, strerror(errno));
			goto cleanup;
		}
		dbg("\tWrote last %d bytes\n", f_len);
	}

	rc = u_len + f_len;

 cleanup:
 	EVP_CIPHER_CTX_cleanup(&ctx);
 	if(ifh != -1) close(ifh);
 	if(ofh != -1) close(ofh);
 	
	return rc;
}

int hex2bin(const char * hex, void * bin, int max_length)
{
	int rc = 1;
	int hexlength = strlen(hex);
	
	if(hexlength % 2 == 1) {
		rc = HEX2BIN_ERR_INVALID_LENGTH;
		fprintf(stderr, "ERROR: Hex string length needs to be an even number, not %d (a byte is two hex chars)\n", hexlength);
		goto cleanup;
	}
	
	if(hexlength > max_length * 2) {
		rc = HEX2BIN_ERR_MAX_LENGTH_EXCEEDED;
		fprintf(stderr, "Hex string is too large (%d bytes) to be decoded into the specified buffer (%d bytes)\n", hexlength/2, max_length);
		goto cleanup;
	}
	
	int binlength = hexlength / 2;

	for (int i = 0; i < binlength; i++) {
		if (sscanf(hex, "%2hhx", (unsigned char *)(bin + i)) != 1) {
		    rc = HEX2BIN_ERR_NON_HEX_CHAR;
			fprintf(stderr, "A non-hex char was found in the hex string at pos. %d or %d: [%c%c]\n",
				i, i+1, hex[i], hex[i+1]);
			goto cleanup;
		}
		
		hex += 2;
	}
	
cleanup:
	return rc;	
}

int parse_arguments(int argc, char * argv[], cryptomaniac_t * cm)
{
	int rc = -1;
	memset(cm, 0, sizeof(cryptomaniac_t));

	rc = 0;
	int has_iv = 0, has_key = 0;
	
	cm->infile = argv[1];
	cm->outfile = argv[2];	
	cm->mode = EVP_get_cipherbyname(AES_DEFAULT_MODE);
	
	for(int i = 3; i < argc; i++)
	{
		if(!strcmp(argv[i], "-e")) {
			cm->encrypt = 1;
		} else if(!strcmp(argv[i], "-d")) {
			cm->encrypt = 0;
		} else if(!strcmp(argv[i], "-k")) {
			if(i < argc - 1) {
				int st = hex2bin(argv[i + 1], cm->key, EVP_MAX_KEY_LENGTH);
				if(st <= 0)
					goto cleanup;
				has_key = 1;
				i++;
			} else {
				fprintf(stderr, "ERROR: Expected hex key after -k parameter\n");
				goto cleanup;
			}
		} else if(!strcmp(argv[i], "-i")) {
			if(i < argc - 1) {
				int st = hex2bin(argv[i + 1], cm->iv, EVP_MAX_IV_LENGTH);
				if(st <= 0)
					goto cleanup;
				has_iv = 1;
				i++;
			} else {
				fprintf(stderr, "ERROR: Expected hex IV after -i parameter\n");
				goto cleanup;
			}
		} else if(!strcmp(argv[i], "-m")) {
			if(i < argc - 1) {
				if(!strcmp(argv[i + 1], "cbc")) {
					cm->mode = EVP_get_cipherbyname(EVP_CIPHERNAME_AES_CBC);
					i++;
				} else if(!strcmp(argv[i + 1], "ctr")) {
					cm->mode = EVP_get_cipherbyname(EVP_CIPHERNAME_AES_CTR);
					i++;
				} else {
					fprintf(stderr, "ERROR: Expected cbc or ctr after -m, got %s\n", argv[i + 1]);
					goto cleanup;
				}
			} else {
				fprintf(stderr, "ERROR: Expected cipher mode (cbc or ctr) after -m parameter\n");
				goto cleanup;
			}
		}
	}
	
	if(!has_iv) {
		fprintf(stderr, "ERROR: You must provide an IV value in hexadecimal using -i\n");
		goto cleanup;
	}
	
	if(!has_key) {
		fprintf(stderr, "ERROR: You must provide an encryption key in hexadecimal using -k\n");	
		goto cleanup;
	}
		
	if(cm->mode == NULL) {
		fprintf(stderr, "ERROR: EVP_get_cipherbyname failed. OpenSSL error: %s\n", ERR_error_string(ERR_get_error(), NULL));
		goto cleanup;
	}
	
	rc = 1;
	
cleanup:
	return rc;
}

void print_usage(FILE * out, const char * name)
{
	fprintf(stderr, "Usage: %s <infile> <outfile> <options>\n", name);
	
	fprintf(stderr, "Cryptomaniac command-line client, version 0.1, by Alin Tomescu, http://alinush.is-great.org/\n");
	fprintf(stderr, "Encrypt or decrypt a file using AES256 in CBC or CTR mode. ");
	fprintf(stderr, "You have to provide your own key (32 bytes) and IV (16 bytes) as hexadecimal strings.\n");
	fprintf(stderr, "\n");
	
	fprintf(stderr, "  <infile> is the input file to encrypt or decrypt\n");
	fprintf(stderr, "  <outfile> is the output file where the encrypted or decrypted bytes will be written to\n");
	fprintf(stderr, "  <options> can be anyone of the following:\n");
	fprintf(stderr, "    -e encrypts the infile, stores the result in the outfile\n");
	fprintf(stderr, "    -d decrypts the infile, stores the result in the outfile\n");
	fprintf(stderr, "    -k <key> the encryption key to use as a hex string (32 bytes)\n");
	fprintf(stderr, "    -i <iv> the IV to use as a hex string (16 bytes)\n");
	fprintf(stderr, "    -m <mode> the cipher block-mode to use (this can be cbc or ctr)\n");
	fprintf(stderr, "\n");
	
	fprintf(stderr, "Examples:\n");
	fprintf(stderr, "=========\n");
	fprintf(stderr, "\n");
	
	fprintf(stderr, "  Encrypting a file:\n");
	fprintf(stderr, "  ------------------\n");
	fprintf(stderr, "  %s secrets.txt secrets.safe -e -k ae48fbc31957 -iv 39eab239867dfe\n", name);
	fprintf(stderr, "\n");
	
	fprintf(stderr, "  Decrypting a file:\n");
	fprintf(stderr, "  ------------------\n");
	fprintf(stderr, "  %s secretes.safe secrets.revealed -d -k ae48fbc31957 -iv 39eab239867dfe\n", name);
	fprintf(stderr, "\n");
}
