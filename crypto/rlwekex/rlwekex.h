/* crypto/rlwekex/rlwekex.h */
#ifndef HEADER_RLWEKEX_H
#define HEADER_RLWEKEX_H

#include <openssl/opensslconf.h>

#ifdef OPENSSL_NO_RLWEKEX
#error RLWEKEX is disabled.
#endif

#include <openssl/ossl_typ.h>
#include <openssl/bn.h>
#include <openssl/err.h>

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct rlwe_param_st RLWE_PARAM;
typedef struct rlwe_pub_st RLWE_PUB;
typedef struct rlwe_pair_st RLWE_PAIR;
typedef struct rlwe_rec_st RLWE_REC;
typedef struct rlwe_ctx_st RLWE_CTX;

/* Allocate and deallocate parameters, public keys, private key / public key pairs, and reconciliation data structures */
RLWE_PARAM *RLWE_PARAM_new(void);
void RLWE_PARAM_free(RLWE_PARAM *param);

RLWE_PUB *RLWE_PUB_new(void);
RLWE_PUB *RLWE_PUB_copy(RLWE_PUB *dest, const RLWE_PUB *src);
void RLWE_PUB_free(RLWE_PUB *pub);

RLWE_PAIR *RLWE_PAIR_new(void);
RLWE_PAIR *RLWE_PAIR_copy(RLWE_PAIR *dest, const RLWE_PAIR *src);
RLWE_PAIR *RLWE_PAIR_dup(const RLWE_PAIR *pair);
void RLWE_PAIR_free(RLWE_PAIR *pair);

RLWE_REC *RLWE_REC_new(void);
void RLWE_REC_free(RLWE_REC *rec);

RLWE_CTX *RLWE_CTX_new(void);
void RLWE_CTX_free(RLWE_CTX *ctx);

/* Generate key pair */
int RLWE_PAIR_generate_key(RLWE_PAIR *key, RLWE_CTX *ctx);

/* Convert public keys and reconciliation data structures from/to binary */
RLWE_PUB *o2i_RLWE_PUB(RLWE_PUB **pub, const unsigned char *in, long len);
int i2o_RLWE_PUB(RLWE_PUB *pub, unsigned char **out);
RLWE_REC *o2i_RLWE_REC(RLWE_REC **rec, const unsigned char *in, long len);
int i2o_RLWE_REC(RLWE_REC *rec, unsigned char **out);

/* Get public key from a key pair */
RLWE_PUB *RLWE_PAIR_get_publickey(RLWE_PAIR *pair);
/* Does private key exist? */
int RLWE_PAIR_has_privatekey(RLWE_PAIR *pair);

/* Compute shared secret values */
int RLWEKEX_compute_key_alice(void *out, size_t outlen, const RLWE_PUB *peer_pub_key,  const RLWE_REC *peer_reconciliation,
                              const RLWE_PAIR *priv_pub_key, void *(*KDF)(const void *in, size_t inlen, void *out, size_t *outlen), RLWE_CTX *ctx);
int RLWEKEX_compute_key_bob(void *out, size_t outlen, RLWE_REC *reconciliation, const RLWE_PUB *peer_pub_key,  const RLWE_PAIR *priv_pub_key,
                            void *(*KDF)(const void *in, size_t inlen, void *out, size_t *outlen), RLWE_CTX *ctx);

/* BEGIN ERROR CODES */
/* The following lines are auto generated by the script mkerr.pl. Any changes
 * made after this point may be overwritten when the script is next run.
 */
void ERR_load_RLWEKEX_strings(void);

/* Error codes for the RLWEKEX functions. */

/* Function codes. */
#define RLWEKEX_F_I2O_RLWE_PUB				 100
#define RLWEKEX_F_I2O_RLWE_REC				 104
#define RLWEKEX_F_O2I_RLWE_PUB				 101
#define RLWEKEX_F_O2I_RLWE_REC				 105
#define RLWEKEX_F_RANDOM32				 111
#define RLWEKEX_F_RANDOM64				 112
#define RLWEKEX_F_RANDOM8				 110
#define RLWEKEX_F_RLWEKEX_				 107
#define RLWEKEX_F_RLWEKEX_COMPUTE_KEY_ALICE		 108
#define RLWEKEX_F_RLWEKEX_COMPUTE_KEY_BOB		 109
#define RLWEKEX_F_RLWE_CTX_NEW				 114
#define RLWEKEX_F_RLWE_PAIR_COPY			 115
#define RLWEKEX_F_RLWE_PAIR_NEW				 102
#define RLWEKEX_F_RLWE_PARAM_NEW			 113
#define RLWEKEX_F_RLWE_PUB_COPY				 116
#define RLWEKEX_F_RLWE_PUB_NEW				 103
#define RLWEKEX_F_RLWE_REC_NEW				 106

/* Reason codes. */
#define RLWEKEX_R_INVALID_LENGTH			 102
#define RLWEKEX_R_KDF_FAILED				 100
#define RLWEKEX_R_RANDOM_FAILED				 101

#ifdef  __cplusplus
}
#endif
#endif
