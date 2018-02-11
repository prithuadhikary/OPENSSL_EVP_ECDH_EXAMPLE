#include <stdio.h>
#include <stdlib.h>
#include <openssl/ecdh.h>
#include <openssl/ec.h>
#include <openssl/pem.h>

struct derivedKey {
    char* secret;
    int length;
};

typedef struct derivedKey derivedKey;

EVP_PKEY* generateKey();
EVP_PKEY* extractPublicKey(EVP_PKEY *privateKey);
derivedKey* deriveShared(EVP_PKEY *publicKey, EVP_PKEY *privateKey);

int main()
{
    EVP_PKEY *alicePrivateKey = generateKey();
    EVP_PKEY *bobPrivateKey = generateKey();

    EVP_PKEY *alicePubKey = extractPublicKey(alicePrivateKey);

    EVP_PKEY *bobPubKey = extractPublicKey(bobPrivateKey);

    derivedKey* secretAlice = deriveShared(bobPubKey, alicePrivateKey);

    derivedKey* secretBob = deriveShared(alicePubKey, bobPrivateKey);

    BIGNUM *secretAliceBN = BN_new();

    BIGNUM *secretBobBN = BN_new();

    BN_bin2bn(secretAlice->secret, secretAlice->length, secretAliceBN);

    BN_bin2bn(secretBob->secret, secretBob->length, secretBobBN);

    printf("\nSecret Alice : ");

    BN_print_fp(stdout, secretAliceBN);

    printf("\nSecret Bob : ");

    BN_print_fp(stdout, secretBobBN);

    return 0;
}

void handleErrors(){
    printf("\n\nFailed...");
}


void handleDerivationErrors(int x){
    printf("\n\nDerivation Failed...");
    printf("%d", x);
}

EVP_PKEY* generateKey(){

    EVP_PKEY_CTX *paramGenCtx = NULL, *keyGenCtx = NULL;
    EVP_PKEY *params= NULL, *keyPair= NULL;

    paramGenCtx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);

    if(!EVP_PKEY_paramgen_init(paramGenCtx)) handleErrors();

    EVP_PKEY_CTX_set_ec_paramgen_curve_nid(paramGenCtx, NID_X9_62_prime256v1);

    EVP_PKEY_paramgen(paramGenCtx, &params);

    keyGenCtx = EVP_PKEY_CTX_new(params, NULL);

    if(!EVP_PKEY_keygen_init(keyGenCtx)) handleErrors();

    if(!EVP_PKEY_keygen(keyGenCtx, &keyPair)) handleErrors();

    EC_KEY *ecKey = EVP_PKEY_get1_EC_KEY(keyPair);

    BIGNUM *privKey = EC_KEY_get0_private_key(ecKey);

    EC_POINT *pubPoint = EC_KEY_get0_public_key(ecKey);

    BIGNUM *x = BN_new();

    BIGNUM *y = BN_new();

    EC_POINT_get_affine_coordinates_GFp(EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1), pubPoint, x, y, NULL);

    printf("\nprivate : ");

    BN_print_fp(stdout, privKey);

    printf("\npubX : ");

    BN_print_fp(stdout, x);

    printf("\npubY : ");

    BN_print_fp(stdout, y);

    return keyPair;
}

EVP_PKEY* extractPublicKey(EVP_PKEY *privateKey){
    EC_KEY *ecKey = EVP_PKEY_get1_EC_KEY(privateKey);
    EC_POINT *ecPoint = EC_KEY_get0_public_key(ecKey);

    EVP_PKEY *publicKey = EVP_PKEY_new();

    EC_KEY *pubEcKey = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);

    EC_KEY_set_public_key(pubEcKey, ecPoint);

    EVP_PKEY_set1_EC_KEY(publicKey, pubEcKey);

    return publicKey;
}

derivedKey* deriveShared(EVP_PKEY *publicKey, EVP_PKEY *privateKey){

    derivedKey *dk = (derivedKey *)malloc(sizeof(derivedKey));

    EVP_PKEY_CTX *paramCtx = NULL, *derivationCtx = NULL;

    derivationCtx = EVP_PKEY_CTX_new(privateKey, NULL);

    EVP_PKEY_derive_init(derivationCtx);

    EVP_PKEY_derive_set_peer(derivationCtx, publicKey);

	if(1 != EVP_PKEY_derive(derivationCtx, NULL, &dk->length)) handleDerivationErrors(0);

	printf("\n\nSecret Len: %d", dk->length);

	if(NULL == (dk->secret = OPENSSL_malloc(dk->length))) handleDerivationErrors(1);

	if(1 != (EVP_PKEY_derive(derivationCtx, dk->secret, &dk->length))) handleDerivationErrors(2);

	return dk;
}
