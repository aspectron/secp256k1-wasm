/**********************************************************************
 * Copyright (c) 2014 Pieter Wuille                                   *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#include <emscripten/bind.h>
#include <emscripten/val.h>

extern "C" {
    #include <stdio.h>
    #include <string.h>

    #define PACKAGE_NAME "libsecp256k1"
    #define PACKAGE_TARNAME "libsecp256k1"
    #define PACKAGE_VERSION "0.1"
    #define PACKAGE_STRING "libsecp256k1 0.1"
    #define PACKAGE_BUGREPORT ""
    #define PACKAGE_URL ""
    #define PACKAGE "libsecp256k1"
    #define VERSION "0.1"
    #define STDC_HEADERS 1
    #define HAVE_SYS_TYPES_H 1
    #define HAVE_SYS_STAT_H 1
    #define HAVE_STDLIB_H 1
    #define HAVE_STRING_H 1
    #define HAVE_MEMORY_H 1
    #define HAVE_STRINGS_H 1
    #define HAVE_INTTYPES_H 1
    #define HAVE_STDINT_H 1
    #define HAVE_UNISTD_H 1
    #define HAVE_DLFCN_H 1
    #define LT_OBJDIR ".libs/"
    #define HAVE___INT128 1
    #define USE_FIELD_5X52 1
    #define USE_NUM_NONE 1
    #define USE_FIELD_INV_BUILTIN 1
    #define USE_SCALAR_INV_BUILTIN 1
    #define USE_SCALAR_4X64 1
    #define ECMULT_WINDOW_SIZE 15
    #define ECMULT_GEN_PREC_BITS 4
    #define HAVE_LIBCRYPTO 1
    #define ENABLE_MODULE_EXTRAKEYS 1
    #define ENABLE_MODULE_SCHNORRSIG 1

    
    #include "include/secp256k1_extrakeys.h"
    #include "secp256k1.c"
    #include "util.h"
    #include "bench.h"

    #ifdef ENABLE_OPENSSL_TESTS
    #include <openssl/bn.h>
    #include <openssl/ecdsa.h>
    #include <openssl/obj_mac.h>
    #endif

    typedef struct {
        secp256k1_context *ctx;
        unsigned char msg[32];
        unsigned char key[32];
        unsigned char sig[72];
        size_t siglen;
        unsigned char pubkey[33];
        size_t pubkeylen;
    #ifdef ENABLE_OPENSSL_TESTS
        EC_GROUP* ec_group;
    #endif
    } data_t;


    
    int init(){
        
        return 0;
    }


    
    void sha265Encode(const char* msg, const unsigned char*out){
        secp256k1_sha256 hasher;
        secp256k1_sha256_initialize(&hasher);
        secp256k1_sha256_write(&hasher, (const unsigned char*)(msg), strlen(msg));
        secp256k1_sha256_finalize(&hasher, (unsigned char*)out);
    }


    int size(unsigned char *ptr){
        int count = 0;
        while (*(ptr + count) != '\0')
        {
            ++count;
        }
        return count;
    }

    void charArray2hexString(unsigned char* input, char* output){
        int loop;
        int i;
        int max;
        
        i=0;
        loop=0;
        max = size(input);
        
        for(loop=0; loop<max; loop++)
        {
            //printf("%i : %i =>%c\n", loop, i, input[loop]);
            sprintf(&output[i], "%02X", input[loop]);
            i+=2;
        }
        output[i++] = '\0';
    }


    
    int test123(int b){
        int a = 1111;
        return a+b;
    }

    char key[32];
    
    char * genPrivkey(){
        int i;

        for (i = 0; i < 32; i++) {
            key[i] = 33 + i;
        }

        return key;
    }

    
    void ecdsa_sign(const char *msg){
        int i;
        unsigned char msgHash[32];
        char msgHashHex[32];
        char hex[128], privKeyHex[32];
        secp256k1_ecdsa_signature sig;
        data_t data;

        secp256k1_context *ctx;
        ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
        //secp256k1_context_randomize(ctx)

        sha265Encode(msg, msgHash);
        charArray2hexString(msgHash, msgHashHex);
        //printf("MSG: %s\nHEX: %s\n", msg, msgHashHex);
        

        //data.ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);
        for (i = 0; i < 32; i++) {
            data.msg[i] = 1 + i;
        }
        for (i = 0; i < 32; i++) {
            data.key[i] = 33 + i;
        }
        data.siglen = 72;
        
        secp256k1_ecdsa_sign(ctx, &sig, (const unsigned char *)msgHashHex, data.key, NULL, NULL);
        secp256k1_context_destroy(ctx);

        
        charArray2hexString(sig.data, hex);
        
        //printf("sig: %s\n", hex);
        charArray2hexString(data.key, privKeyHex);
        
        //printf("privKey: %s\n", privKeyHex);
    }
}
using namespace emscripten;


char* strToChars(std::string str){
    char* char_array;
    char_array = &str[0];
    return char_array;
}
const unsigned char* strToUnsignedChars(std::string str){
    const unsigned char* char_array;
    char_array = (const unsigned char *)&str[0];
    return char_array;
}

std::string stringTohex(const std::string& input){
    static const char hex_digits[] = "0123456789ABCDEF";

    std::string output;
    output.reserve(input.length() * 2);
    for (unsigned char c : input)
    {
        output.push_back(hex_digits[c >> 4]);
        output.push_back(hex_digits[c & 15]);
    }
    return output;
}

std::string convertToString(char* a){//, int size)
    //int hex_size = sizeof(hex) / sizeof(char);
    //std::string hex_str = convertToString(hex, hex_size);
    std::string s = a; 
    return s; 
}

std::string convertToString(const unsigned char* a){//, int size)
    //int hex_size = sizeof(hex) / sizeof(char);
    //std::string hex_str = convertToString(hex, hex_size);
    std::string s = std::string( reinterpret_cast< const char* >(a)); 
    return s; 
}

char const hex[16] = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B','C','D','E','F'};

std::string convertToHex(unsigned char* data, int len) {
  std::string str;
  //int len = 10;//sizeof(data);
  /*unsigned char d[len];
  for (int i = 0; i < len; ++i) {
    d[i] = data[i];
  }*/
  //printf("fdsdfkdfgjkdgjk %s\n", data);

  for (int i = 0; i < len; ++i) {
    const char ch = data[i];
    //printf("ch: %c\n", ch);
    str.append(&hex[(ch & 0xF0) >> 4], 1);
    str.append(&hex[ch & 0x0F], 1);
  }
  return str;
}

std::string convertToHex(const unsigned char* data, int len) {
  std::string str;
  //int len = 10;//sizeof(data);
  //val Module = val::global("xxx");
  //Module.call<void>("set", val("fdsdfkdfgdfdfdsf sdf sdfs fsd fsdf sdf sdfs fsd fsdf sdfsdfsd fs fsdf dsj\n"));
  //printf("");
  for (int i = 0; i < len; ++i) {
    const char ch = data[i];
    //printf("ch: %c\n", ch);
    str.append(&hex[(ch & 0xF0) >> 4], 1);
    str.append(&hex[ch & 0x0F], 1);
  }
  return str;
}




struct Result {
    std::string data;
    unsigned char c;
    int r;
};

struct PublicKeys{
    std::string key;
    std::string xonly;
    std::string seckey;
};

struct SignResult{
    std::string sig;
    std::string error;
};

Result result;


Result ecdsa_sign_new(std::string _msg, std::string privKey){
    char* msg;
    msg = &_msg[0];
    int i;
    unsigned char msgHash[32];
    char msgHashHex[32];
    char hex[128];
    secp256k1_ecdsa_signature sig;
    data_t data;
    const unsigned char *privKeyHex = strToUnsignedChars(privKey);


    secp256k1_context *ctx;
    ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    //secp256k1_context_randomize(ctx)

    sha265Encode(msg, msgHash);
    charArray2hexString(msgHash, msgHashHex);
    //result.msg = convertToString(msgHashHex);
    //result.privKey = privKey;//convertToString(privKeyHex);
    //printf("MSG: %s\nHEX: %s\n", msg, msgHashHex);
    

    //data.ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);
    for (i = 0; i < 32; i++) {
        data.msg[i] = 1 + i;
    }
    for (i = 0; i < 32; i++) {
        data.key[i] = 33 + i;
    }
    data.siglen = 72;
    
    secp256k1_ecdsa_sign(ctx, &sig, (const unsigned char *)msgHashHex, privKeyHex, NULL, NULL);
    secp256k1_context_destroy(ctx);

    
    //charArray2hexString(sig.data, hex);
    
    //printf("sig: %s\n", hex);
    //charArray2hexString(data.key, privKeyHex);
    
    //printf("privKey: %s\n", privKeyHex);
    
    //result.sig2 = convertToString(hex);
    result.data = convertToHex(sig.data, 64);

    return result;
}

int deserialize_private_key(secp256k1_context *ctx, std::string private_key, secp256k1_keypair *keypair){
    for(int i=0; i<96; i++){
        keypair->data[i] = 'x';
    }

    const unsigned char *privateKey = strToUnsignedChars(private_key);
    return secp256k1_keypair_create(ctx, keypair, privateKey);
}

Result test_keypair_seckey(std::string seckey){
    secp256k1_context *ctx;
    ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);
    secp256k1_keypair keypair;
    deserialize_private_key(ctx, seckey, &keypair);
    secp256k1_xonly_pubkey xOnlyPubkey{};
    unsigned char xOnlyPubkeySerialized[32];
    //memset(&output, 0, 32);
    for(int i=0; i<64; i++){
        xOnlyPubkey.data[i] = '0';
    }
    int pk_parity;
    int r2 = secp256k1_keypair_xonly_pub(ctx, &xOnlyPubkey, &pk_parity, &keypair);

    //for(int i=0; i<64; i++){
        //pubkey2.data[i] = pubkey.data[i];
    //}

    int r3 = secp256k1_xonly_pubkey_serialize(ctx, xOnlyPubkeySerialized, &xOnlyPubkey);

    unsigned char pubkey[33];
    size_t pubkeyLen = 33;
    secp256k1_ec_pubkey_serialize(ctx, (unsigned char *)&pubkey, &pubkeyLen, (const secp256k1_pubkey *)&xOnlyPubkey, SECP256K1_EC_COMPRESSED);

    unsigned char seckey32[200];
    for(int i=0; i<200; i++){
        seckey32[i] = 'x';
    }

    secp256k1_scalar *sk;

    //result.r = secp256k1_keypair_seckey_load(ctx, sk, &keypair);
    result.r = secp256k1_keypair_seckey(ctx, seckey32, &keypair);
    //printf("keypair.data: %s\n", convertToHex(keypair.data, 96).c_str());
    

    result.data =   "\n\t pk_parity: "+std::to_string(pk_parity)
                    +"\n\t seckey32: "+convertToHex(seckey32, 64)
                    +"\n\t pubkey: "+convertToHex(pubkey, 33)
                    +"\n\t pubkeyLen: "+convertToString((char *)pubkeyLen)
                    +"\n\t xonly_pubkey: "+convertToHex(xOnlyPubkey.data, 64)
                    //+"\n\tpubkey2: "+convertToHex(pubkey2.data, 64)
                    +"\n\t xonly_pubkey_serialized: "+convertToHex(xOnlyPubkeySerialized, 32)
                    +"\n\t seckey32: "+convertToString(seckey32)+"\n";
                    //+"\n\t sk: "+convertToHex(sk.d, 32)+"\n";
    secp256k1_context_destroy(ctx);
    return result;
}

PublicKeys export_public_keys(std::string seckey){
    secp256k1_context *ctx;
    ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);
    secp256k1_keypair keypair;
    deserialize_private_key(ctx, seckey, &keypair);

    secp256k1_xonly_pubkey xOnlyPubkey{};
    unsigned char xOnlyPubkeySerialized[32], pubkey[33];
    size_t pubkeyLen = 33;
    for(int i=0; i<64; i++){
        xOnlyPubkey.data[i] = '0';
    }
    int pk_parity;
    int r = secp256k1_keypair_xonly_pub(ctx, &xOnlyPubkey, &pk_parity, &keypair);
    r = secp256k1_xonly_pubkey_serialize(ctx, xOnlyPubkeySerialized, &xOnlyPubkey);

    
    secp256k1_ec_pubkey_serialize(ctx, (unsigned char *)&pubkey, &pubkeyLen, (const secp256k1_pubkey *)&xOnlyPubkey, SECP256K1_EC_COMPRESSED);

    PublicKeys publicKeys;
    publicKeys.key = convertToHex(pubkey, 33);
    publicKeys.xonly = convertToHex(xOnlyPubkeySerialized, 32);
    publicKeys.seckey = seckey;
    secp256k1_context_destroy(ctx);
    return publicKeys;
}

SignResult schnorrsig_sign(std::string seckey, std::string msg){
    secp256k1_context *ctx;
    ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);
    secp256k1_keypair keypair;
    deserialize_private_key(ctx, seckey, &keypair);

    const unsigned char *msg32 = (unsigned char *)&msg[0];

    const unsigned char sig64[64]{};
    secp256k1_schnorrsig_sign(ctx, (unsigned char *)sig64, msg32, &keypair, NULL, NULL);


    
    /*
    secp256k1_xonly_pubkey xOnlyPubkey{};
    unsigned char xOnlyPubkeySerialized[32], pubkey[33];
    size_t pubkeyLen = 33;
    for(int i=0; i<64; i++){
        xOnlyPubkey.data[i] = '0';
    }
    int pk_parity;
    int r = secp256k1_keypair_xonly_pub(ctx, &xOnlyPubkey, &pk_parity, &keypair);
    r = secp256k1_xonly_pubkey_serialize(ctx, xOnlyPubkeySerialized, &xOnlyPubkey);

    secp256k1_ec_pubkey_serialize(ctx, (unsigned char *)&pubkey, &pubkeyLen, (const secp256k1_pubkey *)&xOnlyPubkey, SECP256K1_EC_COMPRESSED);
    */
    
    SignResult signResult;
    signResult.sig = convertToHex(sig64, 64);
    signResult.error = "F7FFA59FE65EFCC9E6CD9C2F7535B7548B36B84004C0F158F6163E836EBA866ECC81C346BCB6D9B8F8A4067A0BA0A487D81501E913F47C6122974831CE75ADA6";
    secp256k1_context_destroy(ctx);
    return signResult;
}

Result deserializePrivateKey(std::string seckey){
    secp256k1_context *ctx;
    ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);
    secp256k1_keypair keypair;
    const unsigned char *privateKey = strToUnsignedChars(seckey);
    result.r = deserialize_private_key(ctx, seckey, &keypair);
    result.data = convertToString(privateKey)+"<nl>"+convertToHex(keypair.data, 96);
    secp256k1_context_destroy(ctx);
    return result;
}


Result ec_pubkey_parse(std::string pubKeyStr){
    secp256k1_context *ctx;
    ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    //secp256k1_context_randomize(ctx)

    secp256k1_pubkey xPubKey;

    const unsigned char *pubKey = strToUnsignedChars(pubKeyStr);
    int r = secp256k1_ec_pubkey_parse(ctx, &xPubKey, pubKey, 33);
    secp256k1_context_destroy(ctx);

    //char dataHex[64];
    //charArray2hexString(xonlyPubKey.data, dataHex);
    //result.data = convertToString(pubKey);
    result.r = r;
    result.data = convertToString(pubKey)+":1:"+convertToHex(xPubKey.data, 64);
    return result;
}

Result secp256k_xonly_pubkey_parse(std::string pubKeyStr){
    secp256k1_context *ctx;
    ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    //secp256k1_context_randomize(ctx)

    secp256k1_xonly_pubkey xonlyPubKey;

    const unsigned char *pubKey = strToUnsignedChars(pubKeyStr);
    int r = secp256k1_xonly_pubkey_parse(ctx, &xonlyPubKey, pubKey);
    secp256k1_context_destroy(ctx);

    //char dataHex[64];
    //charArray2hexString(xonlyPubKey.data, dataHex);
    //result.data = convertToString(pubKey);
    result.r = r;
    result.data = convertToString(pubKey)+"::"+convertToHex(xonlyPubKey.data, 64);
    return result;
} 


/*

void schnorr_sign(const unsigned char *sk, const unsigned char *pk_serialized, unsigned char *aux_rand, const unsigned char *msg, const unsigned char *expected_sig) {
    unsigned char sig[64];
    secp256k1_keypair keypair;
    secp256k1_xonly_pubkey pk, pk_expected;

    CHECK(secp256k1_keypair_create(ctx, &keypair, sk));
    CHECK(secp256k1_schnorrsig_sign(ctx, sig, msg, &keypair, NULL, aux_rand));
    CHECK(secp256k1_memcmp_var(sig, expected_sig, 64) == 0);

    CHECK(secp256k1_xonly_pubkey_parse(ctx, &pk_expected, pk_serialized));
    CHECK(secp256k1_keypair_xonly_pub(ctx, &pk, NULL, &keypair));
    CHECK(secp256k1_memcmp_var(&pk, &pk_expected, sizeof(pk)) == 0);
    CHECK(secp256k1_schnorrsig_verify(ctx, sig, msg, &pk));
}

*/

EMSCRIPTEN_BINDINGS(my_module) {
    //function("lerp", &lerp);
    function("ecdsa_sign", &ecdsa_sign_new);
    function("secp256k_xonly_pubkey_parse", &secp256k_xonly_pubkey_parse);
    function("ec_pubkey_parse", &ec_pubkey_parse);
    function("deserializePrivateKey", &deserializePrivateKey);
    function("test_keypair_seckey", &test_keypair_seckey);
    function("export_public_keys", &export_public_keys);
    function("schnorrsig_sign", &schnorrsig_sign);
    

    value_object<Result>("Result")
        .field("data", &Result::data)
        .field("c", &Result::c)
        .field("r", &Result::r);

    value_object<PublicKeys>("PublicKeys")
        .field("key", &PublicKeys::key)
        .field("xonly", &PublicKeys::xonly)
        .field("seckey", &PublicKeys::seckey);

    value_object<SignResult>("SignResult")
        .field("sig", &SignResult::sig)
        .field("error", &SignResult::error);

    /*
    value_object<SignResult>("SignResult")
        .field("sig", &SignResult::sig)
        //.field("sig2", &SignResult::sig2)
        //.field("msg", &SignResult::msg)
        //.field("privKey", &SignResult::privKey)
        ;
    */
    

}

