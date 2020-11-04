/**********************************************************************
 * Copyright (c) 2014 Pieter Wuille                                   *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#include <emscripten/bind.h>
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

    #include "secp256k1.c"
    #include "include/secp256k1.h"
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
        printf("MSG: %s\nHEX: %s\n", msg, msgHashHex);
        

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
        
        printf("sig: %s\n", hex);
        charArray2hexString(data.key, privKeyHex);
        
        printf("privKey: %s\n", privKeyHex);
    }


    int main111(void) {

        /*int i;
        secp256k1_pubkey pubkey;
        secp256k1_ecdsa_signature sig;
        benchmark_verify_t data;

        data.ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);

        for (i = 0; i < 32; i++) {
            data.msg[i] = 1 + i;
        }
        for (i = 0; i < 32; i++) {
            data.key[i] = 33 + i;
        }
        data.siglen = 72;
        CHECK(secp256k1_ecdsa_sign(data.ctx, &sig, data.msg, data.key, NULL, NULL));
        CHECK(secp256k1_ecdsa_signature_serialize_der(data.ctx, data.sig, &data.siglen, &sig));
        CHECK(secp256k1_ec_pubkey_create(data.ctx, &pubkey, data.key));
        data.pubkeylen = 33;
        CHECK(secp256k1_ec_pubkey_serialize(data.ctx, data.pubkey, &data.pubkeylen, &pubkey, SECP256K1_EC_COMPRESSED) == 1);

        run_benchmark("ecdsa_verify", benchmark_verify, NULL, NULL, &data, 10, 20000);
    #ifdef ENABLE_OPENSSL_TESTS
        data.ec_group = EC_GROUP_new_by_curve_name(NID_secp256k1);
        run_benchmark("ecdsa_verify_openssl", benchmark_verify_openssl, NULL, NULL, &data, 10, 20000);
        EC_GROUP_free(data.ec_group);
    #endif

        secp256k1_context_destroy(data.ctx);
        */
        printf("secp module loaded!\n");
        return 0;
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

char const hex[16] = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A',   'B','C','D','E','F'};

std::string convertToHex(unsigned char* data, int len) {
  std::string str;
  //int len = 10;//sizeof(data);
  printf("len: %i\n", len);
  for (int i = 0; i < len; ++i) {
    const char ch = data[i];
    str.append(&hex[(ch  & 0xF0) >> 4], 1);
    str.append(&hex[ch & 0xF], 1);
  }
  return str;
}



struct SignResult {
    std::string sig;
    std::string sig2;
    std::string msg;
    std::string privKey;
};
SignResult result;
SignResult ecdsa_sign_new(std::string _msg, std::string privKey){
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
    result.msg = convertToString(msgHashHex);
    result.privKey = privKey;//convertToString(privKeyHex);
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
    result.sig = convertToHex(sig.data, 64);

    return result;
}

EMSCRIPTEN_BINDINGS(my_module) {
    //function("lerp", &lerp);
    function("ecdsa_sign", &ecdsa_sign_new);

    value_object<SignResult>("SignResult")
        .field("sig", &SignResult::sig)
        .field("sig2", &SignResult::sig2)
        //.field("msg", &SignResult::msg)
        //.field("privKey", &SignResult::privKey)
        ;
}

