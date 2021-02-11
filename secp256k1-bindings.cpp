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

}
using namespace emscripten;

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

std::string convertToString(char* a){
    std::string s = a; 
    return s; 
}

std::string convertToString(const unsigned char* a){//, int size)
    std::string s = std::string( reinterpret_cast< const char* >(a)); 
    return s; 
}

char const hex[16] = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B','C','D','E','F'};

std::string convertToHex(unsigned char* data, int len) {
  std::string str;
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
  for (int i = 0; i < len; ++i) {
    const char ch = data[i];
    //printf("ch: %c\n", ch);
    str.append(&hex[(ch & 0xF0) >> 4], 1);
    str.append(&hex[ch & 0x0F], 1);
  }
  return str;
}

void hexToBytes(const std::string& hex, unsigned char* data) {
    std::string byteString;

    for (unsigned int i = 0; i < hex.length(); i += 2) {
        byteString = hex.substr(i, 2);
        const unsigned char byte = (char) strtol(byteString.c_str(), NULL, 16);
        *(data++) = byte;
    }
}

struct Result {
    std::string data;
    unsigned char c;
    int r;
};

struct PublicKeys{
    std::string key;
    std::string pubkey;
    std::string xonly;
    std::string seckey;
};

struct SignResult{
    std::string sig;
    std::string error;
};

struct ProcessResult{
    bool success;
    std::string error;
    std::string info;
};

static secp256k1_context *ctx = NULL;

bool create_context() {
    ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    return ctx ? true : false;
}

bool destroy_context() {
    secp256k1_context_destroy(ctx);
    ctx = NULL;
    return true;
}

void ensure_context() {
    if(!ctx)
        ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
}

int deserialize_private_key(secp256k1_context *ctx, std::string private_key, secp256k1_keypair *keypair){
    unsigned char privateKey[32];
    hexToBytes(private_key, privateKey);
    return secp256k1_keypair_create(ctx, keypair, privateKey);
}

PublicKeys export_public_keys(std::string seckey){
    ensure_context();
    secp256k1_keypair keypair;
    deserialize_private_key(ctx, seckey, &keypair);

    secp256k1_xonly_pubkey xOnlyPubkey{};
    unsigned char xOnlyPubkeySerialized[32], pubkey[33], pubkeyFull[65];
    size_t pubkeyLen = 33, pubkeyLenFull = 65;
    int pk_parity;
    int r = secp256k1_keypair_xonly_pub(ctx, &xOnlyPubkey, &pk_parity, &keypair);
    r = secp256k1_xonly_pubkey_serialize(ctx, xOnlyPubkeySerialized, &xOnlyPubkey);

    secp256k1_ec_pubkey_serialize(ctx, pubkeyFull, &pubkeyLenFull, (const secp256k1_pubkey *)&xOnlyPubkey, SECP256K1_EC_UNCOMPRESSED);
    secp256k1_ec_pubkey_serialize(ctx, pubkey, &pubkeyLen, (const secp256k1_pubkey *)&xOnlyPubkey, SECP256K1_EC_COMPRESSED);

    //printf("pubkeyFull fsdsd fds fdsf dsf sgfd gdf gdfgd fgs dasfs f sdfs fsd sdf %s\n", pubkeyFull);

    PublicKeys publicKeys;
    publicKeys.key = convertToHex(pubkeyFull, 65);
    publicKeys.pubkey = convertToHex(pubkey, 33);
    publicKeys.xonly = convertToHex(xOnlyPubkeySerialized, 32);
    publicKeys.seckey = seckey;

    return publicKeys;
}


std::string export_public_key_xonly(std::string seckey) {
    ensure_context();
    secp256k1_keypair keypair;
    deserialize_private_key(ctx, seckey, &keypair);

    secp256k1_xonly_pubkey xOnlyPubkey{};
    unsigned char xOnlyPubkeySerialized[32];
    int pk_parity;
    int r = secp256k1_keypair_xonly_pub(ctx, &xOnlyPubkey, &pk_parity, &keypair);
    r = secp256k1_xonly_pubkey_serialize(ctx, xOnlyPubkeySerialized, &xOnlyPubkey);

    return convertToHex(xOnlyPubkeySerialized, 32);
}


SignResult schnorrsig_sign(std::string seckey, std::string msg32){
    ensure_context();
    secp256k1_keypair keypair;
    deserialize_private_key(ctx, seckey, &keypair);

    unsigned char msg[32];
    hexToBytes(msg32, msg);

    unsigned char sig[64];
    secp256k1_schnorrsig_sign(ctx, sig, msg, &keypair, NULL, NULL);
    
    SignResult signResult;
    signResult.sig = convertToHex(sig, 64);
    signResult.error = "";
    return signResult;
}

Result deserializePrivateKey(std::string seckey){
    ensure_context();
    secp256k1_keypair keypair;
    unsigned char privateKey[32];
    hexToBytes(seckey, privateKey);
    Result result;
    result.r = deserialize_private_key(ctx, seckey, &keypair);
    result.data = convertToString(privateKey)+"<nl>"+convertToHex(keypair.data, 96);
    return result;
}

Result xonly_pubkey_parse(std::string pubKeyStr){
    ensure_context();

    secp256k1_xonly_pubkey xonlyPubKey;

    unsigned char pubKey[64];
    hexToBytes(pubKeyStr, pubKey);
    int r = secp256k1_xonly_pubkey_parse(ctx, &xonlyPubKey, pubKey);

    Result result;
    result.r = r;
    result.data = convertToHex(xonlyPubKey.data, 64);
    return result;
}

ProcessResult schnorrsig_verify(std::string sig64, std::string msg32, std::string xonlykey32){
    ensure_context();

    secp256k1_xonly_pubkey xonlyPubKey;

    unsigned char sig[64];
    hexToBytes(sig64, sig);

    unsigned char msg[32];
    hexToBytes(msg32, msg);

    unsigned char pubKey[32];
    hexToBytes(xonlykey32, pubKey);

    int r = secp256k1_xonly_pubkey_parse(ctx, &xonlyPubKey, pubKey);
    //printf("secp256k1_xonly_pubkey_parse: %d, pubKey: %s\n", r, pubKey);
    r = secp256k1_schnorrsig_verify(ctx, sig, msg, &xonlyPubKey);

    ProcessResult pResult;
    pResult.success = r==1;
    pResult.info = convertToHex(xonlyPubKey.data, 64)+", sig:"+convertToHex(sig, 64);
    return pResult;
}


EMSCRIPTEN_BINDINGS(my_module) {
    function("create_context", &create_context);
    function("destroy_context", &destroy_context);

    function("deserializePrivateKey", &deserializePrivateKey);
    function("xonly_pubkey_parse", &xonly_pubkey_parse);
    function("export_public_keys", &export_public_keys);
    function("export_public_key_xonly", &export_public_key_xonly);
    function("schnorrsig_sign", &schnorrsig_sign);
    function("schnorrsig_verify", &schnorrsig_verify);
    

    value_object<Result>("Result")
        .field("data", &Result::data)
        .field("c", &Result::c)
        .field("r", &Result::r);

    value_object<PublicKeys>("PublicKeys")
        .field("key", &PublicKeys::key)
        .field("pubkey", &PublicKeys::pubkey)
        .field("xonly", &PublicKeys::xonly)
        .field("seckey", &PublicKeys::seckey);

    value_object<SignResult>("SignResult")
        .field("sig", &SignResult::sig)
        .field("error", &SignResult::error);

    value_object<ProcessResult>("ProcessResult")
        .field("success", &ProcessResult::success)
        .field("error", &ProcessResult::error)
        .field("info", &ProcessResult::info);

}

