#pragma once
#ifndef PROTOCOL_H_
#define PROTOCOL_H_

#include <cstdint>
#include <aes.h>

#define DEFAULT 0

/* 
Handles all protocols for the program

lots of consts, enums and structs for the different protocols and sizes defined in the assignment
there aren't many comments here because the code is fairly repetitive and self explanitory
*/


typedef uint8_t  version_t;
typedef uint16_t code_t;
typedef uint32_t csize_t;

// all in bytes
const version_t VERSION	        = 3;
const size_t	CLIENT_ID_SIZE	= 16;
const size_t	NAME_SIZE		= 255;
const size_t	PUBLIC_KEY_SIZE = 160;
const size_t	SYMM_KEY_SIZE	= 16; // 128 bits
const size_t	REQUEST_OPTIONS = 6;
const size_t	RESPONSE_OPTIONS= 8;
const size_t    MAX_ENC_SYM_SIZE= 1024;
const size_t    ENC_BATCH_SIZE  = 1024;
const size_t    HEADER_SIZE     = 7 + 16;


enum RequestCodes {
    REQUEST_REGISTRATION    = 1100,
    REQUEST_PUBLIC_KEY      = 1101,
    REQUEST_LOGIN           = 1102,
    REQUEST_SEND_FILE       = 1103,
    REQUEST_VALID_CRC       = 1104,
    REQUEST_WARNING_CRC     = 1105,
    REQUEST_ERROR_CRC       = 1106
};


enum ResponseCodes {
    RESPONSE_REGISTRATION           = 2100,
    RESPONSE_FAILED_REGISTRATION    = 2101,
    RESPONSE_PUBLIC_KEY             = 2102,
    RESPONSE_FILE                   = 2103,
    RESPONSE_RECEIVED               = 2104,
    RESPONSE_LOGIN                  = 2105,
    RESPONSE_FAILED_LOGIN           = 2106,
    RESPONSE_ERROR                  = 2107
};

// fixes padding in the structs
#pragma pack (1)

// strusts for the different components passed through the protocols
struct sClientID {
    uint8_t uuid[CLIENT_ID_SIZE];
    sClientID() : uuid{ DEFAULT } {}
};

struct sClientName {
    uint8_t name[NAME_SIZE];
    sClientName() : name{ DEFAULT } {}
};

struct sPublicKey {
    uint8_t publicKey[PUBLIC_KEY_SIZE];
    sPublicKey() : publicKey{ DEFAULT } {}
};

struct sSymmetricKey {
    uint8_t symmetricKey[SYMM_KEY_SIZE];
    sSymmetricKey() : symmetricKey{ DEFAULT } {}
};

struct sEncSymmKey {
    uint8_t encSymmetricKey[MAX_ENC_SYM_SIZE];
    sEncSymmKey() : encSymmetricKey{ DEFAULT } {}
};

struct sFileName {
    uint8_t name[NAME_SIZE];
    sFileName() : name{ DEFAULT } {}
};

struct sFileContent {
    uint8_t file[ENC_BATCH_SIZE];
    sFileContent() : file{ DEFAULT } {}
};

// structs for requests
struct sRequestHeader {
    sClientID       clientID;
    const version_t version;
    const code_t    code;
    csize_t         payloadSize;
    sRequestHeader(const code_t requestCode) : version(VERSION), code(requestCode), payloadSize(DEFAULT) {}
    sRequestHeader(const sClientID& id, const code_t requestCode) : clientID(id), version(VERSION), code(requestCode), payloadSize(DEFAULT) {}
};

struct sRegistrationRequest {
    sRequestHeader header;
    struct {
        sClientName clientName;
    } payload;
    sRegistrationRequest() : header(REQUEST_REGISTRATION) {}
};

struct sPublicKeyRequest {
    sRequestHeader header;
    struct {
        sClientName clientName;
        sPublicKey  publicKey;
    } payload;
    sPublicKeyRequest() : header(REQUEST_PUBLIC_KEY) {}
};

struct sLoginRequest {
    sRequestHeader header;
    struct {
        sClientName clientName;
    } payload;
    sLoginRequest() : header(REQUEST_LOGIN) {}
};

struct sFileSendRequest {
    sRequestHeader header;
    struct {
        csize_t     contentSize;
        sFileName   fileName;
        sFileContent msgContent;
    } payload;
    sFileSendRequest() : header(REQUEST_SEND_FILE) {}
};

struct sValidCRCRequest {
    sRequestHeader header;
    struct {
        sFileName   fileName;
    } payload;
    sValidCRCRequest() : header(REQUEST_VALID_CRC) {}
};

struct sWarningCRCRequest {
    sRequestHeader header;
    struct {
        sFileName   fileName;
    } payload;
    sWarningCRCRequest() : header(REQUEST_WARNING_CRC) {}
};

struct sErrorCRCRequest {
    sRequestHeader header;
    struct {
        sFileName   fileName;
    } payload;
    sErrorCRCRequest() : header(REQUEST_ERROR_CRC) {}
};

// structs for responses
struct sResponseHeader {
    const version_t version;
    const code_t    code;
    csize_t         payloadSize;
    sResponseHeader() : version(DEFAULT), code(DEFAULT), payloadSize(DEFAULT) {}
};

struct sRegistrationResponse {  // 2100
    sResponseHeader header;
    struct {
        sClientID   clientID;
    } payload;
};

struct sRegistrationFailedResponse { // 2101
    sResponseHeader header;
};

struct sPublicKeyResponse { // 2102
    sResponseHeader header;
    struct {
        sClientID   clientID;
        sEncSymmKey encSymmKey;
    } payload;
};

struct sCRCResponse { // 2103
    sResponseHeader header;
    struct {
        sClientID   clientID;
        csize_t     contentSize;
        sFileName   fileName;
        csize_t     checkSum;
    } payload;
};

struct sGenericResponse { // 2104
    sResponseHeader header;
    struct {
        sClientID   clientID;
    } payload;
};

struct sLoginResponse { // 2105
    sResponseHeader header;
    struct {
        sClientID   clientID;
        sEncSymmKey encSymmKey;
    } payload;
};

struct sLoginFailedResponse { // 2106
    sResponseHeader header;
    struct {
        sClientID   clientID;
    } payload;
};

struct sErrorResponse { // 2107
    sResponseHeader header;
};



#endif
