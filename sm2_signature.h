//
//  sm2_signature.h
//  mbedtlsSM2
//
//  Created by mac on 2018/4/18.
//  Copyright © 2018年 mac. All rights reserved.
//

#ifndef sm2_signature_h
#define sm2_signature_h

#include <stdio.h>
#include "ecp.h"
#define MAX_POINT_BYTE_LENGTH 64
#define HASH_BYTE_LENGTH 32

typedef struct {
    
    uint8_t *message;// Message
    size_t message_size;
    
    uint8_t *ID; //distinguishing identifier
    size_t ENTL;
    
    mbedtls_ecp_keypair * key_pair;
    
    uint8_t Z[HASH_BYTE_LENGTH];
    uint8_t k[MAX_POINT_BYTE_LENGTH];
    uint8_t r[MAX_POINT_BYTE_LENGTH];
    uint8_t s[MAX_POINT_BYTE_LENGTH];
    uint8_t R[MAX_POINT_BYTE_LENGTH];
}sm2_sign_ctx;

typedef struct
{
    uint8_t buffer[1024];
    int position;
    uint8_t hash[HASH_BYTE_LENGTH];
} sm2_hash;


int sm2_sign(mbedtls_ecp_group *ecp, sm2_sign_ctx *sign);
int sm2_verify(mbedtls_ecp_group *ecp, sm2_sign_ctx *sign);
#endif /* sm2_signature_h */
