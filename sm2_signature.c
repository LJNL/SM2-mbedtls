//
//  sm2_signature.c
//  mbedtlsSM2
//
//  Created by mac on 2018/4/18.
//  Copyright © 2018年 mac. All rights reserved.
//

#include "sm2_signature.h"
#include "dependAlgorithm.h"
#include "string.h"
#define BN2BIN_SIZE 512
uint8_t bn2binbuffer[BN2BIN_SIZE];
#define HASH_BUFFER_APPEND_BIN(SM2_HASH, SIZE) \
memcpy(SM2_HASH.buffer+SM2_HASH.position, bn2binbuffer+512-SIZE, SIZE); \
SM2_HASH.position+=SIZE;

#define HASH_BUFFER_APPEND_STR(SM2_HASH, SRC_BUFF,SIZE) \
memcpy(SM2_HASH.buffer+SM2_HASH.position, SRC_BUFF, SIZE); \
SM2_HASH.position+=SIZE;

size_t byte_length(size_t bit_length)
{
    return (bit_length+7)/8;
}


int sm2_sign(mbedtls_ecp_group *ecp, sm2_sign_ctx *sign)
{
    int res=0;
    sm2_hash Z_A;
    sm2_hash e;
    size_t num_size;
    
    mbedtls_mpi e_n,k_n,r_n,s_n,temp;
    mbedtls_mpi_init(&s_n);
    mbedtls_mpi_init(&e_n);
    mbedtls_mpi_init(&k_n);
    mbedtls_mpi_init(&r_n);
    mbedtls_mpi_init(&temp);
    
    mbedtls_ecp_point kG;
    mbedtls_ecp_point_init(&kG);
    
    //step 1
    memset(&Z_A,0,sizeof(Z_A));
    //Z =H (ENTL ∥ ID A ∥ a ∥ b ∥ x G ∥ y G ∥ x A ∥ y A )。
    Z_A.buffer[0]=((sign->ENTL*8)>>8) & 0xff;// need to convert bytes to bits ,so multiply 8
    Z_A.buffer[1]=(sign->ENTL*8) & 0xff;
    Z_A.position+=2;
    
    HASH_BUFFER_APPEND_STR(Z_A ,sign->ID,sign->ENTL)
    
    res=mbedtls_mpi_write_binary(&ecp->A, bn2binbuffer, BN2BIN_SIZE);
    MBEDTLS_ERR_PRINT(res)
    num_size=mbedtls_mpi_size(&ecp->A);
    HASH_BUFFER_APPEND_BIN(Z_A, num_size)
    
    
    res=mbedtls_mpi_write_binary(&ecp->B, bn2binbuffer, BN2BIN_SIZE);
    MBEDTLS_ERR_PRINT(res)
    num_size=mbedtls_mpi_size(&ecp->B);
    HASH_BUFFER_APPEND_BIN(Z_A, num_size)
    
    
    res=mbedtls_mpi_write_binary(&ecp->G.X, bn2binbuffer, BN2BIN_SIZE);
    MBEDTLS_ERR_PRINT(res)
    num_size=mbedtls_mpi_size(&ecp->G.X);
    HASH_BUFFER_APPEND_BIN(Z_A, num_size)
    
    
    res=mbedtls_mpi_write_binary(&ecp->G.Y, bn2binbuffer, BN2BIN_SIZE);
    MBEDTLS_ERR_PRINT(res)
    num_size=mbedtls_mpi_size(&ecp->G.Y);
    HASH_BUFFER_APPEND_BIN(Z_A, num_size)
    
    
    res=mbedtls_mpi_write_binary(&sign->key_pair->Q.X, bn2binbuffer, BN2BIN_SIZE);
    MBEDTLS_ERR_PRINT(res)
    num_size=mbedtls_mpi_size(&sign->key_pair->Q.X);
    HASH_BUFFER_APPEND_BIN(Z_A, num_size)
    
    
    res=mbedtls_mpi_write_binary(&sign->key_pair->Q.Y, bn2binbuffer, BN2BIN_SIZE);
    MBEDTLS_ERR_PRINT(res)
    num_size=mbedtls_mpi_size(&sign->key_pair->Q.Y);
    HASH_BUFFER_APPEND_BIN(Z_A, num_size)
    
    res=hash256(Z_A.buffer, Z_A.position, Z_A.hash);
    MBEDTLS_ERR_PRINT(res)
    memcpy(sign->Z, Z_A.hash, HASH_BYTE_LENGTH);
    
    //show the Z_HASH
    //show_string(Z_A.hash,HASH_BYTE_LENGTH);
    
    
    //step 2
    memset(&e, 0, sizeof(e));
    
    HASH_BUFFER_APPEND_STR(e,sign->Z,HASH_BYTE_LENGTH)
    HASH_BUFFER_APPEND_STR(e, sign->message,sign->message_size)
    
    hash256(e.buffer, e.position, e.hash);
    //show
    //show_string(e.hash,HASH_BYTE_LENGTH);
    
    res=mbedtls_mpi_read_binary(&e_n, e.hash, HASH_BYTE_LENGTH);
    MBEDTLS_ERR_PRINT(res)

    //step 3
    /*
    res=random_number(sign->k, MAX_POINT_BYTE_LENGTH);
    res=mbedtls_mpi_read_binary(&k_n, sign->k, MAX_POINT_BYTE_LENGTH);
     */
    res=random_num(&k_n, byte_length(ecp->nbits), &ecp->N);
    MBEDTLS_ERR_PRINT(res)
    res=mbedtls_mpi_write_binary(&k_n, sign->k, byte_length(ecp->nbits));
    MBEDTLS_ERR_PRINT(res)
    
    //step 4
    res=mbedtls_ecp_mul(ecp,  &kG, &k_n, &ecp->G, NULL, NULL);
    MBEDTLS_ERR_PRINT(res)
    
    //step 5
    res=mbedtls_mpi_add_mpi(&r_n, &e_n, &kG.X);
    MBEDTLS_ERR_PRINT(res)
    res=mbedtls_mpi_mod_mpi(&r_n, &r_n, &ecp->N);
    MBEDTLS_ERR_PRINT(res)
    
    //step 6
    res=mbedtls_mpi_add_int(&temp, &sign->key_pair->d, 1);
    MBEDTLS_ERR_PRINT(res)
    res=mbedtls_mpi_inv_mod(&temp, &temp, &ecp->N);
    MBEDTLS_ERR_PRINT(res)
    
    res=mbedtls_mpi_mul_mpi(&s_n, &r_n, &sign->key_pair->d);
    MBEDTLS_ERR_PRINT(res)
    res=mbedtls_mpi_sub_mpi(&s_n, &k_n, &s_n);
    MBEDTLS_ERR_PRINT(res)
    
    res=mbedtls_mpi_mul_mpi(&s_n, &temp, &s_n);
    MBEDTLS_ERR_PRINT(res)
    res=mbedtls_mpi_mod_mpi(&s_n, &s_n, &ecp->N);
    MBEDTLS_ERR_PRINT(res)
    
    res=mbedtls_mpi_write_binary(&r_n, sign->r, byte_length(ecp->nbits));
    MBEDTLS_ERR_PRINT(res)
    res=mbedtls_mpi_write_binary(&s_n, sign->s, byte_length(ecp->nbits));
    MBEDTLS_ERR_PRINT(res)
    
cleanup:
    //free
    //return 0;
    //mbedtls_mpi e_n,k_n,r_n,s_n,temp;
    mbedtls_mpi_free(&e_n);
    mbedtls_mpi_free(&k_n);
    mbedtls_mpi_free(&r_n);
    mbedtls_mpi_free(&s_n);
    mbedtls_mpi_free(&temp);
    mbedtls_ecp_point_free(&kG);
    return res;
}

int sm2_verify(mbedtls_ecp_group *ecp, sm2_sign_ctx *sign)
{
    sm2_hash e;
    int res=0;
    mbedtls_mpi e_n,r_n,s_n,t_n,R_n;
    mbedtls_ecp_point sGtP;
    
    mbedtls_ecp_point_init(&sGtP);
    mbedtls_mpi_init(&e_n);
    mbedtls_mpi_init(&r_n);
    mbedtls_mpi_init(&s_n);
    mbedtls_mpi_init(&t_n);
    mbedtls_mpi_init(&R_n);
    
    memset(&e, 0, sizeof(e));
    
    //step 3 4
    HASH_BUFFER_APPEND_STR(e, sign->Z, HASH_BYTE_LENGTH);
    HASH_BUFFER_APPEND_STR(e, sign->message, sign->message_size);
    res=hash256(e.buffer, e.position, e.hash);
    MBEDTLS_ERR_PRINT(res)
    
    //show_string(e.hash, HASH_BYTE_LENGTH);
    
    res=mbedtls_mpi_read_binary(&e_n, e.hash, HASH_BYTE_LENGTH);
    MBEDTLS_ERR_PRINT(res)
    //step 5
    res=mbedtls_mpi_read_binary(&r_n,sign->r, byte_length(ecp->nbits));
    MBEDTLS_ERR_PRINT(res)
    res=mbedtls_mpi_read_binary(&s_n,sign->s, byte_length(ecp->nbits));
    MBEDTLS_ERR_PRINT(res)
    
    res=mbedtls_mpi_add_mpi(&t_n, &r_n, &s_n);
    MBEDTLS_ERR_PRINT(res)
    res=mbedtls_mpi_mod_mpi(&t_n, &t_n, &ecp->N);
    MBEDTLS_ERR_PRINT(res)
    
    //step 6
    res=mbedtls_ecp_muladd(ecp, &sGtP, &s_n, &ecp->G, &t_n, &sign->key_pair->Q);
    MBEDTLS_ERR_PRINT(res)
    
    //step 7
    res=mbedtls_mpi_add_mpi(&R_n, &e_n, &sGtP.X);
    MBEDTLS_ERR_PRINT(res)
    res=mbedtls_mpi_mod_mpi(&R_n, &R_n, &ecp->N);
    MBEDTLS_ERR_PRINT(res)
    res=mbedtls_mpi_cmp_mpi(&R_n, &r_n);
    MBEDTLS_ERR_PRINT(res)
cleanup:
    mbedtls_ecp_point_free(&sGtP);
    mbedtls_mpi_free(&e_n);
    mbedtls_mpi_free(&r_n);
    mbedtls_mpi_free(&s_n);
    mbedtls_mpi_free(&t_n);
    mbedtls_mpi_free(&R_n);
    return res;
    
}













