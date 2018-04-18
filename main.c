//
//  main.c
//  mbedtlsSM2
//
//  Created by mac on 2018/4/16.
//  Copyright © 2018年 mac. All rights reserved.
//
#define ECP_SHORTWEIERSTRASS
#include <stdio.h>
#include <string.h>
#include "sm2_signature.h"
#include "ecp.h"
#include "entropy.h"
#include "ctr_drbg.h"
#include "md.h"
#include "entropy.h"
#include "ctr_drbg.h"
#include "sm2_test_param.h"
#define MAX_POINT_BYTE_LENGTH 64
#define HASH_BYTE_LENGTH 32



int main(int argc, const char * argv[]) {
    // insert code here...
    int res=0;
    mbedtls_ecp_group ecp_g; //param
    mbedtls_ecp_keypair ecp_k;// key
    sm2_sign_ctx ctx;
    
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_entropy_init(&entropy);
    
    mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, NULL, 0);
    
    
    mbedtls_ecp_group_init(&ecp_g);
    mbedtls_ecp_keypair_init(&ecp_k);
    memset(&ctx, 0, sizeof(ctx));
    
    //param init
    //sm2_param_recommand
    res=mbedtls_mpi_read_string(&ecp_g.P, 16, sm2_param_recommand[0]);
    res=mbedtls_mpi_read_string(&ecp_g.A, 16, sm2_param_recommand[1]);
    res=mbedtls_mpi_read_string(&ecp_g.B, 16, sm2_param_recommand[2]);
    res=mbedtls_mpi_read_string(&ecp_g.G.X, 16, sm2_param_recommand[3]);
    res=mbedtls_mpi_read_string(&ecp_g.G.Y, 16, sm2_param_recommand[4]);
    res=mbedtls_mpi_read_string(&ecp_g.G.Z, 16, "1");
    res=mbedtls_mpi_read_string(&ecp_g.N, 16, sm2_param_recommand[5]);
    ecp_g.nbits=mbedtls_mpi_bitlen(&ecp_g.N);
    ecp_g.pbits=mbedtls_mpi_bitlen(&ecp_g.P);

    
    
    //key gen
    res=mbedtls_ecp_gen_keypair_base( &ecp_g,&ecp_g.G,&ecp_k.d, &ecp_k.Q,mbedtls_ctr_drbg_random, &ctr_drbg);
    ctx.key_pair=&ecp_k;
    
   
    //ctx param
    ctx.message=message;
    ctx.message_size=10;
    
    ctx.ID=ID_A;
    ctx.ENTL=12;
    
    
    //verify curve
    res=mbedtls_ecp_check_pubkey(&ecp_g, &ecp_g.G);
    
    //signature
    res=sm2_sign(&ecp_g, &ctx);
    res=sm2_verify(&ecp_g, &ctx);
    if(res==0)
        printf("\nverify ok\n");
    
    
    mbedtls_ecp_group_free(&ecp_g);
    mbedtls_ecp_keypair_free(&ecp_k);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);

    return 0;
}


