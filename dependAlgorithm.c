//
//  dependAlgorithm.c
//  mbedtlsSM2
//
//  Created by mac on 2018/4/18.
//  Copyright © 2018年 mac. All rights reserved.
//

#include "entropy.h"
#include "ctr_drbg.h"
#include "md.h"
#include "bignum.h"
#include "dependAlgorithm.h"
int random_number( unsigned char *buf, size_t bufsize )
{
    int  ret;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_entropy_context entropy;
    
    mbedtls_ctr_drbg_init( &ctr_drbg );
    
    
    mbedtls_entropy_init( &entropy );
    ret = mbedtls_ctr_drbg_seed( &ctr_drbg, mbedtls_entropy_func, &entropy, (const unsigned char *) "RANDOM_GEN", 10 );
    if( ret != 0 )
    {
        mbedtls_printf( "failed in mbedtls_ctr_drbg_seed: %d\n", ret );
        goto cleanup;
    }
    mbedtls_ctr_drbg_set_prediction_resistance( &ctr_drbg, MBEDTLS_CTR_DRBG_PR_OFF );
    
    
    
    ret = mbedtls_ctr_drbg_random( &ctr_drbg, buf, bufsize);
    if( ret != 0 )
    {
        mbedtls_printf("failed!\n");
        goto cleanup;
    }
    
    
    ret = 0;
    
cleanup:
    mbedtls_printf("\n");
    
    mbedtls_ctr_drbg_free( &ctr_drbg );
    mbedtls_entropy_free( &entropy );
    
    return( ret );
}

int hash256(unsigned char *input, size_t bufsize,unsigned char * output)
{
    //conversion
    int ret=0;
    mbedtls_md_context_t mdctx;
    mbedtls_md_type_t mdtype=MBEDTLS_MD_SHA256;
    mbedtls_md_info_t* mdinfo=mbedtls_md_info_from_type(mdtype);
    mbedtls_md_init(&mdctx);
    ret=mbedtls_md_setup(&mdctx, mdinfo, 0);
    MBEDTLS_ERR_PRINT(ret)
    ret=mbedtls_md_starts(&mdctx);
    MBEDTLS_ERR_PRINT(ret)
    ret=mbedtls_md_update(&mdctx, input, bufsize);
    MBEDTLS_ERR_PRINT(ret)
    ret=mbedtls_md_finish(&mdctx, output);
    MBEDTLS_ERR_PRINT(ret)
cleanup:
    mbedtls_md_free(&mdctx);
    return ret;
}

//a<b
int random_num(mbedtls_mpi* a,size_t bytes, mbedtls_mpi* b)
{

    
    int  ret;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_entropy_context entropy;
    
    mbedtls_ctr_drbg_init( &ctr_drbg );
    
    
    mbedtls_entropy_init( &entropy );
    ret = mbedtls_ctr_drbg_seed( &ctr_drbg, mbedtls_entropy_func, &entropy, (const unsigned char *) "RANDOM_GEN", 10 );
    if( ret != 0 )
    {
        mbedtls_printf( "failed in mbedtls_ctr_drbg_seed: %d\n", ret );
        goto cleanup;
    }
    mbedtls_ctr_drbg_set_prediction_resistance( &ctr_drbg, MBEDTLS_CTR_DRBG_PR_OFF );
    
    
    MBEDTLS_MPI_CHK( mbedtls_mpi_fill_random( a, bytes, mbedtls_ctr_drbg_random, &ctr_drbg) );
        
    while( mbedtls_mpi_cmp_mpi( a,b  ) >= 0 )
        MBEDTLS_MPI_CHK( mbedtls_mpi_shift_r( a, 1 ) );
    
    ret = 0;
    
cleanup:
    mbedtls_printf("\n");
    
    mbedtls_ctr_drbg_free( &ctr_drbg );
    mbedtls_entropy_free( &entropy );
    
    return( ret );
}

void show_string(int8_t *string, size_t len)
{
    int j;
    for (j = 0; j < len; j++)
    {
        printf("%02X", string[j]);
        if ((j+1) % 32 == 0 && (j+1) != len)
        {
            printf("\n");
        }
        else if ((j+1) % 4 == 0)
        {
            printf(" ");
        }
    }
}
