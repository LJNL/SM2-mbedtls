//
//  dependAlgorithm.h
//  mbedtlsSM2
//
//  Created by mac on 2018/4/18.
//  Copyright © 2018年 mac. All rights reserved.
//

#ifndef dependAlgorithm_h
#define dependAlgorithm_h
#include <stdio.h>
#define mbedtls_printf printf
#define MBEDTLS_ERR_PRINT(ret) if( ret != 0 ) \
{\
mbedtls_printf( "Failed--line: %s code: %d\n",__LINE__, ret );\
goto cleanup;\
}

int random_number( unsigned char *buf, size_t bufsize );
int random_num(mbedtls_mpi* a,size_t bytes, mbedtls_mpi* b);
int hash256(unsigned char *input, size_t bufsize,unsigned char * output);
void show_string(int8_t *string, size_t len);
#endif /* dependAlgorithm_h */
