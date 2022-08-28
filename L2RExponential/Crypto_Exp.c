//20220809 BoB 11기 이예찬
#include <stdio.h> 
#include <openssl/bn.h>

void printBN(char *msg, BIGNUM *a){
        char *number_str = BN_bn2dec(a);
        printf("%s %s\n", msg, number_str);
        OPENSSL_free(number_str);
}

int ExpMod(BIGNUM *r, const BIGNUM *a, const BIGNUM *e, BIGNUM *m){
        BIGNUM *A = BN_dup(a);                                  //Definition A, initialized with a
        BN_CTX *ctx = BN_CTX_new();
        int binary_size = BN_num_bytes(e);                      //e's byte size
        unsigned char * binary = malloc(binary_size * sizeof(char));    //allocate memory
        BN_bn2bin(e, binary);                                   //*binary is e's binary array
        int k = BN_num_bits(e);                                 //e's number of bits
        int pos = (binary_size * 8) - k + 1;                    //calculating start position, 
        int i = 0, j = 0;                                       //loop byte, loop residue bit
        
        for(i = 0; i < BN_num_bytes(e); i++){                   //L2R
                char tmp_binary = binary[i];
                for(j = pos; j < 8; j++){
                        BN_mod_mul(A, A, A, m, ctx);            //A = A^2 (mod m)
                        uint8_t bit = 1 << 7 - j;
                        if(tmp_binary & bit){                   //if bi = 1
                                BN_mod_mul(A, A, a, m, ctx);    //A = A * a (mod m)
                        }
                }
                pos = 0;
        }

        BN_dec2bn(&r, BN_bn2dec(A));

        BN_free(A);
        BN_CTX_free(ctx);
        free(binary);

        return 0;
}

int main (int argc, char *argv[]){
        BIGNUM *a = BN_new();
        BIGNUM *e = BN_new();
        BIGNUM *m = BN_new();
        BIGNUM *res = BN_new();

        if(argc != 4){
                printf("usage: exp base exponent modulus\n");
                return -1;
        }

        BN_dec2bn(&a, argv[1]);
        BN_dec2bn(&e, argv[2]);
        BN_dec2bn(&m, argv[3]);
        printBN("a = ", a);
        printBN("e = ", e);
        printBN("m = ", m);

        ExpMod(res, a, e, m);

        printBN("a**e mod m = ", res);

        if(a != NULL) BN_free(a);
        if(e != NULL) BN_free(e);
        if(m != NULL) BN_free(m);
        if(res != NULL) BN_free(res);

        return 0;
}