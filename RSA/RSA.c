//20220818 BoB 11기 이예찬
#include <stdio.h> 
#include <openssl/bn.h>
#include <string.h>
#include <time.h>
typedef struct _b11rsa_st {
    BIGNUM *e;
    BIGNUM *d;
    BIGNUM *n;
}BOB11_RSA;

BIGNUM *XEuclid(BIGNUM *x, BIGNUM *y, const BIGNUM *a, const BIGNUM *b)
{
	BIGNUM *dividend = BN_dup(a);
    BIGNUM *divider = BN_dup(b);
    BIGNUM *quofient = BN_new();
    BIGNUM *residue = BN_dup(a);
    BIGNUM *x0 = BN_new();
    BIGNUM *x1 = BN_new();
    BIGNUM *x2 = BN_new();
    BIGNUM *y0 = BN_new();
    BIGNUM *y1 = BN_new();
    BIGNUM *y2 = BN_new();
    BN_dec2bn(&x0, "1");
    BN_dec2bn(&y0, "0");
    BN_dec2bn(&x1, "0");
    BN_dec2bn(&y1, "1");
    BN_CTX *ctx = BN_CTX_new();
    while(BN_is_zero(residue) != 1){
            BN_div(quofient, residue, dividend, divider, ctx);
            if(BN_is_zero(residue) == 1){
                    break;
            }
            BN_mul(x2,quofient,x1,ctx);
            BN_mul(y2,quofient,y1,ctx);
            BN_sub(x2, x0, x2);
            BN_sub(y2, y0, y2);
            x0 = BN_dup(x1);
            x1 = BN_dup(x2);
            y0 = BN_dup(y1);
            y1 = BN_dup(y2);

            dividend = BN_dup(divider);
            divider = BN_dup(residue);
    }
	BN_dec2bn(&x, BN_bn2dec(x1));
	BN_dec2bn(&y, BN_bn2dec(y1));
    return divider;
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
int Miller_Rabin(BIGNUM* p){
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *rem = BN_new(); // reminder
    BIGNUM *p_minus = BN_dup(p);
    BIGNUM *d = BN_new();
    BIGNUM *one = BN_new();
    BIGNUM *two = BN_new();
    int s = 0;
    BN_dec2bn(&one, "1");
    BN_dec2bn(&two, "2");
    BN_sub(p_minus, p_minus, one);
    while(1){
        BN_div(p_minus, rem, p_minus, two, ctx);   
        if(BN_is_zero(rem)){//2로 나누어 떨어졌을 때
            s++;
        }
        else{ //2로 나누어 떨어 지지 않을 때. 이미 홀수를 나눠버렸으므로 복구가 필요함
            BN_mul(d, p_minus,two,ctx);
            BN_add(d, d, rem);
            break;
        }
    }
    BN_sub(p_minus, p, one);
    BN_free(rem);
    BN_free(one);

    BIGNUM *a = BN_new();
    int loop = 0;
    BIGNUM *x = BN_new();
    BIGNUM *y = BN_new();
    BIGNUM *gcd;
    BIGNUM *p_minus_4 = BN_new();
    BIGNUM *four = BN_new();
    BN_dec2bn(&four, "4");
    BN_sub(p_minus_4, p, four); 

    while(loop < 5){
        int loop_continue = 0;
        BN_rand_range(a, p_minus_4);
        BN_add(a, a, two);
        //2 <= a <= p - 2

        gcd = XEuclid(x,y,a,p);
        if(BN_is_one(gcd) == 0){
            continue;
        }

        loop++;

        ExpMod(x, a, d, p);
        if(BN_is_one(x))
            continue;

        for(int j = 0; j < s; j++){
            if(BN_cmp(x, p_minus) == 0){
                loop_continue = 1;
                break;
            }
            else{
                BN_mod_mul(x, x, x, p, ctx);
            }
        }
        if(loop_continue == 1)
            continue;

        BN_CTX_free(ctx);
        BN_free(p_minus);
        BN_free(d);
        BN_free(two);
        BN_free(a);
        BN_free(x);
        BN_free(y);
        BN_free(gcd);
        BN_free(p_minus_4);
        BN_free(four);
        return -1;
    }

    BN_CTX_free(ctx);
    BN_free(p_minus);
    BN_free(d);
    BN_free(two);
    BN_free(a);
    BN_free(x);
    BN_free(y);
    BN_free(gcd);
    BN_free(p_minus_4);
    BN_free(four);

    return 0;
}
void Generate_BIGNUM_Prime(BIGNUM * result, int nBits){
    char ascii[16] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'};
    int arr_size = nBits / 8;
    char *tmp = (char*)malloc(sizeof(char)*(arr_size+1));
    for(int i =0; i < arr_size; i++){
        int random = rand() % 16;
        if(i == 0)//start with e
            random = 14; 
        if(i == arr_size-1)//짝수로 끝나는 것을 방지함.
            random = 2*(rand()%8) + 1; 
        tmp[i] = ascii[random];
    }
    tmp[arr_size] = 0;
    BIGNUM *prime = BN_new();
    BIGNUM *two = BN_new();
    BN_dec2bn(&two, "2");
    BN_hex2bn(&prime, tmp);
    //Do miller rabin test
    //if fail, append 2 and do it again
    while(Miller_Rabin(prime) == -1){
        BN_add(prime, prime, two);
    }
    BN_copy(result, prime);
    BN_free(prime);
    BN_free(two);
}

int BOB11_RSA_KeyGen(BOB11_RSA *b11rsa, int nBits){
    BIGNUM *p = BN_new();
    BIGNUM *q = BN_new();
    BIGNUM *tmp = BN_new();
    BN_CTX *ctx = BN_CTX_new();

    //Generate Prime Number
    Generate_BIGNUM_Prime(p, nBits);
    Generate_BIGNUM_Prime(q, nBits);

    //Define e
    BN_dec2bn(&(b11rsa->e), "65537");

    //Calculate n
    BN_mul(tmp, p, q, ctx);
    b11rsa->n = BN_dup(tmp);
    
    //Calculate d
    BIGNUM *d = BN_new();
    BIGNUM *pie = BN_new();
    BIGNUM *p_minus = BN_dup(p);
    BIGNUM *q_minus = BN_dup(q);
    BIGNUM *one = BN_new();
    BIGNUM *two = BN_new();
    BN_dec2bn(&one, "1");
    BN_sub(p_minus, p_minus, one);
    BN_sub(q_minus, q_minus, one);
    BN_mul(pie, p_minus, q_minus, ctx);
    XEuclid(d, tmp, b11rsa->e, pie);
    BN_add(d,d,pie);
    BN_mod(d, d, pie, ctx);
    b11rsa->d = BN_dup(d);

    BN_free(p);
    BN_free(q);
    BN_free(tmp);
    BN_CTX_free(ctx);
    BN_free(d);
    BN_free(pie);
    BN_free(p_minus);
    BN_free(q_minus);
    BN_free(one);
    BN_free(two);

}

void PrintUsage()
{
    printf("usage: rsa [-k|-e e n plaintext|-d d n ciphertext]\n");
}
BOB11_RSA* BOB11_RSA_new(){
    return (BOB11_RSA *)malloc(sizeof(BOB11_RSA));
}
void BOB11_RSA_free(BOB11_RSA* ptr){
    free(ptr);
}
void BOB11_RSA_Enc(BIGNUM* out, BIGNUM* in, BOB11_RSA* b11rsa){
    ExpMod(out, in, b11rsa->e, b11rsa->n);
}
void BOB11_RSA_Dec(BIGNUM* out, BIGNUM* in, BOB11_RSA* b11rsa){
    ExpMod(out, in, b11rsa->d, b11rsa->n);
}

int main (int argc, char *argv[])
{
    BOB11_RSA *b11rsa = BOB11_RSA_new();
    BIGNUM *in = BN_new();
    BIGNUM *out = BN_new();

    if(argc == 2){
        if(strncmp(argv[1],"-k",2)){
            PrintUsage();
            return -1;
        }
        BOB11_RSA_KeyGen(b11rsa,1024);
        BN_print_fp(stdout,b11rsa->n);
        printf(" ");
        BN_print_fp(stdout,b11rsa->e);
        printf(" ");
        BN_print_fp(stdout,b11rsa->d);
    }else if(argc == 5){
        if(strncmp(argv[1],"-e",2) && strncmp(argv[1],"-d",2)){
            PrintUsage();
            return -1;
        }
        BN_hex2bn(&b11rsa->n, argv[3]);
        BN_hex2bn(&in, argv[4]);
        if(!strncmp(argv[1],"-e",2)){
            BN_hex2bn(&b11rsa->e, argv[2]);
            BOB11_RSA_Enc(out,in, b11rsa);
        }else if(!strncmp(argv[1],"-d",2)){
            BN_hex2bn(&b11rsa->d, argv[2]);
            BOB11_RSA_Dec(out,in, b11rsa);
        }else{
            PrintUsage();
            return -1;
        }
        BN_print_fp(stdout,out);
    }else{
        PrintUsage();
        return -1;
    }

    if(in != NULL) BN_free(in);
    if(out != NULL) BN_free(out);
    if(b11rsa!= NULL) BOB11_RSA_free(b11rsa);

    return 0;
}