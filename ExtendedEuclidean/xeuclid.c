#include <stdio.h> 
#include <openssl/bn.h>

void printBN(char *msg, BIGNUM *a){
        char *number_str = BN_bn2dec(a);
        printf("%s %s\n", msg, number_str);
        OPENSSL_free(number_str);

}
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


int main (int argc, char *argv[])
{
        BIGNUM *a = BN_new();
        BIGNUM *b = BN_new();
        BIGNUM *x = BN_new();
        BIGNUM *y = BN_new();
        BIGNUM *gcd;

        if(argc != 3){
                printf("usage: xeuclid num1 num2");
                return -1;
        }
        BN_dec2bn(&a, argv[1]);
        BN_dec2bn(&b, argv[2]);
        gcd = XEuclid(x,y,a,b);

        printBN("(a,b) = ", gcd);
        printBN("a = ", a);
        printBN("b = ", b);
        printBN("x = ", x);
        printBN("y = ", y);
        printf("%s*(%s) + %s*(%s) = %s\n",BN_bn2dec(a),BN_bn2dec(x),BN_bn2dec(b),BN_bn2dec(y),BN_bn2dec(gcd));

        if(a != NULL) BN_free(a);
        if(b != NULL) BN_free(b);
        if(x != NULL) BN_free(x);
        if(y != NULL) BN_free(y);
        if(gcd != NULL) BN_free(gcd);

        return 0;
}
