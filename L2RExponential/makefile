all: Crypto_Exp

Crypto_Exp : Crypto_Exp.c
	gcc -o Crypto_Exp Crypto_Exp.c -L/usr/local/lib64/ -lcrypto

clean:
	rm -f Crypto_Exp *.o
