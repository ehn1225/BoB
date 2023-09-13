# RSA Encryption Algorithm
### OpenSSL을 이용하여 구현한 RSA 암호화 알고리즘
- Euclidean algorithm, Modular exponentiation(L2R), Miller–Rabin primality test를 이용하여 구현
- 암호키 생성, 암호화, 복호화 기능

## Usage
- usage: rsa [-k|-e e n plaintext|-d d n ciphertext] </br>

## Prepare
- openssl-3.0.5

## 실행 화면
- <img src="https://github.com/ehn1225/BoB/assets/5174517/fa3adb50-490b-47c7-8489-b61a2fbde435" width="700"></img>
- n, e, d 순으로 출력

## Reference
- [OpenSSL](https://www.openssl.org/)
- [Miller–Rabin test](https://en.wikipedia.org/wiki/Miller%E2%80%93Rabin_primality_test#Miller%E2%80%93Rabin_test)
- [Modular exponentiation Left-to-right binary method](https://en.wikipedia.org/wiki/Modular_exponentiation#Left-to-right_binary_method)
