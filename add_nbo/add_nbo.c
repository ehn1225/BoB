//BoB11 LeeYeChan
#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <stdint.h>
#include <string.h>

int main(int argc, char* argv[]) {
	uint32_t a = 1;
	uint32_t b = 1;
	unsigned char buf[4] = {0,}; //fread를 담을 배열

	if (argc < 3) { //입력값 확인
		printf("매개변수가 부족합니다.");
		return 1;
	}

	FILE* fp = fopen(argv[1], "rb");

	if (fp == NULL) {
		printf("파일을 열 수 없습니다.");
		return 1;
	}
	fread(buf, 4, 1, fp);
	a = (buf[0] << 24) | (buf[1] << 16) | (buf[2] << 8) | (buf[3]);

	fp = fopen(argv[2], "rb");
	memset(buf, 0, 4); //buf 재사용을 위한 초기화

	if (fp == NULL) {
		printf("파일을 열 수 없습니다.");
		return 1;
	}
	fread(buf, 4, 1, fp);
	b = (buf[0] << 24) | (buf[1] << 16) | (buf[2] << 8) | (buf[3]);

	printf("%u(0x%x) + %u(0x%x) = %u(0x%x)", a,a,b,b,a+b,a+b);

	return 0;
}
