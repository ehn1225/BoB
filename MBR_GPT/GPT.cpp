//20220808 BOB11기 이예찬
#include <iostream>
#include <stdio.h>
#include <string>
#include <fstream>
using namespace std;

struct GPT_PARTITION {
	unsigned char partition_guid[16];
	unsigned char unique_guid[16];
	unsigned char fisrt_lba[8];
	unsigned char last_lba[8];
	unsigned char attribute_flags[8];
	unsigned char partition_name[16];
};
#define GPTPartitionEntry_POS 0x400
#define GPTPartitionEntry_size 128 

uint64_t ntoh_int64(unsigned char* number) {
	uint64_t tmp = 0;
	tmp = (number[7] << 56) | (number[6] << 48) | (number[5] << 40) | (number[4] << 32) | (number[3] << 24) | (number[2] << 16) | (number[1] << 8) | number[0];
	return tmp;
}
int main(int argc, char* argv[]) {
	string file_name;
	file_name = argv[1];
	unsigned char* buffer = NULL;;
	int length = 0;
	ifstream f(file_name, ifstream::binary);
	if (f) {
		f.seekg(0, f.end);
		length = (int)f.tellg();
		f.seekg(0, f.beg);

		buffer = (unsigned char*)malloc(length);

		f.read((char*)buffer, length);
		f.close();

	}
	else {
		cout << "Cant Read File.(" << file_name << ")" << endl;
		return 1;
	}

	for (int j = 0; j < 128; j++) {
		GPT_PARTITION* tmp = (GPT_PARTITION*)(buffer + GPTPartitionEntry_POS + (j * GPTPartitionEntry_size));
		if (tmp->partition_guid[0] == 0x00) {
			break;
		}
		uint64_t f_lba = ntoh_int64(tmp->fisrt_lba);
		uint64_t l_lba = ntoh_int64(tmp->last_lba);
		int size = (l_lba - f_lba + 1) * 512;

		for (int i = 0; i < 16; i++)
			printf("%02X", tmp->partition_guid[i]);

		printf("%12X  \t %.2fMB \n", f_lba * 512, size/1048576.0f);

	}

	return 0;
}