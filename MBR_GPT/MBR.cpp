//20220808 BOB11기 이예찬
#include <iostream>
#include <stdio.h>
#include <string>
#include <fstream>
using namespace std;
#define MBR_PARTITION_POS 0x1BE
#define MBR_PARTITION_SIZE 16
uint32_t EBR_BASE = 0;

struct MBR_PARTITION {
	unsigned char is_active;
	unsigned char chs1[3];
	unsigned char partition_type;
	unsigned char chs2[3];
	uint32_t lba;
	uint32_t num_sector;
};

void Print_Partiton(MBR_PARTITION* ptr, unsigned int offset) {
	printf("%02x %10X  \t %.2fMB \n",ptr->partition_type, (ptr->lba * 512) + offset, (ptr->num_sector*512) / 1048576.0f);
}
void Follow_EBR(unsigned char * buffer, unsigned int offset) {
	MBR_PARTITION* tmp = NULL;
	tmp = (MBR_PARTITION*)(buffer + MBR_PARTITION_POS +  offset);
	Print_Partiton(tmp, offset);
	tmp = (MBR_PARTITION*)(buffer + MBR_PARTITION_POS + offset + MBR_PARTITION_SIZE);
	if(tmp->partition_type == 0x05)
		Follow_EBR(buffer, (tmp->lba*512) + EBR_BASE);
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
	MBR_PARTITION* tmp = NULL;
	for (int i = 0; i < 4; i++) {
		tmp = (MBR_PARTITION*)(buffer + MBR_PARTITION_POS + (i * MBR_PARTITION_SIZE));
		if (tmp->partition_type != 0x05) {
			Print_Partiton(tmp, 0);
		} 
		else{
			EBR_BASE = tmp->lba * 512;
			Follow_EBR(buffer, EBR_BASE);
			break;
		}
	}

}