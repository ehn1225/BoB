//20220820 BOB11기 이예찬
#include <iostream>
#include <stdio.h>
#include <string>
#include <fstream>
using namespace std;

typedef struct MFT_ENTRY_HDR {
	uint8_t Signature[4];
	uint16_t Offset_Fixup_Array;
	uint16_t Count_Fixup_Values;
	uint64_t LSN;
	uint16_t Sequence_Value;
	uint16_t HardLink_Count;
	uint16_t Offset_FirstAttr;
	uint16_t Flags;
	uint32_t Used_Size;
	uint32_t Allocated_Size;
	uint64_t FileRefBase_MFTentry;
	uint16_t Next_Attr_ID;
} MFT_ENTRY_HDR;

typedef struct ATTR_HDR {
	uint32_t AttrType_ID;
	uint32_t Len_Attr;
	uint8_t ResidentFlag;
	uint8_t Len_Name;
	uint16_t Offset_Name;
	uint16_t flags;
	uint16_t attr_Identifier;
	uint64_t start_vcn_run;
	uint64_t end_vcn_run;
	uint64_t offset_run;
	uint16_t compression_unit_size;
	uint32_t padding;
	uint64_t allocSize_Attr_content;
	uint64_t real_size_Attr_content;
	uint8_t init_size_Attr_content[8];
}ATTR_HDR;

unsigned char* buffer = NULL;;

void MFT_Entry_Header(int MFT_POSITION) {
	MFT_ENTRY_HDR* mfthdr = (MFT_ENTRY_HDR*)(buffer + MFT_POSITION);
	int pos = mfthdr->Offset_FirstAttr;

	ATTR_HDR* attr = (ATTR_HDR*)(buffer + MFT_POSITION + pos);

	while (1) {
		attr = (ATTR_HDR*)(buffer + MFT_POSITION + pos);
		if (attr->AttrType_ID == 0xffffffff) {
			return;
		}
		if (attr->Len_Attr == 0) {
			return;
		}
		if (attr->ResidentFlag == 0 || attr->AttrType_ID != 0x80) {
			pos += attr->Len_Attr;
			continue;
		}

		int total = 0;
		uint32_t pos2 = 0x0;

		while (1) {
			uint8_t* pos_pointer = attr->init_size_Attr_content + pos2;
			if (*pos_pointer == 0)
				break;
			unsigned int run_offset = (*pos_pointer >> 4);
			unsigned int run_length = (*pos_pointer & 0x0F);

			int offset_size = 0;
			int length_size = 0;

			memcpy(&offset_size, pos_pointer + 1 + run_length, run_offset);
			memcpy(&length_size, pos_pointer + 1, run_length);

			pos2 += (run_offset + run_length+1);
			total += length_size;

			//Minus Offset
			unsigned int test_minus = (1 << ((8 * run_offset) - 1));
			if (offset_size & test_minus) {
				unsigned int tmp = 0xffffffff;
				tmp = (tmp >> (4 - run_offset) * 8);
				offset_size = tmp + 1 - offset_size;
			}
			printf("%d,%d\n", offset_size, length_size);
		}

		printf("%d\n", total);
		
		pos += attr->Len_Attr;
	}


}


int main(int argc, char* argv[]) {
	string file_name;
	file_name = argv[1];
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
	
	short BPS = 0;
	int8_t SPC = 0;
	memcpy(&BPS, buffer + 11, 2);
	memcpy(&SPC, buffer + 13, 1);
	//printf("BPS : %d\n", BPS);
	//printf("SPC : %d\n", SPC);
	int CLUSTER_SIZE = BPS * SPC;
	//printf("Cluster Size : %d\n", CLUSTER_SIZE);

	int64_t STARTOFMFT = 0;
	memcpy(&STARTOFMFT, buffer + 48, 8);
	//printf("Start Of MFT : %d\n", STARTOFMFT);

	int MFTPOSITION = STARTOFMFT * CLUSTER_SIZE;

	//printf("MFT  : %d\n", MFTPOSITION);

	MFT_Entry_Header(MFTPOSITION);

}