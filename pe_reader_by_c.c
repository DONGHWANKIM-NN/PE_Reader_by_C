#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>


// 데이터 형식 범위
typedef unsigned short WORD;
typedef unsigned long DWORD;
typedef unsigned char BYTE;
typedef unsigned long long ULONGLONG;

#pragma pack(1)
// MS DOS HEADER
typedef struct _IMAGE_DOS_HEADER {
    WORD e_magic;    /* 00: MZ Header signature */
    WORD e_cblp;     /* 02: Bytes on last page of file */
    WORD e_cp;       /* 04: Pages in file */
    WORD e_crlc;     /* 06: Relocations */
    WORD e_cparhdr;  /* 08: Size of header in paragraphs */
    WORD e_minalloc; /* 0a: Minimum extra paragraphs needed */
    WORD e_maxalloc; /* 0c: Maximum extra paragraphs needed */
    WORD e_ss;       /* 0e: Initial (relative) SS value */
    WORD e_sp;       /* 10: Initial SP value */
    WORD e_csum;     /* 12: Checksum */
    WORD e_ip;       /* 14: Initial IP value */
    WORD e_cs;       /* 16: Initial (relative) CS value */
    WORD e_lfarlc;   /* 18: File address of relocation table */
    WORD e_ovno;     /* 1a: Overlay number */
    WORD e_res[4];   /* 1c: Reserved words */
    WORD e_oemid;    /* 24: OEM identifier (for e_oeminfo) */
    WORD e_oeminfo;  /* 26: OEM information; e_oemid specific */
    WORD e_res2[10]; /* 28: Reserved words */
    DWORD e_lfanew;  /* 3c: Offset to extended header */
} IMAGE_DOS_HEADER;

// PE HEADER 중 PE(NT) IMAGE FILE HEADER
typedef struct _IMAGE_FILE_HEADER {
  WORD  Machine;
  WORD  NumberOfSections;
  DWORD TimeDateStamp;
  DWORD PointerToSymbolTable;
  DWORD NumberOfSymbols;
  WORD  SizeOfOptionalHeader;
  WORD  Characteristics;
} IMAGE_FILE_HEADER, *PIMAGE_FILE_HEADER;

// IMAGE DATA DIRECTORY
typedef struct _IMAGE_DATA_DIRECTORY {
  DWORD VirtualAddress;
  DWORD Size;
} IMAGE_DATA_DIRECTORY, *PIMAGE_DATA_DIRECTORY;

// PE HEADER 중 PE(NT) IMAGE OPTIONAL HEADER
#define IMAGE_NUMBEROF_DIRECTORY_ENTRIES 16

typedef struct _IMAGE_OPTIONAL_HEADER64 {
  WORD  Magic; /* 0x20b */
  BYTE MajorLinkerVersion;
  BYTE MinorLinkerVersion;
  DWORD SizeOfCode;
  DWORD SizeOfInitializedData;
  DWORD SizeOfUninitializedData;
  DWORD AddressOfEntryPoint;
  DWORD BaseOfCode;
  ULONGLONG ImageBase;
  DWORD SectionAlignment;
  DWORD FileAlignment;
  WORD MajorOperatingSystemVersion;
  WORD MinorOperatingSystemVersion;
  WORD MajorImageVersion;
  WORD MinorImageVersion;
  WORD MajorSubsystemVersion;
  WORD MinorSubsystemVersion;
  DWORD Win32VersionValue;
  DWORD SizeOfImage;
  DWORD SizeOfHeaders;
  DWORD CheckSum;
  WORD Subsystem;
  WORD DllCharacteristics;
  ULONGLONG SizeOfStackReserve;
  ULONGLONG SizeOfStackCommit;
  ULONGLONG SizeOfHeapReserve;
  ULONGLONG SizeOfHeapCommit;
  DWORD LoaderFlags;
  DWORD NumberOfRvaAndSizes;
  IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
} IMAGE_OPTIONAL_HEADER64, *PIMAGE_OPTIONAL_HEADER64;

// PE HEADER(NT HEADER)
typedef struct _IMAGE_NT_HEADERS64 {
  DWORD Signature;
  IMAGE_FILE_HEADER FileHeader;
  IMAGE_OPTIONAL_HEADER64 OptionalHeader;
} IMAGE_NT_HEADERS64, *PIMAGE_NT_HEADERS64;


//SECTION HEADER
#define IMAGE_SIZEOF_SHORT_NAME 8

typedef struct _IMAGE_SECTION_HEADER {
  BYTE  Name[IMAGE_SIZEOF_SHORT_NAME];
  union {
    DWORD PhysicalAddress;
    DWORD VirtualSize;
  } Misc;
  DWORD VirtualAddress;
  DWORD SizeOfRawData;
  DWORD PointerToRawData;
  DWORD PointerToRelocations;
  DWORD PointerToLinenumbers;
  WORD  NumberOfRelocations;
  WORD  NumberOfLinenumbers;
  DWORD Charactekristics;
} IMAGE_SECTION_HEADER, *PIMAGE_SECTION_HEADER;



int main(int argc, const char** argv[]) {

    if (argc <= 1) {
        printf("insert file\n");
        exit(1);
    }   
    
    //@brief 파일 입출력을 위한 파일 포인터
    FILE *fp;

    //@brief 파일 open, 실패 시 프로그램을 종료    
    fp = fopen(argv[1]/*프로그램 매개변수로 받은 파일 이름*/, "rb" /*바이너리 읽기 모드*/);
    if (fp == NULL) {
        printf("File Open Error\n");
        exit(1);
    }

    
    //char list_msdosheader[50] = {"e_magic", "e_cblp", "e_cp", "e_cric", "e_cparhdr", "e_minalloc", "e_maxalloc", "e_ss", "e_sp", "e_csum", "e_ip", "e_cs", "e_lfarlc", "e_ovno", "e_res", "e_oemid", "e_oeminfo", "e_res2", "e_lfanew"};


    IMAGE_DOS_HEADER dos_header;
    fread(&dos_header, sizeof(IMAGE_DOS_HEADER), 1, fp);
    printf("MS DOS HEADER\n");
    printf("e_magic : %x\n", dos_header.e_magic);
    printf("e_cblp : %x\n", dos_header.e_cblp);
    printf("e_cp : %x\n", dos_header.e_cp);
    printf("e_crlc : %x\n", dos_header.e_crlc);
    printf("e_cparhdr : %x\n", dos_header.e_cparhdr);
    printf("e_minalloc : %x\n", dos_header.e_minalloc);
    printf("e_maxalloc : %x\n", dos_header.e_maxalloc);
    printf("e_ss : %x\n", dos_header.e_ss);
    printf("e_sp : %x\n", dos_header.e_sp);
    printf("e_csum : %x\n", dos_header.e_csum);
    printf("e_ip : %x\n", dos_header.e_ip);
    printf("e_cs : %x\n", dos_header.e_cs);
    printf("e_lfarlc : %x\n", dos_header.e_lfarlc);
    printf("e_ovno : %x\n", dos_header.e_ovno);
    printf("e_res : %x\n", dos_header.e_res);
    printf("e_oemid : %x\n", dos_header.e_oemid);
    printf("e_oeminfo : %x\n", dos_header.e_oeminfo);
    printf("e_res2 : %x\n", dos_header.e_res2);
    printf("e_lfanew : %x\n\n\n", dos_header.e_lfanew);
   

    IMAGE_NT_HEADERS64 pe_header;
    fread(&pe_header, sizeof(IMAGE_NT_HEADERS64), 1, fp);
    printf("PE HEADER\n");
    printf("Signature : %x\n\n\n", pe_header.Signature);


    IMAGE_FILE_HEADER pe_file_header;
    fread(&pe_file_header, sizeof(pe_file_header), 1, fp);
    printf("PE FILE HEADER\n");
    printf("Machine : %x\n", pe_file_header.Machine);
    printf("Number of Sections : %x\n", pe_file_header.NumberOfSections);
    printf("Time Date Stamp : %x\n", pe_file_header.TimeDateStamp);
    printf("Pointer To Symbol Table : %x\n", pe_file_header.PointerToSymbolTable);
    printf("Number of Symbols : %x\n", pe_file_header.NumberOfSymbols);
    printf("Size of Optional Header : %x\n", pe_file_header.SizeOfOptionalHeader);
    printf("Characteristics : %x\n\n\n", pe_file_header.Characteristics);


    IMAGE_OPTIONAL_HEADER64 pe_optional_header;
    fread(&pe_optional_header, sizeof(pe_optional_header), 1, fp);
    printf("PE OPTIONAL HEADER\n");
    printf("magic : %x\n", pe_optional_header.Magic);
    printf("Major Linker Version : %x\n", pe_optional_header.MajorLinkerVersion);
    printf("Minor Linker Version : %x\n", pe_optional_header.MinorLinkerVersion);
    printf("Size of Code : %x\n", pe_optional_header.SizeOfCode);
    printf("Size of Initialized Data : %x\n", pe_optional_header.SizeOfInitializedData);
    printf("Size of Uninitialized Data : %x\n", pe_optional_header.SizeOfUninitializedData);
    printf("Address of Entry Point : %x\n", pe_optional_header.AddressOfEntryPoint);
    printf("Base of Code : %x\n", pe_optional_header.BaseOfCode);
    printf("Image Base : %x\n", pe_optional_header.ImageBase);
    printf("Section Alignment : %x\n", pe_optional_header.SectionAlignment);
    printf("File Alignment : %x\n", pe_optional_header.FileAlignment);
    printf("Major Operating System Version : %x\n", pe_optional_header.MajorOperatingSystemVersion);
    printf("Minor Operating System Version : %x\n", pe_optional_header.MinorOperatingSystemVersion);
    printf("Major Image Version : %x\n", pe_optional_header.MajorImageVersion);
    printf("Minor Image Version : %x\n", pe_optional_header.MinorImageVersion);
    printf("Major Subsystem Version : %x\n", pe_optional_header.MajorSubsystemVersion);
    printf("Minor Subsystem Version : %x\n", pe_optional_header.MinorSubsystemVersion);
    printf("Win32 Version Value : %x\n", pe_optional_header.Win32VersionValue);
    printf("Size of Image : %x\n", pe_optional_header.SizeOfImage);
    printf("Size of Headers : %x\n", pe_optional_header.SizeOfHeaders);
    printf("Check Sum : %x\n", pe_optional_header.CheckSum);
    printf("Subsystem : %x\n", pe_optional_header.Subsystem);
    printf("Dll Characteristics : %x\n", pe_optional_header.DllCharacteristics);
    printf("Size Of Stack Reserve : %x\n", pe_optional_header.SizeOfStackReserve);
    printf("Size Of Stack Commit : %x\n", pe_optional_header.SizeOfStackCommit);
    printf("Size Of Heap Reserve : %x\n", pe_optional_header.SizeOfHeapReserve);
    printf("Size Of Heap Commit : %x\n", pe_optional_header.SizeOfHeapCommit);
    printf("Loader Flags : %x\n", pe_optional_header.LoaderFlags);
    printf("Number of RVA and Sizes : %x\n\n\n", pe_optional_header.NumberOfRvaAndSizes);


    IMAGE_DATA_DIRECTORY image_data_directory;
    fread(&image_data_directory, sizeof(image_data_directory), 1, fp);
    printf("IMAGE DATA DIRECTORY\n");
    printf("Virtual Address : %x\n", image_data_directory.VirtualAddress);
    printf("Size : %x\n\n\n", image_data_directory.Size);


    IMAGE_SECTION_HEADER section_header;
    fread(&section_header, sizeof(section_header), 1, fp);
    printf("SECTION HEADER\n");
    printf("Virtual Address : %x\n", section_header.VirtualAddress);
    printf("Size of Raw Data : %x\n", section_header.SizeOfRawData);
    printf("Pointer to Raw Data : %x\n", section_header.PointerToRawData);
    printf("Pointer to Relocations : %x\n", section_header.PointerToRelocations);
    printf("Pointer to Linenumbers : %x\n", section_header.PointerToLinenumbers);
    printf("Number Of Relocations : %x\n", section_header.NumberOfRelocations);
    printf("Number Of Linenumbers : %x\n", section_header.NumberOfLinenumbers);
    printf("Characteristics : %x\n\n\n", section_header.Charactekristics);


    //이거 파이썬처럼 list 만들어서 l[IMAGE DOS HEADER, IMAGE NT EHADER, IMAGE ILLE HEADER] 이런식으로 해서 이거 내부 항목으로 for문 돌릴 수도 있지 않나?


    //@brief 파일 close. 실패시 exit
    if (fclose(fp) != NULL) {
        printf("File close Error\n");
        exit(1);
    }

    return 0;
}




