#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include "pe_reader_by_c.h"

// 값에 의한 전달, 참조에 의한 전달





int main(int argc, const char** argv[]) {

  //if (argc <= 1) {
  //    printf("insert file\n");
  //    exit(1);
  //}   
  
  //@brief 파일 입출력을 위한 파일 포인터
  FILE *fp;

  //@brief 파일 open, 실패 시 프로그램을 종료
  fp = fopen(argv[1]/*프로그램 매개변수로 받은 파일 이름*/, "rb" /*바이너리 읽기 모드*/);



  if (fp == NULL) {
      printf("파일 열기에 실패했습니다.\n");
      exit(1);
  }

  
  //char list_msdosheader[50] = {"e_magic", "e_cblp", "e_cp", "e_cric", "e_cparhdr", "e_minalloc", "e_maxalloc", "e_ss", "e_sp", "e_csum", "e_ip", "e_cs", "e_lfarlc", "e_ovno", "e_res", "e_oemid", "e_oeminfo", "e_res2", "e_lfanew"};

    int fpPosition = ftell(fp); // pe header를 읽는 데에 ms dos stub을 생략할 필요가 있기에, file offset을 pe header 바로 앞으로 e_lfanew를 이용해 바꿔주기 위한 변수 


  // MS DOS HEADER 읽고 출력  
  IMAGE_DOS_HEADER dos_header;
  fread(&dos_header/*읽을 위치(주소)*/, sizeof(IMAGE_DOS_HEADER)/*읽을 크기*/, 1/*한개*/, fp/*FILE STREAM*/); //MS-DOS HEADER 읽음.
  print_dosheader(dos_header);




  // 파일 포인터 위치 변경
  fpPosition = dos_header.e_lfanew;
  fseek(fp, fpPosition, SEEK_SET);


  // PE HEADER 읽기
  IMAGE_NT_HEADERS64 pe_header;
  fread(&pe_header, sizeof(IMAGE_NT_HEADERS64), 1, fp);

  //PE HEADER(SIGNATURE) 출력
  print_peheader(pe_header);

  // IMAGE_NT_HEADERS64 pe_file_header; 출력
  print_pefileheader(pe_header.FileHeader);

  //PE OPTIONAL HEADER 출력
  print_peoptionalheader(pe_header.OptionalHeader);

  //IMAGE DATA DIRECTORY 읽기

  // fpPosition = 376; //376은 파일오프셋 처음부터 image data directory의 첫번째인 export까지의 거리
  // fseek(fp, fpPosition, SEEK_SET);

  // IMAGE_DATA_DIRECTORY imgdata_directory;
  // fread(&imgdata_directory, sizeof(imgdata_directory), 1, fp);


  //IMAGE DATA DIRECTORY 출력
  // IMAGE_OPTIONAL_HEADER64 optional_header; 이거 하드코딩 하다가 주석처리 해놓습니다.
  printf("IMAGE DATA DIRECTORY\n");
  for(int i = 0; i+1 <= IMAGE_NUMBEROF_DIRECTORY_ENTRIES; i++){
  printf("[%d]", i); //이러는 게 보기 좋아서 이렇게 둡니다.
  printf("Virtual Address : %x\n", pe_header.OptionalHeader.DataDirectory[i].VirtualAddress);
  printf("Size : %x\n\n", pe_header.OptionalHeader.DataDirectory[i].Size);
  }

  //print_imagedatadirectory(/*imgdata_directory*/optional_header.DataDirectory);



  //section header 읽기
  IMAGE_SECTION_HEADER section_header;

  int sizeofrawdata[20];
  //section header 출력
  printf("\nSECTION HEADER\n");
  for(int i = 1; i<=pe_header.FileHeader.NumberOfSections; i++){
  fread(&section_header, sizeof(section_header), 1, fp);
  sizeofrawdata[i-1] = sizeof(section_header);
  print_sectionheader(section_header);
  }



  

  //SECTION 읽겠습니다!! 근데 어떻게 읽으면 좋냐... 구조체도 없는데
  fpPosition = fseek(fp, section_header.PointerToLinenumbers, SEEK_SET); // pointer to raw data를 이용해서 file offset을 section 앞으로 가져갈 거다.
  
  for(int i = 0; i + 1 <= pe_header.FileHeader.NumberOfSections; i++){
  char section; // 긴 section을 담을 공간.
  
  fread(&section, section_header.SizeOfRawData, 1, fp);
  printf("%s\n", section_header.Name[i]);
  printf("%s\n\n\n", section);

  }




  





  //@brief 파일 close. 실패시 exit
  if (fclose(fp) != NULL) {
      printf("파일을 닫는 데 실패했습니다.\n");
      exit(1);
  }
  return 0;
}








void print_dosheader(IMAGE_DOS_HEADER dos_header)
{
  printf("MS DOS HEADER\n");
  printf("e_magic : %c%c\n", dos_header.e_magic&255, dos_header.e_magic>>8);
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
  //printf("e_res2 : %x\n", dos_header.e_res2);
  printf("e_lfanew : %x\n\n\n\n", dos_header.e_lfanew);
}

void print_peheader(IMAGE_NT_HEADERS64 pe_header) 
{
  printf("PE HEADER\n");
  printf("Signature : %c%c\n\n\n", pe_header.Signature&255, pe_header.Signature>>8);
}


void print_pefileheader(IMAGE_FILE_HEADER pe_file_header){
  printf("PE FILE HEADER\n");
  printf("Machine : %x\n", pe_file_header.Machine);
  printf("Number of Sections : %x\n", pe_file_header.NumberOfSections);
  printf("Time Date Stamp : %x\n", pe_file_header.TimeDateStamp);
  printf("Pointer To Symbol Table : %x\n", pe_file_header.PointerToSymbolTable);
  printf("Number of Symbols : %x\n", pe_file_header.NumberOfSymbols);
  printf("Size of Optional Header : %x\n", pe_file_header.SizeOfOptionalHeader);
  printf("Characteristics : %x\n\n\n", pe_file_header.Characteristics);
}


void print_peoptionalheader(IMAGE_OPTIONAL_HEADER64 pe_optional_header){
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
  printf("Number of RVA and Sizes : %x\n\n\n\n", pe_optional_header.NumberOfRvaAndSizes);
}

  
// void print_imagedatadirectory(IMAGE_DATA_DIRECTORY imgdata_directory){
//   int i = 1;
//   while(i<=IMAGE_NUMBEROF_DIRECTORY_ENTRIES){
//     printf("Virtual Address : %x\n", imgdata_directory.VirtualAddress);
//     printf("Size : %x\n\n", imgdata_directory.Size);
//     i++;
//   }
// }


void print_sectionheader(IMAGE_SECTION_HEADER section_header){
  printf("Name : %s\n", section_header.Name);
  printf("Virtual size : %x\n", section_header.Misc.VirtualSize);
  printf("Virtual Address : %x\n", section_header.VirtualAddress);
  printf("Size of Raw Data : %x\n", section_header.SizeOfRawData);
  printf("Pointer to Raw Data : %x\n", section_header.PointerToRawData);
  printf("Pointer to Relocations : %x\n", section_header.PointerToRelocations);
  printf("Pointer to Linenumbers : %x\n", section_header.PointerToLinenumbers);
  printf("Number Of Relocations : %x\n", section_header.NumberOfRelocations);
  printf("Number Of Linenumbers : %x\n", section_header.NumberOfLinenumbers);
  printf("Characteristics : %x\n\n", section_header.Characteristics);
}