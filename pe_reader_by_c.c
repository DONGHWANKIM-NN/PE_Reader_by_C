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
  fp = fopen("/home/hwnnhji/PE_Reader_by_C/notepad.exe"/*argv[1]*//*프로그램 매개변수로 받은 파일 이름*/, "rb" /*바이너리 읽기 모드*/);



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
  
  /*malloc을 해주는 이유는 다음과 같다. malloc을 해서 따로 공간을 마련해, section header의 공간 자체를 동적할당으로 저장해놓으면 */
  IMAGE_SECTION_HEADER* section_header = (IMAGE_SECTION_HEADER *) malloc(sizeof(IMAGE_SECTION_HEADER)*pe_header.FileHeader.NumberOfSections);

  int number_of_sections = pe_header.FileHeader.NumberOfSections;

  //section header 출력
  printf("\nSECTION HEADER\n");
  for(int i = 0; i < number_of_sections; i++){
    fread(&section_header[i], sizeof(IMAGE_SECTION_HEADER), 1, fp);
    print_sectionheader(section_header[i]);
  }
  printf("\n\n");




  //section 출력
  for(int i = 0; i < number_of_sections; i++){
    printf("\n%s\n", section_header[i].Name);
    fseek(fp, section_header[i].PointerToRawData, SEEK_SET); // 위에서 malloc 받을 걸 일부러 그대로 유지해서, 그 값으로 fseek을 진행함.

    char* section_list = (char *) malloc(sizeof(char) * section_header[i].SizeOfRawData); // 하나씩 fread받아서 바로바로 1개씩 출력하게 할까 싶었는데, 안되길래 malloc으로 전체를 받음.
    fread(section_list, section_header[i].SizeOfRawData, 1, fp); //section_list가 이미 malloc으로 받은 '주소'값이기 때문에 &section_list 같은 &는 필요없다.
    
    for(int j = 0; j <= section_header[i].SizeOfRawData; j++){
      printf("%x ", (unsigned char) section_list[j]); //여기서 unsigned char을 붙이는 이유는 오버플로우 때문이다. 정확한 이유는 모르겠으나 관련 웹사이트를 남겨놓음
                                                      /* https://kldp.org/node/30346
                                                        https://stackoverflow.com/questions/7188919/the-x-format-specifier-with-an-unsigned-char-in-c*/
    }
    free(section_list);
  }
  printf("\n\n\n\n");





  //RVA to RAW 함수
  /* 1. File에 File Offset이 있다면 Memory에는 Virtual Address가 있다.
     2. 즉 Virtual Address라는 개념은 메모리에서의 절대주소값이며, 이는 상대주소인 RVA에 ImageBase를 더한 값과 같다.
     3. RAW는 File에서의 Offset을 의미하는 것이고, RVA는 Memory에서의 상대주소를 의미하는 것이다.
     4. RVA - PointerToRawData = RAW - VirtualAddress이다. 즉 Memory상대위치 - File에서의 각 Section의 시작위치 = FileOffset - Memory절대위치 라고! 생각할 수 있지만....
     5. 4번의 식에서의 Virtual Address는 2에서 정의한 Memory에서의 절대주소값이란 개념을 의미하는 게 아니다. 이는 Section Header 내에 위치하는 VirtualAddress값을 의미하며 이는 Memory에서 Section의 RVA를 의미한다.
     6. 따라서 식은 'Memory상대위치 - File에서 각 Section의 시작위치 = FileOffset - Memory에서 각 Section의 시작위치'로 정리할 수 있다.*/
  //함수를 만들기 위한 요소
  /* 1. rva와 raw는 서로 '구하거나', '받거나' 둘 중 하나로 충당되어야 함.
     2. PointerToRawData과 VirtualAddress는 section header에 존재.
     3. 따라서 RVA를 구하려면 RAW를 받아야 하며, RAW를 구하려면 RVA를 받아야 함.*/
 
  //기본적인 Define
  int rva, raw;
  char rvaorraw;


  //RVA to RAW v.s. RAW to RVA
  printf("RVA(a) or RAW(w)(to evaluate)\n");
  scanf("%c", &rvaorraw);
  printf("%c를 입력받음\n", rvaorraw);


  // RAW to RVA

  if(rvaorraw == 'a'){
    printf("RAW를 입력\n");
    scanf("%x", &raw);
    
    // File Offset(RAW)가 어느 Section에 들어있는지 확인하는 과정
    unsigned int sectionheaderposition; //raw가 어느 section 중간에 들어가있는지를 확인하는 과정
    
    // for(int k = 0; k <= number_of_sections; k++){
    //   if(section_header[k].PointerToRawData <= raw & raw < section_header[k+1].PointerToRawData){
    //     sectionheaderposition = k;
    //   }
    //   else{
    //     continue;
    //   }
    // }

    if(section_header[0].PointerToRawData <= raw){
      if(section_header[1].PointerToRawData <= raw){
        if(section_header[2].PointerToRawData <= raw){
          if(section_header[3].PointerToRawData <= raw){
            if(section_header[4].PointerToRawData <= raw){
              if(section_header[5].PointerToRawData <= raw){
                if(section_header[6].PointerToRawData <= raw){
                  if(section_header[7].PointerToRawData <= raw){
                    sectionheaderposition = 7;
                  }
                  else{
                    sectionheaderposition = 6;
                  }
                }
                else{
                  sectionheaderposition = 5;
                }
              }
              else{
                sectionheaderposition = 4;
              }
            }
            else{
              sectionheaderposition = 3;
            }
          }
          else{
            sectionheaderposition = 2;
          }
        }
        else{
          sectionheaderposition = 1;
        }
      }
      else{
        sectionheaderposition = 0;
      }
    }
    else{
      printf("제대로된 값을 입력 요망.\n");
    }

    printf("입력하신 %x 값은 %d번째 Section; %s에 포함된 값입니다.\n", raw, sectionheaderposition, section_header[sectionheaderposition].Name);
    //raw와, raw가 포함된 section 내의 VirtualAddress와 pointertorawdata를 이용하여 rva 구하기.
    rva = raw - section_header[sectionheaderposition].PointerToRawData + section_header[sectionheaderposition].VirtualAddress;
    printf("rva : %x\n", rva);
  }


  // RVA to RAW

  else if(rvaorraw == 'w'){
    printf("RVA를 입력\n");
    scanf("%x", &rva);

    // RVA가 어느 Section에 들어있는지 확인하는 과정
    int sectionheaderposition; //raw가 어느 section 중간에 들어가있는지를 확인하는 과정

    if(section_header[0].VirtualAddress <= rva){
      if(section_header[1].VirtualAddress <= rva){
        if(section_header[2].VirtualAddress <= rva){
          if(section_header[3].VirtualAddress <= rva){
            if(section_header[4].VirtualAddress <= rva){
              if(section_header[5].VirtualAddress <= rva){
                if(section_header[6].VirtualAddress <= rva){
                  if(section_header[7].VirtualAddress <= rva){
                    sectionheaderposition = 7;
                  }
                  else{
                    sectionheaderposition = 6;
                  }
                }
                else{
                  sectionheaderposition = 5;
                }
              }
              else{
                sectionheaderposition = 4;
              }
            }
            else{
              sectionheaderposition = 3;
            }
          }
          else{
            sectionheaderposition = 2;
          }
        }
        else{
          sectionheaderposition = 1;
        }
      }
      else{
        sectionheaderposition = 0;
      }
    }
    else{
      printf("제대로된 값을 입력 요망.\n");
    }

    printf("입력하신 %x 값은 %d번째 Section; %s에 포함된 값입니다.\n", rva, sectionheaderposition, section_header[sectionheaderposition].Name);
    //raw와, raw가 포함된 section 내의 VirtualAddress와 pointertorawdata를 이용하여 rva 구하기.
    raw = rva - section_header[sectionheaderposition].VirtualAddress + section_header[sectionheaderposition].PointerToRawData;
    printf("raw : %x\n", raw);
  }

  
  free(section_header);

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