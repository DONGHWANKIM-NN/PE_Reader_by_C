#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include "pe_reader_by_c.h"


  //RVA to RAW 함수
  /* 1. File에 File Offset이 있다면 Memory에는 Virtual Address가 있다.
     2. 즉 Virtual Address라는 개념은 메모리에서의 절대주소값이며, 이는 상대주소인 RVA에 ImageBase를 더한 값과 같다.
     3. RAW는 File에서의 Offset을 의미하는 것이고, RVA는 Memory에서의 상대주소를 의미하는 것이다.
     4. RAW - PointerToRawData = RVA - VirtualAddress이다. 즉 FileOffset - File에서의 각 Section의 시작위치 = Memory상대위치 - Memory절대위치 라고! 생각할 수 있지만....
     5. 4번의 식에서의 Virtual Address는 2에서 정의한 Memory에서의 절대주소값이 아니다. 이는 Section Header 내에 위치하는 VirtualAddress값을 의미하며 이는 Memory에서 Section의 RVA를 의미한다.
     6. 따라서 식은 'FileOffset - File에서 각 Section의 시작위치 = Memory상대위치 - Memory에서 각 Section의 시작위치'로 정리할 수 있다.*/


int main(void){

    //기본 정의
    int rva, raw;

    printf("RVA or RAW(to evaluate)");
    char rvaorraw;
    scanf("%c", &rvaorraw);

    if(rvaorraw == "RVA"){
        printf("RAW를 입력");
        scanf("%d", &raw);
        
        rva = raw; //다 쓴 거 아니다. pe reader by c에서 게속함
        
    }
}