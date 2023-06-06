#include <stdio.h>

typedef struct section_header
{
    char Name[8];
    union
    {
        int PhysicalAddress;
        int VirtualSize;
    } Misc;
} section_header;

typedef struct mydata {
    int a;
} mydata;

int main()
{


// //section_header.Misc.PhysicalAddress;
// mydata data_1;
// data_1.a = 10;

// printf("data_1 : %d\n", data_1.a);




section_header Sectionheader;
Sectionheader.Name;
Sectionheader.Misc.PhysicalAddress = 10;
Sectionheader.Misc.VirtualSize = 999;

printf("%d\n", Sectionheader.Misc.PhysicalAddress);




    return 0;
}