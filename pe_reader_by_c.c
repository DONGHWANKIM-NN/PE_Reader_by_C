#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>

typedef unsigned short WORD;
typedef unsigned long DWORD;

// WinNT.h
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


int main(int argc, const char* argv[]) {

    if (argc <= 1) {
        printf("please insert parameter\n");
        exit(1);
    }
    /**
     * @brief 파일 입출력을 위한 파일 포인터
     *
     */
    FILE* fp;

    /**
     * @brief 파일을 연다!
     * 실패한다면 프로그램을 종료한다.
     *
     */
    fp = fopen(argv[1]/*프로그램 매개변수로 받은 파일 이름*/, "rb" /*바이너리 읽기 모드*/);
    if (fp == NULL) {
        printf("File Open Error\n");
        exit(1);
    }

    IMAGE_DOS_HEADER dos_header;
    fread(&dos_header, sizeof(IMAGE_DOS_HEADER), 1, fp);
    printf("magic : %x\n", dos_header.e_magic);
   

    /**
     * @brief 파일을 닫는다!
     * 실패한다면 프로그램을 종료한다.
     *
     */
    if (fclose(fp) != NULL) {
        printf("File close Error\n");
        exit(1);
    }

    return 0;
}