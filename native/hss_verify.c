/* Bounded wrapper around the unmodified Cisco HSS/LMS verifier. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "hss.h"
static size_t read_file(const char *path,unsigned char *out,size_t cap) {
    FILE *f=fopen(path,"rb");if(!f)return 0;
    size_t n=fread(out,1,cap,f);int c=fgetc(f);int bad=ferror(f);fclose(f);
    return c==EOF&&!bad?n:0;
}
int main(int argc,char **argv) {
    if(argc!=4)return 2;
    unsigned char key[60],message[16384],signature[65536];
    size_t k=read_file(argv[1],key,sizeof(key));
    size_t m=read_file(argv[2],message,sizeof(message));
    size_t s=read_file(argv[3],signature,sizeof(signature));
    /* One HSS level, LMS SHA256 N32 H10, LMOTS SHA256 N32 W8. */
    const unsigned char prefix[]={0,0,0,1,0,0,0,6,0,0,0,4};
    if(k!=60||!m||s!=1456||memcmp(key,prefix,sizeof(prefix)))return 2;
    return hss_validate_signature(key,message,m,signature,s,NULL)?0:1;
}
