/* DISPOSABLE TEST SIGNER ONLY. Private state stays in this process's RAM.
 * EOF destroys it. Never restore, deploy or enroll this program as a signer. */
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <sys/random.h>
#include "hss.h"
static bool random_bytes(void *out,size_t n) {
    unsigned char *p=out;
    while(n) { ssize_t r=getrandom(p,n,0); if(r<=0)return false;p+=r;n-=r; }
    return true;
}
static void hexprint(const unsigned char *p,size_t n) {
    while(n--)printf("%02x",*p++);putchar('\n');fflush(stdout);
}
static int digit(char c) {
    if(c>='0'&&c<='9')return c-'0';if(c>='a'&&c<='f')return c-'a'+10;return -1;
}
int main(int argc,char **argv) {
    (void)argv;if(argc!=1)return 2;
    param_set_t lm[1]={LMS_SHA256_N32_H10},ots[1]={LMOTS_SHA256_N32_W8};
    unsigned char pub[HSS_MAX_PUBLIC_KEY_LEN],priv[HSS_MAX_PRIVATE_KEY_LEN];
    size_t plen=hss_get_public_key_len(1,lm,ots);
    if(!hss_generate_private_key(random_bytes,1,lm,ots,NULL,priv,pub,plen,NULL,0,NULL))return 3;
    struct hss_working_key *wk=hss_load_private_key(NULL,priv,1024*1024,NULL,0,NULL);
    if(!wk)return 3;
    size_t slen=hss_get_signature_len_from_working_key(wk);
    unsigned char *sig=malloc(slen);if(!sig)return 3;
    hexprint(pub,plen);
    char line[32770];unsigned char message[16384];int result=0;
    while(fgets(line,sizeof(line),stdin)) {
        size_t chars=strlen(line);
        if(!chars||line[chars-1]!='\n'){result=2;break;}
        chars--;if(!chars||chars%2||chars/2>sizeof(message)){result=2;break;}
        size_t n=chars/2;bool valid=true;
        for(size_t i=0;i<n;i++) {int a=digit(line[i*2]),b=digit(line[i*2+1]);if(a<0||b<0){valid=false;break;}message[i]=(unsigned char)(16*a+b);}
        if(!valid){result=2;break;}
        if(!hss_generate_signature(wk,NULL,priv,message,n,sig,slen,NULL)){result=3;break;}
        hexprint(sig,slen);
    }
    hss_free_working_key(wk);memset(priv,0,sizeof(priv));free(sig);return result;
}
