/* Narrow primitive, not an authority boundary. Caller must burn the external
 * leaf marker before arda_sign, then durably store state before signature release. */
#include <stdint.h>
#include <string.h>
#include "hss.h"
#include "hss_zeroize.h"
__attribute__((import_module("env"),import_name("random_fill")))
extern int random_fill(void *,unsigned);
static unsigned char private_state[64],public_key[60],message[16384],signature[1456];
static bool random_bytes(void *out,size_t n){return n<=65536 && random_fill(out,(unsigned)n)==1;}
static int parameters(void){unsigned levels;param_set_t lm[MAX_HSS_LEVELS],ots[MAX_HSS_LEVELS];
 return hss_get_parameter_set(&levels,lm,ots,NULL,private_state) && levels==1 && lm[0]==LMS_SHA256_N32_H10 && ots[0]==LMOTS_SHA256_N32_W8;}
unsigned char *arda_private_ptr(void){return private_state;}
unsigned char *arda_public_ptr(void){return public_key;}
unsigned char *arda_message_ptr(void){return message;}
unsigned char *arda_signature_ptr(void){return signature;}
unsigned arda_leaf(void){uint64_t q=0;for(int i=0;i<8;i++)q=(q<<8)|private_state[i];return q<1024?(unsigned)q:1024;}
void arda_clear(void){hss_zeroize(private_state,sizeof private_state);hss_zeroize(public_key,sizeof public_key);hss_zeroize(message,sizeof message);hss_zeroize(signature,sizeof signature);}
int arda_generate(void){arda_clear();param_set_t lm[]={LMS_SHA256_N32_H10},ots[]={LMOTS_SHA256_N32_W8};
 return hss_get_private_key_len(1,lm,ots)==64 && hss_generate_private_key(random_bytes,1,lm,ots,NULL,private_state,public_key,sizeof public_key,NULL,0,NULL);}
int arda_sign(unsigned n){
 hss_zeroize(signature,sizeof signature);
 if(n==0||n>sizeof message||!parameters()||arda_leaf()>=1024)return 0;
 unsigned leaf=arda_leaf();
 struct hss_working_key *w=hss_load_private_key(NULL,private_state,1024*1024,NULL,0,NULL);if(!w)return 0;
 int ok=hss_get_signature_len_from_working_key(w)==sizeof signature && hss_generate_signature(w,NULL,private_state,message,n,signature,sizeof signature,NULL);
 hss_free_working_key(w);
 if(!ok||arda_leaf()!=leaf+1||signature[0]||signature[1]||signature[2]||signature[3])goto fail;
 unsigned got=((unsigned)signature[4]<<24)|((unsigned)signature[5]<<16)|((unsigned)signature[6]<<8)|signature[7];
 if(got!=leaf||!hss_validate_signature(public_key,message,n,signature,sizeof signature,NULL))goto fail;
 return 1;
fail:hss_zeroize(signature,sizeof signature);return 0;
}
