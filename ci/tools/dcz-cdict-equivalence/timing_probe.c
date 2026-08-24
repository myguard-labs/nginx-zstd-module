#ifndef ZSTD_STATIC_LINKING_ONLY
#define ZSTD_STATIC_LINKING_ONLY
#endif
#include <zstd.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
static char dict[1<<20],body[1<<18],o[1<<21],dec[1<<19];
static double now(void){struct timespec t;clock_gettime(CLOCK_MONOTONIC,&t);return t.tv_sec+t.tv_nsec/1e9;}
static void slurp(const char*path,char*buf,size_t cap){
  FILE*f=fopen(path,"rb");
  if(!f){fprintf(stderr,"cannot open %s\n",path);exit(1);}
  size_t n=fread(buf,1,cap,f);
  fclose(f);
  if(n<cap){fprintf(stderr,"%s: need %zu bytes, got %zu\n",path,cap,n);exit(1);}
}

int main(void){
  slurp("dict.bin",dict,sizeof dict);
  slurp("body.bin",body,sizeof body);
  size_t ds[]={4096,65536,1048576}; size_t blen=8192; int lvl=9; int N=300;
  for(int i=0;i<3;i++){
    size_t dlen=ds[i];
    unsigned wlog=10;while(((size_t)1<<wlog)<dlen+blen&&wlog<23)wlog++;
    double t0=now();size_t r1=0;
    for(int k=0;k<N;k++){
      ZSTD_CCtx*c=ZSTD_createCCtx();
      ZSTD_CCtx_setParameter(c,ZSTD_c_compressionLevel,lvl);
      ZSTD_CCtx_setParameter(c,ZSTD_c_windowLog,wlog);
      ZSTD_CCtx_setPledgedSrcSize(c,blen);
      ZSTD_CCtx_refPrefix(c,dict,dlen);
      ZSTD_CCtx_setParameter(c,ZSTD_c_checksumFlag,1);
      r1=ZSTD_compress2(c,o,sizeof o,body,blen);ZSTD_freeCCtx(c);}
    double t1=now();
    ZSTD_CCtx_params*p=ZSTD_createCCtxParams();
    ZSTD_CCtxParams_setParameter(p,ZSTD_c_compressionLevel,lvl);
    ZSTD_CCtxParams_setParameter(p,ZSTD_c_windowLog,wlog);
    ZSTD_CDict*cd=ZSTD_createCDict_advanced2(dict,dlen,ZSTD_dlm_byRef,ZSTD_dct_rawContent,p,ZSTD_defaultCMem);
    double t2=now();size_t r2=0;
    for(int k=0;k<N;k++){
      ZSTD_CCtx*c=ZSTD_createCCtx();
      ZSTD_CCtx_setParameter(c,ZSTD_c_compressionLevel,lvl);
      ZSTD_CCtx_setParameter(c,ZSTD_c_windowLog,wlog);
      ZSTD_CCtx_setPledgedSrcSize(c,blen);
      ZSTD_CCtx_refCDict(c,cd);
      ZSTD_CCtx_setParameter(c,ZSTD_c_checksumFlag,1);
      r2=ZSTD_compress2(c,o,sizeof o,body,blen);ZSTD_freeCCtx(c);}
    double t3=now();
    /* decode the CDict output with the raw dict as prefix -> must roundtrip */
    ZSTD_DCtx*d=ZSTD_createDCtx();
    ZSTD_DCtx_setParameter(d,ZSTD_d_windowLogMax,23);
    ZSTD_DCtx_refPrefix(d,dict,dlen);
    size_t dr=ZSTD_decompressDCtx(d,dec,sizeof dec,o,r2);
    int ok=!ZSTD_isError(dr)&&dr==blen&&!memcmp(dec,body,blen);
    printf("dict=%8zu wlog=%2u  refPrefix %7.1f us/req (%zu B)  cachedCDict %6.1f us/req (%zu B)  roundtrip=%s\n",
      dlen,wlog,(t1-t0)/N*1e6,r1,(t3-t2)/N*1e6,r2,ok?"OK":"FAIL");
    ZSTD_freeDCtx(d);ZSTD_freeCDict(cd);ZSTD_freeCCtxParams(p);
  }
  return 0;
}
