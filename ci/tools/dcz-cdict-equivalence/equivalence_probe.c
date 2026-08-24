#ifndef ZSTD_STATIC_LINKING_ONLY
#define ZSTD_STATIC_LINKING_ONLY
#endif
#include <zstd.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
static char dict[1<<20],body[1<<18],o1[1<<21],o2[1<<21];
#define P(o,c,k,v) ZSTD_CCtxParams_setParameter(o,k,v)
static void setcp(ZSTD_CCtx_params*p,ZSTD_compressionParameters cp,int lvl){
  P(p,0,ZSTD_c_compressionLevel,lvl);
  P(p,0,ZSTD_c_windowLog,cp.windowLog);P(p,0,ZSTD_c_chainLog,cp.chainLog);
  P(p,0,ZSTD_c_hashLog,cp.hashLog);P(p,0,ZSTD_c_searchLog,cp.searchLog);
  P(p,0,ZSTD_c_minMatch,cp.minMatch);P(p,0,ZSTD_c_targetLength,cp.targetLength);
  P(p,0,ZSTD_c_strategy,cp.strategy);
}
static void setcc(ZSTD_CCtx*c,ZSTD_compressionParameters cp,int lvl){
  ZSTD_CCtx_setParameter(c,ZSTD_c_compressionLevel,lvl);
  ZSTD_CCtx_setParameter(c,ZSTD_c_windowLog,cp.windowLog);
  ZSTD_CCtx_setParameter(c,ZSTD_c_chainLog,cp.chainLog);
  ZSTD_CCtx_setParameter(c,ZSTD_c_hashLog,cp.hashLog);
  ZSTD_CCtx_setParameter(c,ZSTD_c_searchLog,cp.searchLog);
  ZSTD_CCtx_setParameter(c,ZSTD_c_minMatch,cp.minMatch);
  ZSTD_CCtx_setParameter(c,ZSTD_c_targetLength,cp.targetLength);
  ZSTD_CCtx_setParameter(c,ZSTD_c_strategy,cp.strategy);
}
static size_t slurp(const char*path,char*buf,size_t cap){
  FILE*f=fopen(path,"rb");
  if(!f){fprintf(stderr,"cannot open %s\n",path);exit(1);}
  size_t n=fread(buf,1,cap,f);
  fclose(f);
  if(n<cap){fprintf(stderr,"%s: need %zu bytes, got %zu\n",path,cap,n);exit(1);}
  return n;
}

int main(void){
  slurp("dict.bin",dict,sizeof dict);
  slurp("body.bin",body,sizeof body);
  size_t ds[]={4096,65536,262144,1048576},bs[]={512,8192,131072};
  int bad=0,tot=0;
  for(int di=0;di<4;di++)for(int bi=0;bi<3;bi++){
    size_t dlen=ds[di],blen=bs[bi];
    unsigned wlog=10;while(((size_t)1<<wlog)<dlen+blen&&wlog<23)wlog++;
    for(int lvl=1;lvl<=19;lvl++){
      /* PINNED cparams: derived from level + dict size only, with srcSize
         left at 0 (unknown) so the set is config-time-derivable. The SAME
         cp is then applied to both paths, so any surviving difference is
         the match-finding path itself, not parameter drift. */
      ZSTD_compressionParameters cp=ZSTD_getCParams(lvl,0,dlen);
      if(cp.windowLog>wlog)cp.windowLog=wlog;
      ZSTD_CCtx_params*p=ZSTD_createCCtxParams();setcp(p,cp,lvl);
      ZSTD_CDict*cd=ZSTD_createCDict_advanced2(dict,dlen,ZSTD_dlm_byRef,ZSTD_dct_rawContent,p,ZSTD_defaultCMem);
      ZSTD_CCtx*a=ZSTD_createCCtx();setcc(a,cp,lvl);
      ZSTD_CCtx_setPledgedSrcSize(a,blen);ZSTD_CCtx_refPrefix(a,dict,dlen);
      ZSTD_CCtx_setParameter(a,ZSTD_c_checksumFlag,1);
      size_t r1=ZSTD_compress2(a,o1,sizeof o1,body,blen);
      ZSTD_CCtx*b=ZSTD_createCCtx();setcc(b,cp,lvl);
      ZSTD_CCtx_setPledgedSrcSize(b,blen);ZSTD_CCtx_refCDict(b,cd);
      ZSTD_CCtx_setParameter(b,ZSTD_c_checksumFlag,1);
      size_t r2=ZSTD_compress2(b,o2,sizeof o2,body,blen);
      if(ZSTD_isError(r1)||ZSTD_isError(r2)){
        printf("ERR d=%7zu b=%6zu lvl=%2d: %s / %s\n",dlen,blen,lvl,
               ZSTD_isError(r1)?ZSTD_getErrorName(r1):"ok",
               ZSTD_isError(r2)?ZSTD_getErrorName(r2):"ok");
      } else {
        tot++;
        if(r1!=r2||memcmp(o1,o2,r1)){bad++;printf("DIFF d=%7zu b=%6zu lvl=%2d strategy=%d pfx=%zu cd=%zu\n",dlen,blen,lvl,cp.strategy,r1,r2);}
      }
      ZSTD_freeCCtx(a);ZSTD_freeCCtx(b);ZSTD_freeCDict(cd);ZSTD_freeCCtxParams(p);
    }
  }
  printf("identical %d/%d\n",tot-bad,tot);
  return 0;
}
