#include <stdio.h>
#include <string.h>
#include <stdlib.h>
typedef unsigned char u_char; typedef long ngx_int_t; typedef unsigned long size_t_;
typedef struct { size_t len; u_char *data; } ngx_str_t;
#define NGX_OK 0
#define NGX_ERROR -1
#define NGX_DECLINED -5
#define LEN 32
#define BUFLEN 64
static u_char b64tab[256];
static void init(void){ const char*a="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
 memset(b64tab,77,256); for(int i=0;i<64;i++) b64tab[(u_char)a[i]]=i; }
/* faithful port of ngx_decode_base64_internal */
static int dec(ngx_str_t*dst,ngx_str_t*src){ size_t len; u_char *d,*s;
 for(len=0;len<src->len;len++){ if(src->data[len]=='=') break; if(b64tab[src->data[len]]==77) return NGX_ERROR; }
 if(len%4==1) return NGX_ERROR;
 s=src->data; d=dst->data;
 while(len>3){ *d++=(u_char)(b64tab[s[0]]<<2|b64tab[s[1]]>>4);
  *d++=(u_char)(b64tab[s[1]]<<4|b64tab[s[2]]>>2);
  *d++=(u_char)(b64tab[s[2]]<<6|b64tab[s[3]]); s+=4; len-=4; }
 if(len>1) *d++=(u_char)(b64tab[s[0]]<<2|b64tab[s[1]]>>4);
 if(len>2) *d++=(u_char)(b64tab[s[1]]<<4|b64tab[s[2]]>>2);
 dst->len=d-dst->data; return NGX_OK; }
/* MASTER: negotiate gate + helper (both return DECLINED) */
static ngx_int_t helper_master(ngx_str_t raw,u_char*out){ ngx_str_t b,d;
 if(raw.len<2||raw.data[0]!=':'||raw.data[raw.len-1]!=':'||raw.len-2>44) return NGX_DECLINED;
 b.data=raw.data+1;b.len=raw.len-2;d.data=out;
 if(dec(&d,&b)!=NGX_OK||d.len!=LEN) return NGX_DECLINED;
 return NGX_OK; }
static int negotiate_master(ngx_str_t v,u_char*out,const char**msg){
 if(v.len<2||v.data[0]!=':'||v.data[v.len-1]!=':'||v.len-2>44){*msg="malformed";return 0;}
 if(helper_master(v,out)!=NGX_OK){*msg="notbase64";return 0;}
 *msg="accept";return 1; }
/* BRANCH */
static ngx_int_t helper_br(ngx_str_t raw,u_char*out){ ngx_str_t b,d;
 if(raw.len<2||raw.data[0]!=':'||raw.data[raw.len-1]!=':'||raw.len-2>44) return NGX_DECLINED;
 b.data=raw.data+1;b.len=raw.len-2;d.data=out;
 if(dec(&d,&b)!=NGX_OK||d.len!=LEN) return NGX_ERROR;
 return NGX_OK; }
static int negotiate_br(ngx_str_t v,u_char*out,const char**msg){ ngx_int_t rc=helper_br(v,out);
 if(rc==NGX_DECLINED){*msg="malformed";return 0;}
 if(rc!=NGX_OK){*msg="notbase64";return 0;}
 *msg="accept";return 1; }
int main(void){ init();
 const char*cases[]={"",":","::",":abc","abc:","AAAA",
  ":AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=:",         /* 44 valid, decodes to 32 -> ACCEPT */
  ":AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8:",          /* 43, unpadded valid -> ACCEPT */
  ":QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVphYmNk:",            /* 40 valid b64, decodes to 30 */
  ":QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVphYmNkZQ==:",        /* >44 */
  ":QUJD:",                                                 /* valid b64 short */
  ":!!!!:",":====:",":QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVph:", /* 36ch */
  ":A:",":AA:",":AAA:",":AAAA:", ":\x1b\x7f:", NULL};
 int diff=0;
 printf("%-50s %-12s %-12s\n","input","master","branch");
 for(int i=0;cases[i];i++){ u_char o1[BUFLEN],o2[BUFLEN]; const char*m1,*m2;
  ngx_str_t v; v.data=(u_char*)cases[i]; v.len=strlen(cases[i]);
  int r1=negotiate_master(v,o1,&m1), r2=negotiate_br(v,o2,&m2);
  int d=(r1!=r2)||strcmp(m1,m2); if(d)diff++;
  printf("%-50s %-12s %-12s %s\n",cases[i][0]?cases[i]:"(empty)",m1,m2,d?"<<<DIFF":"");
 }
 printf("\nDIFFERENCES: %d\n",diff); return diff!=0; }
