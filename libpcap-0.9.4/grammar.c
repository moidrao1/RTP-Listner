/* original parser id follows */
/* yysccsid[] = "@(#)yaccpar	1.9 (Berkeley) 02/21/93" */
/* (use YYMAJOR/YYMINOR for ifdefs dependent on parser version) */

#define YYBYACC 1
#define YYMAJOR 1
#define YYMINOR 9
#define YYPATCH 20140715

#define YYEMPTY        (-1)
#define yyclearin      (yychar = YYEMPTY)
#define yyerrok        (yyerrflag = 0)
#define YYRECOVERING() (yyerrflag != 0)
#define YYENOMEM       (-2)
#define YYEOF          0
#define YYPREFIX "yy"

#define YYPURE 0

#line 2 "grammar.y"
/*
 * Copyright (c) 1988, 1989, 1990, 1991, 1992, 1993, 1994, 1995, 1996
 *	The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that: (1) source code distributions
 * retain the above copyright notice and this paragraph in its entirety, (2)
 * distributions including binary code include the above copyright notice and
 * this paragraph in its entirety in the documentation or other materials
 * provided with the distribution, and (3) all advertising materials mentioning
 * features or use of this software display the following acknowledgement:
 * ``This product includes software developed by the University of California,
 * Lawrence Berkeley Laboratory and its contributors.'' Neither the name of
 * the University nor the names of its contributors may be used to endorse
 * or promote products derived from this software without specific prior
 * written permission.
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 *
 */
#ifndef lint
static const char rcsid[] _U_ =
    "@(#) $Header: /tcpdump/master/libpcap/grammar.y,v 1.86.2.5 2005/09/05 09:08:06 guy Exp $ (LBL)";
#endif

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef WIN32
#include <pcap-stdinc.h>
#else /* WIN32 */
#include <sys/types.h>
#include <sys/socket.h>
#endif /* WIN32 */

#include <stdlib.h>

#ifndef WIN32
#if __STDC__
struct mbuf;
struct rtentry;
#endif

#include <netinet/in.h>
#endif /* WIN32 */

#include <stdio.h>

#include "pcap-int.h"

#include "gencode.h"
#include "pf.h"
#include <pcap-namedb.h>

#ifdef HAVE_OS_PROTO_H
#include "os-proto.h"
#endif

#define QSET(q, p, d, a) (q).proto = (p),\
			 (q).dir = (d),\
			 (q).addr = (a)

int n_errors = 0;

static struct qual qerr = { Q_UNDEF, Q_UNDEF, Q_UNDEF, Q_UNDEF };

static void
yyerror(char *msg)
{
	++n_errors;
	bpf_error("%s", msg);
	/* NOTREACHED */
}

#ifndef YYBISON
int yyparse(void);

int
pcap_parse()
{
	return (yyparse());
}
#endif

#line 90 "grammar.y"
#ifdef YYSTYPE
#undef  YYSTYPE_IS_DECLARED
#define YYSTYPE_IS_DECLARED 1
#endif
#ifndef YYSTYPE_IS_DECLARED
#define YYSTYPE_IS_DECLARED 1
typedef union {
	int i;
	bpf_u_int32 h;
	u_char *e;
	char *s;
	struct stmt *stmt;
	struct arth *a;
	struct {
		struct qual q;
		int atmfieldtype;
		int mtp3fieldtype;
		struct block *b;
	} blk;
	struct block *rblk;
} YYSTYPE;
#endif /* !YYSTYPE_IS_DECLARED */
#line 131 "y.tab.c"

/* compatibility with bison */
#ifdef YYPARSE_PARAM
/* compatibility with FreeBSD */
# ifdef YYPARSE_PARAM_TYPE
#  define YYPARSE_DECL() yyparse(YYPARSE_PARAM_TYPE YYPARSE_PARAM)
# else
#  define YYPARSE_DECL() yyparse(void *YYPARSE_PARAM)
# endif
#else
# define YYPARSE_DECL() yyparse(void)
#endif

/* Parameters sent to lex. */
#ifdef YYLEX_PARAM
# define YYLEX_DECL() yylex(void *YYLEX_PARAM)
# define YYLEX yylex(YYLEX_PARAM)
#else
# define YYLEX_DECL() yylex(void)
# define YYLEX yylex()
#endif

/* Parameters sent to yyerror. */
#ifndef YYERROR_DECL
#define YYERROR_DECL() yyerror(const char *s)
#endif
#ifndef YYERROR_CALL
#define YYERROR_CALL(msg) yyerror(msg)
#endif

extern int YYPARSE_DECL();

#define DST 257
#define SRC 258
#define HOST 259
#define GATEWAY 260
#define NET 261
#define NETMASK 262
#define PORT 263
#define PORTRANGE 264
#define LESS 265
#define GREATER 266
#define PROTO 267
#define PROTOCHAIN 268
#define CBYTE 269
#define ARP 270
#define RARP 271
#define IP 272
#define SCTP 273
#define TCP 274
#define UDP 275
#define ICMP 276
#define IGMP 277
#define IGRP 278
#define PIM 279
#define VRRP 280
#define ATALK 281
#define AARP 282
#define DECNET 283
#define LAT 284
#define SCA 285
#define MOPRC 286
#define MOPDL 287
#define TK_BROADCAST 288
#define TK_MULTICAST 289
#define NUM 290
#define INBOUND 291
#define OUTBOUND 292
#define PF_IFNAME 293
#define PF_RSET 294
#define PF_RNR 295
#define PF_SRNR 296
#define PF_REASON 297
#define PF_ACTION 298
#define LINK 299
#define GEQ 300
#define LEQ 301
#define NEQ 302
#define ID 303
#define EID 304
#define HID 305
#define HID6 306
#define AID 307
#define LSH 308
#define RSH 309
#define LEN 310
#define IPV6 311
#define ICMPV6 312
#define AH 313
#define ESP 314
#define VLAN 315
#define MPLS 316
#define PPPOED 317
#define PPPOES 318
#define ISO 319
#define ESIS 320
#define CLNP 321
#define ISIS 322
#define L1 323
#define L2 324
#define IIH 325
#define LSP 326
#define SNP 327
#define CSNP 328
#define PSNP 329
#define STP 330
#define IPX 331
#define NETBEUI 332
#define LANE 333
#define LLC 334
#define METAC 335
#define BCC 336
#define SC 337
#define ILMIC 338
#define OAMF4EC 339
#define OAMF4SC 340
#define OAM 341
#define OAMF4 342
#define CONNECTMSG 343
#define METACONNECT 344
#define VPI 345
#define VCI 346
#define RADIO 347
#define SIO 348
#define OPC 349
#define DPC 350
#define SLS 351
#define OR 352
#define AND 353
#define UMINUS 354
#define YYERRCODE 256
typedef short YYINT;
static const YYINT yylhs[] = {                           -1,
    0,    0,   24,    1,    1,    1,    1,    1,   20,   21,
    2,    2,    2,    3,    3,    3,    3,    3,    3,    3,
    3,    3,   23,   22,    4,    4,    4,    7,    7,    5,
    5,    8,    8,    8,    8,    8,    8,    6,    6,    6,
    6,    6,    6,    6,    6,    6,    6,    9,    9,   10,
   10,   10,   10,   10,   10,   11,   11,   11,   11,   12,
   16,   16,   16,   16,   16,   16,   16,   16,   16,   16,
   16,   16,   16,   16,   16,   16,   16,   16,   16,   16,
   16,   16,   16,   16,   16,   16,   16,   16,   16,   16,
   16,   16,   16,   16,   16,   16,   16,   16,   25,   25,
   25,   25,   25,   25,   25,   25,   25,   25,   25,   25,
   25,   25,   26,   26,   26,   26,   26,   26,   38,   38,
   37,   18,   18,   18,   19,   19,   19,   13,   13,   14,
   14,   14,   14,   14,   14,   14,   14,   14,   14,   14,
   14,   14,   15,   15,   15,   15,   15,   17,   17,   27,
   27,   27,   27,   27,   27,   27,   27,   28,   28,   28,
   28,   29,   29,   31,   31,   31,   31,   30,   32,   32,
   33,   33,   33,   33,   35,   35,   35,   35,   34,   36,
   36,
};
static const YYINT yylen[] = {                            2,
    2,    1,    0,    1,    3,    3,    3,    3,    1,    1,
    1,    1,    3,    1,    3,    3,    1,    3,    1,    1,
    1,    2,    1,    1,    1,    3,    3,    1,    1,    1,
    2,    3,    2,    2,    2,    2,    2,    2,    3,    1,
    3,    3,    1,    1,    1,    2,    2,    1,    0,    1,
    1,    3,    3,    3,    3,    1,    1,    1,    1,    1,
    1,    1,    1,    1,    1,    1,    1,    1,    1,    1,
    1,    1,    1,    1,    1,    1,    1,    1,    1,    1,
    1,    1,    1,    1,    1,    1,    1,    1,    1,    1,
    1,    1,    1,    1,    1,    1,    1,    1,    2,    2,
    2,    2,    4,    1,    1,    2,    1,    2,    1,    1,
    1,    1,    2,    2,    2,    2,    2,    2,    1,    1,
    1,    1,    1,    1,    1,    1,    1,    1,    1,    4,
    6,    3,    3,    3,    3,    3,    3,    3,    3,    2,
    3,    1,    1,    1,    1,    1,    1,    1,    3,    1,
    1,    1,    1,    1,    1,    1,    1,    1,    1,    1,
    1,    1,    1,    1,    2,    2,    3,    1,    1,    3,
    1,    1,    1,    1,    1,    2,    2,    3,    1,    1,
    3,
};
static const YYINT yydefred[] = {                         3,
    0,    0,    0,    0,    0,   63,   64,   62,   65,   66,
   67,   68,   69,   70,   71,   72,   73,   74,   75,   76,
   77,   79,   78,  148,  104,  105,    0,    0,    0,    0,
    0,    0,   61,  142,   80,   81,   82,   83,    0,    0,
  110,  111,   84,   85,   94,   86,   87,   88,   89,   90,
   91,   93,   92,   95,   96,   97,  150,  151,  152,  153,
  156,  157,  154,  155,  158,  159,  160,  161,  162,  163,
   98,  171,  172,  173,  174,   23,    0,   24,    0,    4,
   30,    0,    0,    0,  129,    0,  128,    0,    0,   43,
  112,   44,   45,    0,    0,  101,  102,    0,  113,  114,
  115,  116,  119,  120,  117,  121,  118,  106,    0,  108,
  140,    0,    0,   10,    9,    0,    0,   14,   20,    0,
    0,   21,   38,   11,   12,    0,    0,    0,    0,   56,
   60,   57,   58,   59,   35,   36,   99,  100,    0,   34,
   37,  123,  125,  127,    0,    0,    0,    0,    0,    0,
    0,    0,  122,  124,  126,    0,    0,    0,    0,    0,
    0,   31,  168,    0,    0,    0,  164,   46,  179,    0,
    0,    0,  175,   47,  144,  143,  146,  147,  145,    0,
    0,    0,    6,    5,    0,    0,    0,    8,    7,    0,
    0,    0,   25,    0,    0,    0,   22,    0,    0,    0,
    0,   32,    0,    0,    0,    0,    0,    0,  134,  135,
    0,    0,    0,   39,  141,  149,  165,  166,  169,    0,
  176,  177,  180,    0,  103,    0,   16,   15,   18,   13,
    0,    0,   53,   55,   52,   54,  130,    0,  167,    0,
  178,    0,   26,   27,    0,  170,  181,  131,
};
static const YYINT yydgoto[] = {                          1,
  159,  197,  124,  194,   80,   81,  195,   82,   83,  139,
  140,  141,   84,   85,  180,  112,   87,  156,  157,  116,
  117,  113,  127,    2,   90,   91,   92,   93,   94,  167,
  168,  220,   95,  173,  174,  224,  107,  105,
};
static const YYINT yysindex[] = {                         0,
    0,  284, -288, -277, -271,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0, -282, -265, -258, -249,
 -273, -252,    0,    0,    0,    0,    0,    0,  -40,  -40,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,  366,    0, -294,    0,
    0,   43,  -19,  119,    0,  -31,    0,  284,  284,    0,
    0,    0,    0,   40,  677,    0,    0,   54,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,  -40,    0,
    0,  -31,  366,    0,    0,  178,  178,    0,    0,  -37,
   38,    0,    0,    0,    0,   43,   43, -235, -216,    0,
    0,    0,    0,    0,    0,    0,    0,    0,  -91,    0,
    0,    0,    0,    0,  366,  366,  366,  366,  366,  366,
  366,  366,    0,    0,    0,  366,  366,  366,  -38,   12,
   62,    0,    0, -185, -183, -181,    0,    0,    0, -169,
 -166, -157,    0,    0,    0,    0,    0,    0,    0, -141,
   62,  673,    0,    0,    0,  178,  178,    0,    0, -153,
 -134, -125,    0,  128, -294,   62,    0,  -87,  -82,  -80,
  -73,    0,  140,  140,  -20,  -14,   -7,   -7,    0,    0,
  673,  673,  158,    0,    0,    0,    0,    0,    0,  -36,
    0,    0,    0,  -34,    0,   62,    0,    0,    0,    0,
   43,   43,    0,    0,    0,    0,    0, -102,    0, -181,
    0, -157,    0,    0,   96,    0,    0,    0,
};
static const YYINT yyrindex[] = {                         0,
    0,  141,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    6,    9,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,  190,    0,
    0,    0,    0,    0,    0,    4,    0,  511,  511,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,  511,  511,    0,    0,   14,
   16,    0,    0,    0,    0,    0,    0,  446,  499,    0,
    0,    0,    0,    0,    0,    0,    0,    0,  134,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,  621,
  661,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    1,  511,  511,    0,    0,    0,
    0,    0,    0, -214,    0, -207,    0,    0,    0,    0,
    0,    0,   26,   82,   93,   70,   11,   36,    0,    0,
   24,   34,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,  236,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,
};
static const YYINT yygindex[] = {                         0,
  189,   -4, -118,    0,   10,    0,    0,    0,    0,    0,
   56,    0,  710,  -76,    0,  104,  727,   53,   64,    3,
 -129,  725,  120,    0,    0,    0,    0,    0,    0, -151,
    0,    0,    0, -152,    0,    0,    0,    0,
};
#define YYTABLESIZE 982
static const YYINT yytable[] = {                         78,
   12,   96,  214,   40,  239,  107,  241,  193,  109,  191,
  132,  160,   97,   17,  219,   19,  103,  148,   98,  223,
   99,  151,  149,   41,  150,  138,  152,  151,  149,  104,
  150,  101,  152,   42,  151,  133,  160,  100,  128,  152,
  102,   12,  128,  128,   40,  128,  107,  128,  132,  109,
  106,  132,  215,  132,   17,  132,   19,  114,  115,  158,
  128,  128,  128,  138,   41,  232,  138,  193,  132,  136,
  132,  132,  132,  133,   42,   76,  133,  123,  133,   78,
  133,  139,   78,  138,  192,  138,  138,  138,  246,  247,
  240,  176,  137,  133,  242,  133,  133,  133,  162,  155,
  154,  153,  216,  132,  217,   86,  218,  136,  163,  160,
  136,  183,  188,  179,  178,  177,  198,  199,  138,  139,
  221,   89,  139,  222,  128,  184,  189,  136,  133,  136,
  136,  136,  169,  137,  132,  200,  201,   29,   29,  139,
    2,  139,  139,  139,   28,   28,  164,  170,  225,  138,
  137,  227,  137,  137,  137,  228,  148,  165,  171,  133,
  151,  149,  136,  150,  229,  152,   33,  130,  230,  132,
  233,  133,  134,   33,  139,  234,  235,  175,  155,  154,
  153,  151,  149,  236,  150,  137,  152,  245,  248,    1,
   79,   86,   86,  136,  202,  148,  162,  231,    0,  151,
  149,    0,  150,    0,  152,  139,    0,   89,   89,    0,
   76,    0,    0,    0,    0,  238,  137,   78,    0,   86,
   86,    0,   77,    0,  190,    0,  243,  244,    0,    0,
    0,    0,    0,    0,    0,  187,  187,  128,  129,  130,
  131,  132,  147,  133,  134,    0,    0,  135,  136,   24,
  237,    0,    0,    0,    0,    0,    0,    0,    0,    0,
   48,   48,   48,   48,   48,    0,   48,   48,  137,  138,
   48,   48,    0,  128,    0,    0,    0,  128,  128,    0,
  128,  147,  128,    0,    0,    0,    0,  145,  146,   86,
   86,   48,   48,  145,  146,  128,  128,  128,    0,    0,
  128,  128,  128,    0,    0,  187,  187,    0,  128,  128,
  132,  132,  132,  114,  115,  114,   76,  114,  132,  132,
    0,    0,    0,   78,    0,  138,  138,  138,   77,  163,
    0,    0,   24,  138,  138,  133,  133,  133,    0,  142,
  143,  144,    0,  133,  133,  118,  119,  120,  121,  122,
    0,    0,   12,   12,    0,   40,   40,  107,  107,  128,
  109,  109,  132,  132,    0,   17,   17,   19,   19,  136,
  136,  136,    0,    0,    0,   41,   41,  138,  138,    0,
    0,  139,  139,  139,    0,   42,   42,  133,  133,  139,
  139,    0,  137,  137,  137,    0,    0,   49,   49,   49,
   49,   49,    0,   49,   49,   78,    0,   49,   49,    0,
   77,    0,    0,    0,    0,    0,    0,    0,  142,  143,
  144,  136,  136,   33,    0,    0,  145,  146,   49,   49,
    0,    0,    0,  139,  139,    0,   33,   33,   33,   33,
   33,    0,    3,    4,  137,  137,    5,    6,    7,    8,
    9,   10,   11,   12,   13,   14,   15,   16,   17,   18,
   19,   20,   21,   22,   23,  145,  146,   24,   25,   26,
   27,   28,   29,   30,   31,   32,   33,    0,   51,    0,
  118,  119,  120,  121,  122,   51,    0,   34,   35,   36,
   37,   38,   39,   40,   41,   42,   43,   44,   45,   46,
   47,   48,   49,   50,   51,   52,   53,   54,   55,   56,
   57,   58,   59,   60,   61,   62,   63,   64,   65,   66,
   67,   68,   69,   70,   71,   72,   73,   74,   75,    0,
    0,   50,    0,    0,    0,  128,  128,  128,   50,    0,
    0,    0,    0,  128,  128,    0,    0,    0,    3,    4,
    0,    0,    5,    6,    7,    8,    9,   10,   11,   12,
   13,   14,   15,   16,   17,   18,   19,   20,   21,   22,
   23,    0,    0,   24,   25,   26,   27,   28,   29,   30,
   31,   32,   33,    0,    0,    0,    0,   28,   28,    0,
    0,    0,    0,   34,   35,   36,   37,   38,   39,   40,
   41,   42,   43,   44,   45,   46,   47,   48,   49,   50,
   51,   52,   53,   54,   55,   56,   57,   58,   59,   60,
   61,   62,   63,   64,   65,   66,   67,   68,   69,   70,
   71,   72,   73,   74,   75,    6,    7,    8,    9,   10,
   11,   12,   13,   14,   15,   16,   17,   18,   19,   20,
   21,   22,   23,    0,    0,   24,    0,    0,  129,    0,
    0,    0,  129,  129,   33,  129,    0,  129,    0,    0,
    0,    0,    0,    0,    0,   34,   35,   36,   37,   38,
  129,  129,  129,    0,   43,   44,   45,   46,   47,   48,
   49,   50,   51,   52,   53,   54,   55,   56,  128,    0,
    0,    0,  128,  128,   51,  128,   51,  128,   51,   51,
  148,    0,   71,    0,  151,  149,   78,  150,    0,  152,
  128,  128,  128,    0,    0,    0,   88,    0,    0,    0,
    0,    0,    0,    0,    0,   51,  155,  154,  153,    0,
    0,    0,    0,    0,  129,    0,    0,    0,   51,   51,
   51,   51,   51,    0,    0,    0,    0,   50,    0,   50,
    0,   50,   50,  109,  109,  108,  110,   49,   49,   49,
   49,   49,    0,   49,   49,    0,    0,   49,   49,    0,
    0,    0,    0,    0,  128,    0,  111,    0,   50,    0,
    0,    0,    0,    0,    0,    0,  147,    0,   49,   49,
    0,   50,   50,   50,   50,   50,  126,    0,  125,    0,
    0,    0,   88,   88,  161,    0,    0,    0,  166,  172,
    0,    0,  182,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,  109,    0,  181,    0,    0,    0,  161,
  186,  186,  185,  185,    0,    0,    0,    0,    0,    0,
  109,  126,  196,  125,  203,  204,  205,  206,  207,  208,
  209,  210,    0,    0,    0,  211,  212,  213,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
   88,  186,  226,  185,    0,    0,    0,    0,    0,    0,
  129,  129,  129,    0,    0,    0,    0,    0,  129,  129,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,  126,  126,  125,  125,    0,
  128,  128,  128,    0,    0,    0,  169,    0,  128,  128,
    0,    0,    0,    0,    0,    0,  142,  143,  144,    0,
  145,  146,
};
static const YYINT yycheck[] = {                         40,
    0,  290,   41,    0,   41,    0,   41,  126,    0,   47,
    0,   88,  290,    0,  166,    0,  290,   38,  290,  172,
  303,   42,   43,    0,   45,    0,   47,   42,   43,  303,
   45,  290,   47,    0,   42,    0,  113,  303,   38,   47,
  290,   41,   42,   43,   41,   45,   41,   47,   38,   41,
  303,   41,   41,   43,   41,   45,   41,  352,  353,   91,
   60,   61,   62,   38,   41,  195,   41,  186,   58,    0,
   60,   61,   62,   38,   41,   33,   41,   82,   43,   40,
   45,    0,   40,   58,   47,   60,   61,   62,  240,  242,
  220,   38,    0,   58,  224,   60,   61,   62,   89,   60,
   61,   62,   41,   93,  290,    2,  290,   38,  290,  186,
   41,  116,  117,   60,   61,   62,  352,  353,   93,   38,
  290,    2,   41,  290,  124,  116,  117,   58,   93,   60,
   61,   62,  290,   41,  124,  352,  353,  352,  353,   58,
    0,   60,   61,   62,  352,  353,   94,   95,  290,  124,
   58,  305,   60,   61,   62,  290,   38,   94,   95,  124,
   42,   43,   93,   45,  290,   47,   33,  259,   41,  261,
  258,  263,  264,   40,   93,  258,  257,  124,   60,   61,
   62,   42,   43,  257,   45,   93,   47,  290,   93,    0,
    2,   88,   89,  124,  139,   38,  187,  195,   -1,   42,
   43,   -1,   45,   -1,   47,  124,   -1,   88,   89,   -1,
   33,   -1,   -1,   -1,   -1,   58,  124,   40,   -1,  116,
  117,   -1,   45,   -1,  262,   -1,  231,  232,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,  116,  117,  257,  258,  259,
  260,  261,  124,  263,  264,   -1,   -1,  267,  268,  290,
   93,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
  257,  258,  259,  260,  261,   -1,  263,  264,  288,  289,
  267,  268,   -1,   38,   -1,   -1,   -1,   42,   43,   -1,
   45,  124,   47,   -1,   -1,   -1,   -1,  308,  309,  186,
  187,  288,  289,  308,  309,   60,   61,   62,   -1,   -1,
  300,  301,  302,   -1,   -1,  186,  187,   -1,  308,  309,
  300,  301,  302,  352,  353,  352,   33,  352,  308,  309,
   -1,   -1,   -1,   40,   -1,  300,  301,  302,   45,  290,
   -1,   -1,  290,  308,  309,  300,  301,  302,   -1,  300,
  301,  302,   -1,  308,  309,  303,  304,  305,  306,  307,
   -1,   -1,  352,  353,   -1,  352,  353,  352,  353,  124,
  352,  353,  352,  353,   -1,  352,  353,  352,  353,  300,
  301,  302,   -1,   -1,   -1,  352,  353,  352,  353,   -1,
   -1,  300,  301,  302,   -1,  352,  353,  352,  353,  308,
  309,   -1,  300,  301,  302,   -1,   -1,  257,  258,  259,
  260,  261,   -1,  263,  264,   40,   -1,  267,  268,   -1,
   45,   -1,   -1,   -1,   -1,   -1,   -1,   -1,  300,  301,
  302,  352,  353,  290,   -1,   -1,  308,  309,  288,  289,
   -1,   -1,   -1,  352,  353,   -1,  303,  304,  305,  306,
  307,   -1,  265,  266,  352,  353,  269,  270,  271,  272,
  273,  274,  275,  276,  277,  278,  279,  280,  281,  282,
  283,  284,  285,  286,  287,  308,  309,  290,  291,  292,
  293,  294,  295,  296,  297,  298,  299,   -1,   33,   -1,
  303,  304,  305,  306,  307,   40,   -1,  310,  311,  312,
  313,  314,  315,  316,  317,  318,  319,  320,  321,  322,
  323,  324,  325,  326,  327,  328,  329,  330,  331,  332,
  333,  334,  335,  336,  337,  338,  339,  340,  341,  342,
  343,  344,  345,  346,  347,  348,  349,  350,  351,   -1,
   -1,   33,   -1,   -1,   -1,  300,  301,  302,   40,   -1,
   -1,   -1,   -1,  308,  309,   -1,   -1,   -1,  265,  266,
   -1,   -1,  269,  270,  271,  272,  273,  274,  275,  276,
  277,  278,  279,  280,  281,  282,  283,  284,  285,  286,
  287,   -1,   -1,  290,  291,  292,  293,  294,  295,  296,
  297,  298,  299,   -1,   -1,   -1,   -1,  352,  353,   -1,
   -1,   -1,   -1,  310,  311,  312,  313,  314,  315,  316,
  317,  318,  319,  320,  321,  322,  323,  324,  325,  326,
  327,  328,  329,  330,  331,  332,  333,  334,  335,  336,
  337,  338,  339,  340,  341,  342,  343,  344,  345,  346,
  347,  348,  349,  350,  351,  270,  271,  272,  273,  274,
  275,  276,  277,  278,  279,  280,  281,  282,  283,  284,
  285,  286,  287,   -1,   -1,  290,   -1,   -1,   38,   -1,
   -1,   -1,   42,   43,  299,   45,   -1,   47,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,  310,  311,  312,  313,  314,
   60,   61,   62,   -1,  319,  320,  321,  322,  323,  324,
  325,  326,  327,  328,  329,  330,  331,  332,   38,   -1,
   -1,   -1,   42,   43,  259,   45,  261,   47,  263,  264,
   38,   -1,  347,   -1,   42,   43,   40,   45,   -1,   47,
   60,   61,   62,   -1,   -1,   -1,    2,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,  290,   60,   61,   62,   -1,
   -1,   -1,   -1,   -1,  124,   -1,   -1,   -1,  303,  304,
  305,  306,  307,   -1,   -1,   -1,   -1,  259,   -1,  261,
   -1,  263,  264,   39,   40,   39,   40,  257,  258,  259,
  260,  261,   -1,  263,  264,   -1,   -1,  267,  268,   -1,
   -1,   -1,   -1,   -1,  124,   -1,   77,   -1,  290,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,  124,   -1,  288,  289,
   -1,  303,  304,  305,  306,  307,   82,   -1,   82,   -1,
   -1,   -1,   88,   89,   88,   -1,   -1,   -1,   94,   95,
   -1,   -1,  113,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,  109,   -1,  109,   -1,   -1,   -1,  113,
  116,  117,  116,  117,   -1,   -1,   -1,   -1,   -1,   -1,
  126,  127,  126,  127,  145,  146,  147,  148,  149,  150,
  151,  152,   -1,   -1,   -1,  156,  157,  158,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
  186,  187,  186,  187,   -1,   -1,   -1,   -1,   -1,   -1,
  300,  301,  302,   -1,   -1,   -1,   -1,   -1,  308,  309,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,  231,  232,  231,  232,   -1,
  300,  301,  302,   -1,   -1,   -1,  290,   -1,  308,  309,
   -1,   -1,   -1,   -1,   -1,   -1,  300,  301,  302,   -1,
  308,  309,
};
#define YYFINAL 1
#ifndef YYDEBUG
#define YYDEBUG 0
#endif
#define YYMAXTOKEN 354
#define YYUNDFTOKEN 395
#define YYTRANSLATE(a) ((a) > YYMAXTOKEN ? YYUNDFTOKEN : (a))
#if YYDEBUG
static const char *const yyname[] = {

"end-of-file",0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
"'!'",0,0,0,0,"'&'",0,"'('","')'","'*'","'+'",0,"'-'",0,"'/'",0,0,0,0,0,0,0,0,0,
0,"':'",0,"'<'","'='","'>'",0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
0,0,"'['",0,"']'",0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
"'|'",0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,"DST","SRC","HOST","GATEWAY","NET","NETMASK",
"PORT","PORTRANGE","LESS","GREATER","PROTO","PROTOCHAIN","CBYTE","ARP","RARP",
"IP","SCTP","TCP","UDP","ICMP","IGMP","IGRP","PIM","VRRP","ATALK","AARP",
"DECNET","LAT","SCA","MOPRC","MOPDL","TK_BROADCAST","TK_MULTICAST","NUM",
"INBOUND","OUTBOUND","PF_IFNAME","PF_RSET","PF_RNR","PF_SRNR","PF_REASON",
"PF_ACTION","LINK","GEQ","LEQ","NEQ","ID","EID","HID","HID6","AID","LSH","RSH",
"LEN","IPV6","ICMPV6","AH","ESP","VLAN","MPLS","PPPOED","PPPOES","ISO","ESIS",
"CLNP","ISIS","L1","L2","IIH","LSP","SNP","CSNP","PSNP","STP","IPX","NETBEUI",
"LANE","LLC","METAC","BCC","SC","ILMIC","OAMF4EC","OAMF4SC","OAM","OAMF4",
"CONNECTMSG","METACONNECT","VPI","VCI","RADIO","SIO","OPC","DPC","SLS","OR",
"AND","UMINUS",0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,"illegal-symbol",
};
static const char *const yyrule[] = {
"$accept : prog",
"prog : null expr",
"prog : null",
"null :",
"expr : term",
"expr : expr and term",
"expr : expr and id",
"expr : expr or term",
"expr : expr or id",
"and : AND",
"or : OR",
"id : nid",
"id : pnum",
"id : paren pid ')'",
"nid : ID",
"nid : HID '/' NUM",
"nid : HID NETMASK HID",
"nid : HID",
"nid : HID6 '/' NUM",
"nid : HID6",
"nid : EID",
"nid : AID",
"nid : not id",
"not : '!'",
"paren : '('",
"pid : nid",
"pid : qid and id",
"pid : qid or id",
"qid : pnum",
"qid : pid",
"term : rterm",
"term : not term",
"head : pqual dqual aqual",
"head : pqual dqual",
"head : pqual aqual",
"head : pqual PROTO",
"head : pqual PROTOCHAIN",
"head : pqual ndaqual",
"rterm : head id",
"rterm : paren expr ')'",
"rterm : pname",
"rterm : arth relop arth",
"rterm : arth irelop arth",
"rterm : other",
"rterm : atmtype",
"rterm : atmmultitype",
"rterm : atmfield atmvalue",
"rterm : mtp3field mtp3value",
"pqual : pname",
"pqual :",
"dqual : SRC",
"dqual : DST",
"dqual : SRC OR DST",
"dqual : DST OR SRC",
"dqual : SRC AND DST",
"dqual : DST AND SRC",
"aqual : HOST",
"aqual : NET",
"aqual : PORT",
"aqual : PORTRANGE",
"ndaqual : GATEWAY",
"pname : LINK",
"pname : IP",
"pname : ARP",
"pname : RARP",
"pname : SCTP",
"pname : TCP",
"pname : UDP",
"pname : ICMP",
"pname : IGMP",
"pname : IGRP",
"pname : PIM",
"pname : VRRP",
"pname : ATALK",
"pname : AARP",
"pname : DECNET",
"pname : LAT",
"pname : SCA",
"pname : MOPDL",
"pname : MOPRC",
"pname : IPV6",
"pname : ICMPV6",
"pname : AH",
"pname : ESP",
"pname : ISO",
"pname : ESIS",
"pname : ISIS",
"pname : L1",
"pname : L2",
"pname : IIH",
"pname : LSP",
"pname : SNP",
"pname : PSNP",
"pname : CSNP",
"pname : CLNP",
"pname : STP",
"pname : IPX",
"pname : NETBEUI",
"pname : RADIO",
"other : pqual TK_BROADCAST",
"other : pqual TK_MULTICAST",
"other : LESS NUM",
"other : GREATER NUM",
"other : CBYTE NUM byteop NUM",
"other : INBOUND",
"other : OUTBOUND",
"other : VLAN pnum",
"other : VLAN",
"other : MPLS pnum",
"other : MPLS",
"other : PPPOED",
"other : PPPOES",
"other : pfvar",
"pfvar : PF_IFNAME ID",
"pfvar : PF_RSET ID",
"pfvar : PF_RNR NUM",
"pfvar : PF_SRNR NUM",
"pfvar : PF_REASON reason",
"pfvar : PF_ACTION action",
"reason : NUM",
"reason : ID",
"action : ID",
"relop : '>'",
"relop : GEQ",
"relop : '='",
"irelop : LEQ",
"irelop : '<'",
"irelop : NEQ",
"arth : pnum",
"arth : narth",
"narth : pname '[' arth ']'",
"narth : pname '[' arth ':' NUM ']'",
"narth : arth '+' arth",
"narth : arth '-' arth",
"narth : arth '*' arth",
"narth : arth '/' arth",
"narth : arth '&' arth",
"narth : arth '|' arth",
"narth : arth LSH arth",
"narth : arth RSH arth",
"narth : '-' arth",
"narth : paren narth ')'",
"narth : LEN",
"byteop : '&'",
"byteop : '|'",
"byteop : '<'",
"byteop : '>'",
"byteop : '='",
"pnum : NUM",
"pnum : paren pnum ')'",
"atmtype : LANE",
"atmtype : LLC",
"atmtype : METAC",
"atmtype : BCC",
"atmtype : OAMF4EC",
"atmtype : OAMF4SC",
"atmtype : SC",
"atmtype : ILMIC",
"atmmultitype : OAM",
"atmmultitype : OAMF4",
"atmmultitype : CONNECTMSG",
"atmmultitype : METACONNECT",
"atmfield : VPI",
"atmfield : VCI",
"atmvalue : atmfieldvalue",
"atmvalue : relop NUM",
"atmvalue : irelop NUM",
"atmvalue : paren atmlistvalue ')'",
"atmfieldvalue : NUM",
"atmlistvalue : atmfieldvalue",
"atmlistvalue : atmlistvalue or atmfieldvalue",
"mtp3field : SIO",
"mtp3field : OPC",
"mtp3field : DPC",
"mtp3field : SLS",
"mtp3value : mtp3fieldvalue",
"mtp3value : relop NUM",
"mtp3value : irelop NUM",
"mtp3value : paren mtp3listvalue ')'",
"mtp3fieldvalue : NUM",
"mtp3listvalue : mtp3fieldvalue",
"mtp3listvalue : mtp3listvalue or mtp3fieldvalue",

};
#endif

int      yydebug;
int      yynerrs;

int      yyerrflag;
int      yychar;
YYSTYPE  yyval;
YYSTYPE  yylval;

/* define the initial stack-sizes */
#ifdef YYSTACKSIZE
#undef YYMAXDEPTH
#define YYMAXDEPTH  YYSTACKSIZE
#else
#ifdef YYMAXDEPTH
#define YYSTACKSIZE YYMAXDEPTH
#else
#define YYSTACKSIZE 10000
#define YYMAXDEPTH  10000
#endif
#endif

#define YYINITSTACKSIZE 200

typedef struct {
    unsigned stacksize;
    YYINT    *s_base;
    YYINT    *s_mark;
    YYINT    *s_last;
    YYSTYPE  *l_base;
    YYSTYPE  *l_mark;
} YYSTACKDATA;
/* variables for the parser stack */
static YYSTACKDATA yystack;

#if YYDEBUG
#include <stdio.h>		/* needed for printf */
#endif

#include <stdlib.h>	/* needed for malloc, etc */
#include <string.h>	/* needed for memset */

/* allocate initial stack or double stack size, up to YYMAXDEPTH */
static int yygrowstack(YYSTACKDATA *data)
{
    int i;
    unsigned newsize;
    YYINT *newss;
    YYSTYPE *newvs;

    if ((newsize = data->stacksize) == 0)
        newsize = YYINITSTACKSIZE;
    else if (newsize >= YYMAXDEPTH)
        return YYENOMEM;
    else if ((newsize *= 2) > YYMAXDEPTH)
        newsize = YYMAXDEPTH;

    i = (int) (data->s_mark - data->s_base);
    newss = (YYINT *)realloc(data->s_base, newsize * sizeof(*newss));
    if (newss == 0)
        return YYENOMEM;

    data->s_base = newss;
    data->s_mark = newss + i;

    newvs = (YYSTYPE *)realloc(data->l_base, newsize * sizeof(*newvs));
    if (newvs == 0)
        return YYENOMEM;

    data->l_base = newvs;
    data->l_mark = newvs + i;

    data->stacksize = newsize;
    data->s_last = data->s_base + newsize - 1;
    return 0;
}

#if YYPURE || defined(YY_NO_LEAKS)
static void yyfreestack(YYSTACKDATA *data)
{
    free(data->s_base);
    free(data->l_base);
    memset(data, 0, sizeof(*data));
}
#else
#define yyfreestack(data) /* nothing */
#endif

#define YYABORT  goto yyabort
#define YYREJECT goto yyabort
#define YYACCEPT goto yyaccept
#define YYERROR  goto yyerrlab

int
YYPARSE_DECL()
{
    int yym, yyn, yystate;
#if YYDEBUG
    const char *yys;

    if ((yys = getenv("YYDEBUG")) != 0)
    {
        yyn = *yys;
        if (yyn >= '0' && yyn <= '9')
            yydebug = yyn - '0';
    }
#endif

    yynerrs = 0;
    yyerrflag = 0;
    yychar = YYEMPTY;
    yystate = 0;

#if YYPURE
    memset(&yystack, 0, sizeof(yystack));
#endif

    if (yystack.s_base == NULL && yygrowstack(&yystack) == YYENOMEM) goto yyoverflow;
    yystack.s_mark = yystack.s_base;
    yystack.l_mark = yystack.l_base;
    yystate = 0;
    *yystack.s_mark = 0;

yyloop:
    if ((yyn = yydefred[yystate]) != 0) goto yyreduce;
    if (yychar < 0)
    {
        if ((yychar = YYLEX) < 0) yychar = YYEOF;
#if YYDEBUG
        if (yydebug)
        {
            yys = yyname[YYTRANSLATE(yychar)];
            printf("%sdebug: state %d, reading %d (%s)\n",
                    YYPREFIX, yystate, yychar, yys);
        }
#endif
    }
    if ((yyn = yysindex[yystate]) && (yyn += yychar) >= 0 &&
            yyn <= YYTABLESIZE && yycheck[yyn] == yychar)
    {
#if YYDEBUG
        if (yydebug)
            printf("%sdebug: state %d, shifting to state %d\n",
                    YYPREFIX, yystate, yytable[yyn]);
#endif
        if (yystack.s_mark >= yystack.s_last && yygrowstack(&yystack) == YYENOMEM)
        {
            goto yyoverflow;
        }
        yystate = yytable[yyn];
        *++yystack.s_mark = yytable[yyn];
        *++yystack.l_mark = yylval;
        yychar = YYEMPTY;
        if (yyerrflag > 0)  --yyerrflag;
        goto yyloop;
    }
    if ((yyn = yyrindex[yystate]) && (yyn += yychar) >= 0 &&
            yyn <= YYTABLESIZE && yycheck[yyn] == yychar)
    {
        yyn = yytable[yyn];
        goto yyreduce;
    }
    if (yyerrflag) goto yyinrecovery;

    YYERROR_CALL("syntax error");

    goto yyerrlab;

yyerrlab:
    ++yynerrs;

yyinrecovery:
    if (yyerrflag < 3)
    {
        yyerrflag = 3;
        for (;;)
        {
            if ((yyn = yysindex[*yystack.s_mark]) && (yyn += YYERRCODE) >= 0 &&
                    yyn <= YYTABLESIZE && yycheck[yyn] == YYERRCODE)
            {
#if YYDEBUG
                if (yydebug)
                    printf("%sdebug: state %d, error recovery shifting\
 to state %d\n", YYPREFIX, *yystack.s_mark, yytable[yyn]);
#endif
                if (yystack.s_mark >= yystack.s_last && yygrowstack(&yystack) == YYENOMEM)
                {
                    goto yyoverflow;
                }
                yystate = yytable[yyn];
                *++yystack.s_mark = yytable[yyn];
                *++yystack.l_mark = yylval;
                goto yyloop;
            }
            else
            {
#if YYDEBUG
                if (yydebug)
                    printf("%sdebug: error recovery discarding state %d\n",
                            YYPREFIX, *yystack.s_mark);
#endif
                if (yystack.s_mark <= yystack.s_base) goto yyabort;
                --yystack.s_mark;
                --yystack.l_mark;
            }
        }
    }
    else
    {
        if (yychar == YYEOF) goto yyabort;
#if YYDEBUG
        if (yydebug)
        {
            yys = yyname[YYTRANSLATE(yychar)];
            printf("%sdebug: state %d, error recovery discards token %d (%s)\n",
                    YYPREFIX, yystate, yychar, yys);
        }
#endif
        yychar = YYEMPTY;
        goto yyloop;
    }

yyreduce:
#if YYDEBUG
    if (yydebug)
        printf("%sdebug: state %d, reducing by rule %d (%s)\n",
                YYPREFIX, yystate, yyn, yyrule[yyn]);
#endif
    yym = yylen[yyn];
    if (yym)
        yyval = yystack.l_mark[1-yym];
    else
        memset(&yyval, 0, sizeof yyval);
    switch (yyn)
    {
case 1:
#line 161 "grammar.y"
	{
	finish_parse(yystack.l_mark[0].blk.b);
}
break;
case 3:
#line 166 "grammar.y"
	{ yyval.blk.q = qerr; }
break;
case 5:
#line 169 "grammar.y"
	{ gen_and(yystack.l_mark[-2].blk.b, yystack.l_mark[0].blk.b); yyval.blk = yystack.l_mark[0].blk; }
break;
case 6:
#line 170 "grammar.y"
	{ gen_and(yystack.l_mark[-2].blk.b, yystack.l_mark[0].blk.b); yyval.blk = yystack.l_mark[0].blk; }
break;
case 7:
#line 171 "grammar.y"
	{ gen_or(yystack.l_mark[-2].blk.b, yystack.l_mark[0].blk.b); yyval.blk = yystack.l_mark[0].blk; }
break;
case 8:
#line 172 "grammar.y"
	{ gen_or(yystack.l_mark[-2].blk.b, yystack.l_mark[0].blk.b); yyval.blk = yystack.l_mark[0].blk; }
break;
case 9:
#line 174 "grammar.y"
	{ yyval.blk = yystack.l_mark[-1].blk; }
break;
case 10:
#line 176 "grammar.y"
	{ yyval.blk = yystack.l_mark[-1].blk; }
break;
case 12:
#line 179 "grammar.y"
	{ yyval.blk.b = gen_ncode(NULL, (bpf_u_int32)yystack.l_mark[0].i,
						   yyval.blk.q = yystack.l_mark[-1].blk.q); }
break;
case 13:
#line 181 "grammar.y"
	{ yyval.blk = yystack.l_mark[-1].blk; }
break;
case 14:
#line 183 "grammar.y"
	{ yyval.blk.b = gen_scode(yystack.l_mark[0].s, yyval.blk.q = yystack.l_mark[-1].blk.q); }
break;
case 15:
#line 184 "grammar.y"
	{ yyval.blk.b = gen_mcode(yystack.l_mark[-2].s, NULL, yystack.l_mark[0].i,
				    yyval.blk.q = yystack.l_mark[-3].blk.q); }
break;
case 16:
#line 186 "grammar.y"
	{ yyval.blk.b = gen_mcode(yystack.l_mark[-2].s, yystack.l_mark[0].s, 0,
				    yyval.blk.q = yystack.l_mark[-3].blk.q); }
break;
case 17:
#line 188 "grammar.y"
	{
				  /* Decide how to parse HID based on proto */
				  yyval.blk.q = yystack.l_mark[-1].blk.q;
				  yyval.blk.b = gen_ncode(yystack.l_mark[0].s, 0, yyval.blk.q);
				}
break;
case 18:
#line 193 "grammar.y"
	{
#ifdef INET6
				  yyval.blk.b = gen_mcode6(yystack.l_mark[-2].s, NULL, yystack.l_mark[0].i,
				    yyval.blk.q = yystack.l_mark[-3].blk.q);
#else
				  bpf_error("'ip6addr/prefixlen' not supported "
					"in this configuration");
#endif /*INET6*/
				}
break;
case 19:
#line 202 "grammar.y"
	{
#ifdef INET6
				  yyval.blk.b = gen_mcode6(yystack.l_mark[0].s, 0, 128,
				    yyval.blk.q = yystack.l_mark[-1].blk.q);
#else
				  bpf_error("'ip6addr' not supported "
					"in this configuration");
#endif /*INET6*/
				}
break;
case 20:
#line 211 "grammar.y"
	{ 
				  yyval.blk.b = gen_ecode(yystack.l_mark[0].e, yyval.blk.q = yystack.l_mark[-1].blk.q);
				  /*
				   * $1 was allocated by "pcap_ether_aton()",
				   * so we must free it now that we're done
				   * with it.
				   */
				  free(yystack.l_mark[0].e);
				}
break;
case 21:
#line 220 "grammar.y"
	{
				  yyval.blk.b = gen_acode(yystack.l_mark[0].e, yyval.blk.q = yystack.l_mark[-1].blk.q);
				  /*
				   * $1 was allocated by "pcap_ether_aton()",
				   * so we must free it now that we're done
				   * with it.
				   */
				  free(yystack.l_mark[0].e);
				}
break;
case 22:
#line 229 "grammar.y"
	{ gen_not(yystack.l_mark[0].blk.b); yyval.blk = yystack.l_mark[0].blk; }
break;
case 23:
#line 231 "grammar.y"
	{ yyval.blk = yystack.l_mark[-1].blk; }
break;
case 24:
#line 233 "grammar.y"
	{ yyval.blk = yystack.l_mark[-1].blk; }
break;
case 26:
#line 236 "grammar.y"
	{ gen_and(yystack.l_mark[-2].blk.b, yystack.l_mark[0].blk.b); yyval.blk = yystack.l_mark[0].blk; }
break;
case 27:
#line 237 "grammar.y"
	{ gen_or(yystack.l_mark[-2].blk.b, yystack.l_mark[0].blk.b); yyval.blk = yystack.l_mark[0].blk; }
break;
case 28:
#line 239 "grammar.y"
	{ yyval.blk.b = gen_ncode(NULL, (bpf_u_int32)yystack.l_mark[0].i,
						   yyval.blk.q = yystack.l_mark[-1].blk.q); }
break;
case 31:
#line 244 "grammar.y"
	{ gen_not(yystack.l_mark[0].blk.b); yyval.blk = yystack.l_mark[0].blk; }
break;
case 32:
#line 246 "grammar.y"
	{ QSET(yyval.blk.q, yystack.l_mark[-2].i, yystack.l_mark[-1].i, yystack.l_mark[0].i); }
break;
case 33:
#line 247 "grammar.y"
	{ QSET(yyval.blk.q, yystack.l_mark[-1].i, yystack.l_mark[0].i, Q_DEFAULT); }
break;
case 34:
#line 248 "grammar.y"
	{ QSET(yyval.blk.q, yystack.l_mark[-1].i, Q_DEFAULT, yystack.l_mark[0].i); }
break;
case 35:
#line 249 "grammar.y"
	{ QSET(yyval.blk.q, yystack.l_mark[-1].i, Q_DEFAULT, Q_PROTO); }
break;
case 36:
#line 250 "grammar.y"
	{ QSET(yyval.blk.q, yystack.l_mark[-1].i, Q_DEFAULT, Q_PROTOCHAIN); }
break;
case 37:
#line 251 "grammar.y"
	{ QSET(yyval.blk.q, yystack.l_mark[-1].i, Q_DEFAULT, yystack.l_mark[0].i); }
break;
case 38:
#line 253 "grammar.y"
	{ yyval.blk = yystack.l_mark[0].blk; }
break;
case 39:
#line 254 "grammar.y"
	{ yyval.blk.b = yystack.l_mark[-1].blk.b; yyval.blk.q = yystack.l_mark[-2].blk.q; }
break;
case 40:
#line 255 "grammar.y"
	{ yyval.blk.b = gen_proto_abbrev(yystack.l_mark[0].i); yyval.blk.q = qerr; }
break;
case 41:
#line 256 "grammar.y"
	{ yyval.blk.b = gen_relation(yystack.l_mark[-1].i, yystack.l_mark[-2].a, yystack.l_mark[0].a, 0);
				  yyval.blk.q = qerr; }
break;
case 42:
#line 258 "grammar.y"
	{ yyval.blk.b = gen_relation(yystack.l_mark[-1].i, yystack.l_mark[-2].a, yystack.l_mark[0].a, 1);
				  yyval.blk.q = qerr; }
break;
case 43:
#line 260 "grammar.y"
	{ yyval.blk.b = yystack.l_mark[0].rblk; yyval.blk.q = qerr; }
break;
case 44:
#line 261 "grammar.y"
	{ yyval.blk.b = gen_atmtype_abbrev(yystack.l_mark[0].i); yyval.blk.q = qerr; }
break;
case 45:
#line 262 "grammar.y"
	{ yyval.blk.b = gen_atmmulti_abbrev(yystack.l_mark[0].i); yyval.blk.q = qerr; }
break;
case 46:
#line 263 "grammar.y"
	{ yyval.blk.b = yystack.l_mark[0].blk.b; yyval.blk.q = qerr; }
break;
case 47:
#line 264 "grammar.y"
	{ yyval.blk.b = yystack.l_mark[0].blk.b; yyval.blk.q = qerr; }
break;
case 49:
#line 268 "grammar.y"
	{ yyval.i = Q_DEFAULT; }
break;
case 50:
#line 271 "grammar.y"
	{ yyval.i = Q_SRC; }
break;
case 51:
#line 272 "grammar.y"
	{ yyval.i = Q_DST; }
break;
case 52:
#line 273 "grammar.y"
	{ yyval.i = Q_OR; }
break;
case 53:
#line 274 "grammar.y"
	{ yyval.i = Q_OR; }
break;
case 54:
#line 275 "grammar.y"
	{ yyval.i = Q_AND; }
break;
case 55:
#line 276 "grammar.y"
	{ yyval.i = Q_AND; }
break;
case 56:
#line 279 "grammar.y"
	{ yyval.i = Q_HOST; }
break;
case 57:
#line 280 "grammar.y"
	{ yyval.i = Q_NET; }
break;
case 58:
#line 281 "grammar.y"
	{ yyval.i = Q_PORT; }
break;
case 59:
#line 282 "grammar.y"
	{ yyval.i = Q_PORTRANGE; }
break;
case 60:
#line 285 "grammar.y"
	{ yyval.i = Q_GATEWAY; }
break;
case 61:
#line 287 "grammar.y"
	{ yyval.i = Q_LINK; }
break;
case 62:
#line 288 "grammar.y"
	{ yyval.i = Q_IP; }
break;
case 63:
#line 289 "grammar.y"
	{ yyval.i = Q_ARP; }
break;
case 64:
#line 290 "grammar.y"
	{ yyval.i = Q_RARP; }
break;
case 65:
#line 291 "grammar.y"
	{ yyval.i = Q_SCTP; }
break;
case 66:
#line 292 "grammar.y"
	{ yyval.i = Q_TCP; }
break;
case 67:
#line 293 "grammar.y"
	{ yyval.i = Q_UDP; }
break;
case 68:
#line 294 "grammar.y"
	{ yyval.i = Q_ICMP; }
break;
case 69:
#line 295 "grammar.y"
	{ yyval.i = Q_IGMP; }
break;
case 70:
#line 296 "grammar.y"
	{ yyval.i = Q_IGRP; }
break;
case 71:
#line 297 "grammar.y"
	{ yyval.i = Q_PIM; }
break;
case 72:
#line 298 "grammar.y"
	{ yyval.i = Q_VRRP; }
break;
case 73:
#line 299 "grammar.y"
	{ yyval.i = Q_ATALK; }
break;
case 74:
#line 300 "grammar.y"
	{ yyval.i = Q_AARP; }
break;
case 75:
#line 301 "grammar.y"
	{ yyval.i = Q_DECNET; }
break;
case 76:
#line 302 "grammar.y"
	{ yyval.i = Q_LAT; }
break;
case 77:
#line 303 "grammar.y"
	{ yyval.i = Q_SCA; }
break;
case 78:
#line 304 "grammar.y"
	{ yyval.i = Q_MOPDL; }
break;
case 79:
#line 305 "grammar.y"
	{ yyval.i = Q_MOPRC; }
break;
case 80:
#line 306 "grammar.y"
	{ yyval.i = Q_IPV6; }
break;
case 81:
#line 307 "grammar.y"
	{ yyval.i = Q_ICMPV6; }
break;
case 82:
#line 308 "grammar.y"
	{ yyval.i = Q_AH; }
break;
case 83:
#line 309 "grammar.y"
	{ yyval.i = Q_ESP; }
break;
case 84:
#line 310 "grammar.y"
	{ yyval.i = Q_ISO; }
break;
case 85:
#line 311 "grammar.y"
	{ yyval.i = Q_ESIS; }
break;
case 86:
#line 312 "grammar.y"
	{ yyval.i = Q_ISIS; }
break;
case 87:
#line 313 "grammar.y"
	{ yyval.i = Q_ISIS_L1; }
break;
case 88:
#line 314 "grammar.y"
	{ yyval.i = Q_ISIS_L2; }
break;
case 89:
#line 315 "grammar.y"
	{ yyval.i = Q_ISIS_IIH; }
break;
case 90:
#line 316 "grammar.y"
	{ yyval.i = Q_ISIS_LSP; }
break;
case 91:
#line 317 "grammar.y"
	{ yyval.i = Q_ISIS_SNP; }
break;
case 92:
#line 318 "grammar.y"
	{ yyval.i = Q_ISIS_PSNP; }
break;
case 93:
#line 319 "grammar.y"
	{ yyval.i = Q_ISIS_CSNP; }
break;
case 94:
#line 320 "grammar.y"
	{ yyval.i = Q_CLNP; }
break;
case 95:
#line 321 "grammar.y"
	{ yyval.i = Q_STP; }
break;
case 96:
#line 322 "grammar.y"
	{ yyval.i = Q_IPX; }
break;
case 97:
#line 323 "grammar.y"
	{ yyval.i = Q_NETBEUI; }
break;
case 98:
#line 324 "grammar.y"
	{ yyval.i = Q_RADIO; }
break;
case 99:
#line 326 "grammar.y"
	{ yyval.rblk = gen_broadcast(yystack.l_mark[-1].i); }
break;
case 100:
#line 327 "grammar.y"
	{ yyval.rblk = gen_multicast(yystack.l_mark[-1].i); }
break;
case 101:
#line 328 "grammar.y"
	{ yyval.rblk = gen_less(yystack.l_mark[0].i); }
break;
case 102:
#line 329 "grammar.y"
	{ yyval.rblk = gen_greater(yystack.l_mark[0].i); }
break;
case 103:
#line 330 "grammar.y"
	{ yyval.rblk = gen_byteop(yystack.l_mark[-1].i, yystack.l_mark[-2].i, yystack.l_mark[0].i); }
break;
case 104:
#line 331 "grammar.y"
	{ yyval.rblk = gen_inbound(0); }
break;
case 105:
#line 332 "grammar.y"
	{ yyval.rblk = gen_inbound(1); }
break;
case 106:
#line 333 "grammar.y"
	{ yyval.rblk = gen_vlan(yystack.l_mark[0].i); }
break;
case 107:
#line 334 "grammar.y"
	{ yyval.rblk = gen_vlan(-1); }
break;
case 108:
#line 335 "grammar.y"
	{ yyval.rblk = gen_mpls(yystack.l_mark[0].i); }
break;
case 109:
#line 336 "grammar.y"
	{ yyval.rblk = gen_mpls(-1); }
break;
case 110:
#line 337 "grammar.y"
	{ yyval.rblk = gen_pppoed(); }
break;
case 111:
#line 338 "grammar.y"
	{ yyval.rblk = gen_pppoes(); }
break;
case 112:
#line 339 "grammar.y"
	{ yyval.rblk = yystack.l_mark[0].rblk; }
break;
case 113:
#line 342 "grammar.y"
	{ yyval.rblk = gen_pf_ifname(yystack.l_mark[0].s); }
break;
case 114:
#line 343 "grammar.y"
	{ yyval.rblk = gen_pf_ruleset(yystack.l_mark[0].s); }
break;
case 115:
#line 344 "grammar.y"
	{ yyval.rblk = gen_pf_rnr(yystack.l_mark[0].i); }
break;
case 116:
#line 345 "grammar.y"
	{ yyval.rblk = gen_pf_srnr(yystack.l_mark[0].i); }
break;
case 117:
#line 346 "grammar.y"
	{ yyval.rblk = gen_pf_reason(yystack.l_mark[0].i); }
break;
case 118:
#line 347 "grammar.y"
	{ yyval.rblk = gen_pf_action(yystack.l_mark[0].i); }
break;
case 119:
#line 350 "grammar.y"
	{ yyval.i = yystack.l_mark[0].i; }
break;
case 120:
#line 351 "grammar.y"
	{ const char *reasons[] = PFRES_NAMES;
				  int i;
				  for (i = 0; reasons[i]; i++) {
					  if (pcap_strcasecmp(yystack.l_mark[0].s, reasons[i]) == 0) {
						  yyval.i = i;
						  break;
					  }
				  }
				  if (reasons[i] == NULL)
					  bpf_error("unknown PF reason");
				}
break;
case 121:
#line 364 "grammar.y"
	{ if (pcap_strcasecmp(yystack.l_mark[0].s, "pass") == 0 ||
				      pcap_strcasecmp(yystack.l_mark[0].s, "accept") == 0)
					yyval.i = PF_PASS;
				  else if (pcap_strcasecmp(yystack.l_mark[0].s, "drop") == 0 ||
				      pcap_strcasecmp(yystack.l_mark[0].s, "block") == 0)
					yyval.i = PF_DROP;
				  else
					  bpf_error("unknown PF action");
				}
break;
case 122:
#line 375 "grammar.y"
	{ yyval.i = BPF_JGT; }
break;
case 123:
#line 376 "grammar.y"
	{ yyval.i = BPF_JGE; }
break;
case 124:
#line 377 "grammar.y"
	{ yyval.i = BPF_JEQ; }
break;
case 125:
#line 379 "grammar.y"
	{ yyval.i = BPF_JGT; }
break;
case 126:
#line 380 "grammar.y"
	{ yyval.i = BPF_JGE; }
break;
case 127:
#line 381 "grammar.y"
	{ yyval.i = BPF_JEQ; }
break;
case 128:
#line 383 "grammar.y"
	{ yyval.a = gen_loadi(yystack.l_mark[0].i); }
break;
case 130:
#line 386 "grammar.y"
	{ yyval.a = gen_load(yystack.l_mark[-3].i, yystack.l_mark[-1].a, 1); }
break;
case 131:
#line 387 "grammar.y"
	{ yyval.a = gen_load(yystack.l_mark[-5].i, yystack.l_mark[-3].a, yystack.l_mark[-1].i); }
break;
case 132:
#line 388 "grammar.y"
	{ yyval.a = gen_arth(BPF_ADD, yystack.l_mark[-2].a, yystack.l_mark[0].a); }
break;
case 133:
#line 389 "grammar.y"
	{ yyval.a = gen_arth(BPF_SUB, yystack.l_mark[-2].a, yystack.l_mark[0].a); }
break;
case 134:
#line 390 "grammar.y"
	{ yyval.a = gen_arth(BPF_MUL, yystack.l_mark[-2].a, yystack.l_mark[0].a); }
break;
case 135:
#line 391 "grammar.y"
	{ yyval.a = gen_arth(BPF_DIV, yystack.l_mark[-2].a, yystack.l_mark[0].a); }
break;
case 136:
#line 392 "grammar.y"
	{ yyval.a = gen_arth(BPF_AND, yystack.l_mark[-2].a, yystack.l_mark[0].a); }
break;
case 137:
#line 393 "grammar.y"
	{ yyval.a = gen_arth(BPF_OR, yystack.l_mark[-2].a, yystack.l_mark[0].a); }
break;
case 138:
#line 394 "grammar.y"
	{ yyval.a = gen_arth(BPF_LSH, yystack.l_mark[-2].a, yystack.l_mark[0].a); }
break;
case 139:
#line 395 "grammar.y"
	{ yyval.a = gen_arth(BPF_RSH, yystack.l_mark[-2].a, yystack.l_mark[0].a); }
break;
case 140:
#line 396 "grammar.y"
	{ yyval.a = gen_neg(yystack.l_mark[0].a); }
break;
case 141:
#line 397 "grammar.y"
	{ yyval.a = yystack.l_mark[-1].a; }
break;
case 142:
#line 398 "grammar.y"
	{ yyval.a = gen_loadlen(); }
break;
case 143:
#line 400 "grammar.y"
	{ yyval.i = '&'; }
break;
case 144:
#line 401 "grammar.y"
	{ yyval.i = '|'; }
break;
case 145:
#line 402 "grammar.y"
	{ yyval.i = '<'; }
break;
case 146:
#line 403 "grammar.y"
	{ yyval.i = '>'; }
break;
case 147:
#line 404 "grammar.y"
	{ yyval.i = '='; }
break;
case 149:
#line 407 "grammar.y"
	{ yyval.i = yystack.l_mark[-1].i; }
break;
case 150:
#line 409 "grammar.y"
	{ yyval.i = A_LANE; }
break;
case 151:
#line 410 "grammar.y"
	{ yyval.i = A_LLC; }
break;
case 152:
#line 411 "grammar.y"
	{ yyval.i = A_METAC;	}
break;
case 153:
#line 412 "grammar.y"
	{ yyval.i = A_BCC; }
break;
case 154:
#line 413 "grammar.y"
	{ yyval.i = A_OAMF4EC; }
break;
case 155:
#line 414 "grammar.y"
	{ yyval.i = A_OAMF4SC; }
break;
case 156:
#line 415 "grammar.y"
	{ yyval.i = A_SC; }
break;
case 157:
#line 416 "grammar.y"
	{ yyval.i = A_ILMIC; }
break;
case 158:
#line 418 "grammar.y"
	{ yyval.i = A_OAM; }
break;
case 159:
#line 419 "grammar.y"
	{ yyval.i = A_OAMF4; }
break;
case 160:
#line 420 "grammar.y"
	{ yyval.i = A_CONNECTMSG; }
break;
case 161:
#line 421 "grammar.y"
	{ yyval.i = A_METACONNECT; }
break;
case 162:
#line 424 "grammar.y"
	{ yyval.blk.atmfieldtype = A_VPI; }
break;
case 163:
#line 425 "grammar.y"
	{ yyval.blk.atmfieldtype = A_VCI; }
break;
case 165:
#line 428 "grammar.y"
	{ yyval.blk.b = gen_atmfield_code(yystack.l_mark[-2].blk.atmfieldtype, (bpf_int32)yystack.l_mark[0].i, (bpf_u_int32)yystack.l_mark[-1].i, 0); }
break;
case 166:
#line 429 "grammar.y"
	{ yyval.blk.b = gen_atmfield_code(yystack.l_mark[-2].blk.atmfieldtype, (bpf_int32)yystack.l_mark[0].i, (bpf_u_int32)yystack.l_mark[-1].i, 1); }
break;
case 167:
#line 430 "grammar.y"
	{ yyval.blk.b = yystack.l_mark[-1].blk.b; yyval.blk.q = qerr; }
break;
case 168:
#line 432 "grammar.y"
	{
	yyval.blk.atmfieldtype = yystack.l_mark[-1].blk.atmfieldtype;
	if (yyval.blk.atmfieldtype == A_VPI ||
	    yyval.blk.atmfieldtype == A_VCI)
		yyval.blk.b = gen_atmfield_code(yyval.blk.atmfieldtype, (bpf_int32) yystack.l_mark[0].i, BPF_JEQ, 0);
	}
break;
case 170:
#line 440 "grammar.y"
	{ gen_or(yystack.l_mark[-2].blk.b, yystack.l_mark[0].blk.b); yyval.blk = yystack.l_mark[0].blk; }
break;
case 171:
#line 443 "grammar.y"
	{ yyval.blk.mtp3fieldtype = M_SIO; }
break;
case 172:
#line 444 "grammar.y"
	{ yyval.blk.mtp3fieldtype = M_OPC; }
break;
case 173:
#line 445 "grammar.y"
	{ yyval.blk.mtp3fieldtype = M_DPC; }
break;
case 174:
#line 446 "grammar.y"
	{ yyval.blk.mtp3fieldtype = M_SLS; }
break;
case 176:
#line 449 "grammar.y"
	{ yyval.blk.b = gen_mtp3field_code(yystack.l_mark[-2].blk.mtp3fieldtype, (u_int)yystack.l_mark[0].i, (u_int)yystack.l_mark[-1].i, 0); }
break;
case 177:
#line 450 "grammar.y"
	{ yyval.blk.b = gen_mtp3field_code(yystack.l_mark[-2].blk.mtp3fieldtype, (u_int)yystack.l_mark[0].i, (u_int)yystack.l_mark[-1].i, 1); }
break;
case 178:
#line 451 "grammar.y"
	{ yyval.blk.b = yystack.l_mark[-1].blk.b; yyval.blk.q = qerr; }
break;
case 179:
#line 453 "grammar.y"
	{
	yyval.blk.mtp3fieldtype = yystack.l_mark[-1].blk.mtp3fieldtype;
	if (yyval.blk.mtp3fieldtype == M_SIO ||
	    yyval.blk.mtp3fieldtype == M_OPC ||
	    yyval.blk.mtp3fieldtype == M_DPC ||
	    yyval.blk.mtp3fieldtype == M_SLS )
		yyval.blk.b = gen_mtp3field_code(yyval.blk.mtp3fieldtype, (u_int) yystack.l_mark[0].i, BPF_JEQ, 0);
	}
break;
case 181:
#line 463 "grammar.y"
	{ gen_or(yystack.l_mark[-2].blk.b, yystack.l_mark[0].blk.b); yyval.blk = yystack.l_mark[0].blk; }
break;
#line 1799 "y.tab.c"
    }
    yystack.s_mark -= yym;
    yystate = *yystack.s_mark;
    yystack.l_mark -= yym;
    yym = yylhs[yyn];
    if (yystate == 0 && yym == 0)
    {
#if YYDEBUG
        if (yydebug)
            printf("%sdebug: after reduction, shifting from state 0 to\
 state %d\n", YYPREFIX, YYFINAL);
#endif
        yystate = YYFINAL;
        *++yystack.s_mark = YYFINAL;
        *++yystack.l_mark = yyval;
        if (yychar < 0)
        {
            if ((yychar = YYLEX) < 0) yychar = YYEOF;
#if YYDEBUG
            if (yydebug)
            {
                yys = yyname[YYTRANSLATE(yychar)];
                printf("%sdebug: state %d, reading %d (%s)\n",
                        YYPREFIX, YYFINAL, yychar, yys);
            }
#endif
        }
        if (yychar == YYEOF) goto yyaccept;
        goto yyloop;
    }
    if ((yyn = yygindex[yym]) && (yyn += yystate) >= 0 &&
            yyn <= YYTABLESIZE && yycheck[yyn] == yystate)
        yystate = yytable[yyn];
    else
        yystate = yydgoto[yym];
#if YYDEBUG
    if (yydebug)
        printf("%sdebug: after reduction, shifting from state %d \
to state %d\n", YYPREFIX, *yystack.s_mark, yystate);
#endif
    if (yystack.s_mark >= yystack.s_last && yygrowstack(&yystack) == YYENOMEM)
    {
        goto yyoverflow;
    }
    *++yystack.s_mark = (YYINT) yystate;
    *++yystack.l_mark = yyval;
    goto yyloop;

yyoverflow:
    YYERROR_CALL("yacc stack overflow");

yyabort:
    yyfreestack(&yystack);
    return (1);

yyaccept:
    yyfreestack(&yystack);
    return (0);
}
