/* asn.c
 *
 * Copyright (C) 2006-2014 wolfSSL Inc.
 *
 * This file is part of CyaSSL.
 *
 * CyaSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * CyaSSL is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA
 */

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <cyassl/ctaocrypt/settings.h>

#ifndef NO_ASN

#ifdef HAVE_RTP_SYS
    #include "os.h"           /* dc_rtc_api needs    */
    #include "dc_rtc_api.h"   /* to get current time */
#endif

#include <cyassl/ctaocrypt/integer.h>
#include <cyassl/ctaocrypt/asn.h>
#include <cyassl/ctaocrypt/coding.h>
#include <cyassl/ctaocrypt/md2.h>
#include <cyassl/ctaocrypt/hmac.h>
#include <cyassl/ctaocrypt/error-crypt.h>
#include <cyassl/ctaocrypt/pwdbased.h>
#include <cyassl/ctaocrypt/des3.h>
#include <cyassl/ctaocrypt/logging.h>

#include <cyassl/ctaocrypt/random.h>


#ifndef NO_RC4
    #include <cyassl/ctaocrypt/arc4.h>
#endif

#ifdef HAVE_NTRU
    #include "ntru_crypto.h"
#endif

#ifdef HAVE_ECC
    #include <cyassl/ctaocrypt/ecc.h>
#endif

#ifdef CYASSL_DEBUG_ENCODING
    #ifdef FREESCALE_MQX
        #include <fio.h>
    #else
        #include <stdio.h>
    #endif
#endif

#ifdef _MSC_VER
    /* 4996 warning to use MS extensions e.g., strcpy_s instead of XSTRNCPY */
    #pragma warning(disable: 4996)
#endif


#ifndef TRUE
    #define TRUE  1
#endif
#ifndef FALSE
    #define FALSE 0
#endif


#ifdef HAVE_RTP_SYS 
    /* uses parital <time.h> structures */
    #define XTIME(tl)  (0)
    #define XGMTIME(c) my_gmtime((c))
    #define XVALIDATE_DATE(d, f, t) ValidateDate((d), (f), (t))
#elif defined(MICRIUM)
    #if (NET_SECURE_MGR_CFG_EN == DEF_ENABLED)
        #define XVALIDATE_DATE(d,f,t) NetSecure_ValidateDateHandler((d),(f),(t))
    #else
        #define XVALIDATE_DATE(d, f, t) (0)
    #endif
    #define NO_TIME_H
    /* since Micrium not defining XTIME or XGMTIME, CERT_GEN not available */
#elif defined(MICROCHIP_TCPIP_V5) || defined(MICROCHIP_TCPIP)
    #include <time.h>
    #define XTIME(t1) pic32_time((t1))
    #define XGMTIME(c) gmtime((c))
    #define XVALIDATE_DATE(d, f, t) ValidateDate((d), (f), (t))
#elif defined(FREESCALE_MQX)
    #define XTIME(t1)  mqx_time((t1))
    #define XGMTIME(c) mqx_gmtime((c))
    #define XVALIDATE_DATE(d, f, t) ValidateDate((d), (f), (t))
#elif defined(CYASSL_MDK_ARM)
    #if defined(CYASSL_MDK5)
        #include "cmsis_os.h"
    #else
        #include <rtl.h>
    #endif
    #undef RNG
    #include "cyassl_MDK_ARM.h"
    #undef RNG
    #define RNG CyaSSL_RNG /*for avoiding name conflict in "stm32f2xx.h" */
    #define XTIME(tl)  (0)
    #define XGMTIME(c) Cyassl_MDK_gmtime((c))
    #define XVALIDATE_DATE(d, f, t)  ValidateDate((d), (f), (t))
#elif defined(USER_TIME)
    /* user time, and gmtime compatible functions, there is a gmtime 
       implementation here that WINCE uses, so really just need some ticks
       since the EPOCH 
    */

    struct tm {
	int	tm_sec;		/* seconds after the minute [0-60] */
	int	tm_min;		/* minutes after the hour [0-59] */
	int	tm_hour;	/* hours since midnight [0-23] */
	int	tm_mday;	/* day of the month [1-31] */
	int	tm_mon;		/* months since January [0-11] */
	int	tm_year;	/* years since 1900 */
	int	tm_wday;	/* days since Sunday [0-6] */
	int	tm_yday;	/* days since January 1 [0-365] */
	int	tm_isdst;	/* Daylight Savings Time flag */
	long	tm_gmtoff;	/* offset from CUT in seconds */
	char	*tm_zone;	/* timezone abbreviation */
    };
    typedef long time_t;

    /* forward declaration */
    struct tm* gmtime(const time_t* timer);
    extern time_t XTIME(time_t * timer);

    #define XGMTIME(c) gmtime((c))
    #define XVALIDATE_DATE(d, f, t) ValidateDate((d), (f), (t))

    #ifdef STACK_TRAP
        /* for stack trap tracking, don't call os gmtime on OS X/linux,
           uses a lot of stack spce */
        extern time_t time(time_t * timer);
        #define XTIME(tl)  time((tl))
    #endif /* STACK_TRAP */

#else
    /* default */
    /* uses complete <time.h> facility */
    #include <time.h>
    #define XTIME(tl)  time((tl))
    #define XGMTIME(c) gmtime((c))
    #define XVALIDATE_DATE(d, f, t) ValidateDate((d), (f), (t))
#endif


#ifdef _WIN32_WCE
/* no time() or gmtime() even though in time.h header?? */

#include <windows.h>


time_t time(time_t* timer)
{
    SYSTEMTIME     sysTime;
    FILETIME       fTime;
    ULARGE_INTEGER intTime;
    time_t         localTime;

    if (timer == NULL)
        timer = &localTime;

    GetSystemTime(&sysTime);
    SystemTimeToFileTime(&sysTime, &fTime);
    
    XMEMCPY(&intTime, &fTime, sizeof(FILETIME));
    /* subtract EPOCH */
    intTime.QuadPart -= 0x19db1ded53e8000;
    /* to secs */
    intTime.QuadPart /= 10000000;
    *timer = (time_t)intTime.QuadPart;

    return *timer;
}

#endif /*  _WIN32_WCE */
#if defined( _WIN32_WCE ) || defined( USER_TIME )

struct tm* gmtime(const time_t* timer)
{
    #define YEAR0          1900
    #define EPOCH_YEAR     1970
    #define SECS_DAY       (24L * 60L * 60L)
    #define LEAPYEAR(year) (!((year) % 4) && (((year) % 100) || !((year) %400)))
    #define YEARSIZE(year) (LEAPYEAR(year) ? 366 : 365)

    static const int _ytab[2][12] =
    {
        {31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31},
        {31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31}
    };

    static struct tm st_time;
    struct tm* ret = &st_time;
    time_t secs = *timer;
    unsigned long dayclock, dayno;
    int year = EPOCH_YEAR;

    dayclock = (unsigned long)secs % SECS_DAY;
    dayno    = (unsigned long)secs / SECS_DAY;

    ret->tm_sec  = (int) dayclock % 60;
    ret->tm_min  = (int)(dayclock % 3600) / 60;
    ret->tm_hour = (int) dayclock / 3600;
    ret->tm_wday = (int) (dayno + 4) % 7;        /* day 0 a Thursday */

    while(dayno >= (unsigned long)YEARSIZE(year)) {
        dayno -= YEARSIZE(year);
        year++;
    }

    ret->tm_year = year - YEAR0;
    ret->tm_yday = (int)dayno;
    ret->tm_mon  = 0;

    while(dayno >= (unsigned long)_ytab[LEAPYEAR(year)][ret->tm_mon]) {
        dayno -= _ytab[LEAPYEAR(year)][ret->tm_mon];
        ret->tm_mon++;
    }

    ret->tm_mday  = (int)++dayno;
    ret->tm_isdst = 0;

    return ret;
}

#endif /* _WIN32_WCE  || USER_TIME */


#ifdef HAVE_RTP_SYS  

#define YEAR0          1900

struct tm* my_gmtime(const time_t* timer)       /* has a gmtime() but hangs */
{
    static struct tm st_time;
    struct tm* ret = &st_time;

    DC_RTC_CALENDAR cal;
    dc_rtc_time_get(&cal, TRUE);

    ret->tm_year  = cal.year - YEAR0;       /* gm starts at 1900 */
    ret->tm_mon   = cal.month - 1;          /* gm starts at 0 */
    ret->tm_mday  = cal.day;
    ret->tm_hour  = cal.hour;
    ret->tm_min   = cal.minute;
    ret->tm_sec   = cal.second;

    return ret;
}

#endif /* HAVE_RTP_SYS */


#if defined(MICROCHIP_TCPIP_V5) || defined(MICROCHIP_TCPIP)

/*
 * time() is just a stub in Microchip libraries. We need our own
 * implementation. Use SNTP client to get seconds since epoch.
 */
time_t pic32_time(time_t* timer)
{
#ifdef MICROCHIP_TCPIP_V5
    DWORD sec = 0;
#else
    uint32_t sec = 0;
#endif
    time_t localTime;

    if (timer == NULL)
        timer = &localTime;

#ifdef MICROCHIP_MPLAB_HARMONY 
    sec = TCPIP_SNTP_UTCSecondsGet();
#else
    sec = SNTPGetUTCSeconds();
#endif
    *timer = (time_t) sec;

    return *timer;
}

#endif /* MICROCHIP_TCPIP */


#ifdef FREESCALE_MQX

time_t mqx_time(time_t* timer)
{
    time_t localTime;
    TIME_STRUCT time_s;

    if (timer == NULL)
        timer = &localTime;

    _time_get(&time_s);
    *timer = (time_t) time_s.SECONDS;

    return *timer;
}

/* CodeWarrior GCC toolchain only has gmtime_r(), no gmtime() */
struct tm* mqx_gmtime(const time_t* clock)
{
    struct tm tmpTime;

    return gmtime_r(clock, &tmpTime);
}

#endif /* FREESCALE_MQX */

#ifdef CYASSL_TIRTOS

time_t XTIME(time_t * timer)
{
    time_t sec = 0;

    sec = (time_t) MYTIME_gettime();

    if (timer != NULL)
        *timer = sec;

    return sec;
}

#endif /* CYASSL_TIRTOS */

static INLINE word32 btoi(byte b)
{
    return b - 0x30;
}


/* two byte date/time, add to value */
static INLINE void GetTime(int* value, const byte* date, int* idx)
{
    int i = *idx;

    *value += btoi(date[i++]) * 10;
    *value += btoi(date[i++]);

    *idx = i;
}


#if defined(MICRIUM)

CPU_INT32S NetSecure_ValidateDateHandler(CPU_INT08U *date, CPU_INT08U format,
                                         CPU_INT08U dateType)
{
    CPU_BOOLEAN  rtn_code;
    CPU_INT32S   i;
    CPU_INT32S   val;    
    CPU_INT16U   year;
    CPU_INT08U   month;
    CPU_INT16U   day;
    CPU_INT08U   hour;
    CPU_INT08U   min;
    CPU_INT08U   sec;

    i    = 0;
    year = 0u;

    if (format == ASN_UTC_TIME) {
        if (btoi(date[0]) >= 5)
            year = 1900;
        else
            year = 2000;
    }
    else  { /* format == GENERALIZED_TIME */
        year += btoi(date[i++]) * 1000;
        year += btoi(date[i++]) * 100;
    }    

    val = year;
    GetTime(&val, date, &i);
    year = (CPU_INT16U)val;

    val = 0;
    GetTime(&val, date, &i);   
    month = (CPU_INT08U)val;   

    val = 0;
    GetTime(&val, date, &i);  
    day = (CPU_INT16U)val;

    val = 0;
    GetTime(&val, date, &i);  
    hour = (CPU_INT08U)val;

    val = 0;
    GetTime(&val, date, &i);  
    min = (CPU_INT08U)val;

    val = 0;
    GetTime(&val, date, &i);  
    sec = (CPU_INT08U)val;

    return NetSecure_ValidateDate(year, month, day, hour, min, sec, dateType); 
}

#endif /* MICRIUM */


CYASSL_LOCAL int GetLength(const byte* input, word32* inOutIdx, int* len,
                           word32 maxIdx)
{
    int     length = 0;
    word32  i = *inOutIdx;
    byte    b;

    *len = 0;    /* default length */

    if ( (i+1) > maxIdx) {   /* for first read */
        CYASSL_MSG("GetLength bad index on input");
        return BUFFER_E;
    }

    b = input[i++];
    if (b >= ASN_LONG_LENGTH) {        
        word32 bytes = b & 0x7F;

        if ( (i+bytes) > maxIdx) {   /* for reading bytes */
            CYASSL_MSG("GetLength bad long length");
            return BUFFER_E;
        }

        while (bytes--) {
            b = input[i++];
            length = (length << 8) | b;
        }
    }
    else
        length = b;
    
    if ( (i+length) > maxIdx) {   /* for user of length */
        CYASSL_MSG("GetLength value exceeds buffer length");
        return BUFFER_E;
    }

    *inOutIdx = i;
    if (length > 0)
        *len = length;

    return length;
}


CYASSL_LOCAL int GetSequence(const byte* input, word32* inOutIdx, int* len,
                           word32 maxIdx)
{
    int    length = -1;
    word32 idx    = *inOutIdx;

    if (input[idx++] != (ASN_SEQUENCE | ASN_CONSTRUCTED) ||
            GetLength(input, &idx, &length, maxIdx) < 0)
        return ASN_PARSE_E;

    *len      = length;
    *inOutIdx = idx;

    return length;
}


CYASSL_LOCAL int GetSet(const byte* input, word32* inOutIdx, int* len,
                        word32 maxIdx)
{
    int    length = -1;
    word32 idx    = *inOutIdx;

    if (input[idx++] != (ASN_SET | ASN_CONSTRUCTED) ||
            GetLength(input, &idx, &length, maxIdx) < 0)
        return ASN_PARSE_E;

    *len      = length;
    *inOutIdx = idx;

    return length;
}


/* winodws header clash for WinCE using GetVersion */
CYASSL_LOCAL int GetMyVersion(const byte* input, word32* inOutIdx, int* version)
{
    word32 idx = *inOutIdx;

    CYASSL_ENTER("GetMyVersion");

    if (input[idx++] != ASN_INTEGER)
        return ASN_PARSE_E;

    if (input[idx++] != 0x01)
        return ASN_VERSION_E;

    *version  = input[idx++];
    *inOutIdx = idx;

    return *version;
}


#ifndef NO_PWDBASED
/* Get small count integer, 32 bits or less */
static int GetShortInt(const byte* input, word32* inOutIdx, int* number)
{
    word32 idx = *inOutIdx;
    word32 len;

    *number = 0;

    if (input[idx++] != ASN_INTEGER)
        return ASN_PARSE_E;

    len = input[idx++];
    if (len > 4)
        return ASN_PARSE_E;

    while (len--) {
        *number  = *number << 8 | input[idx++];
    }

    *inOutIdx = idx;

    return *number;
}
#endif /* !NO_PWDBASED */


/* May not have one, not an error */
static int GetExplicitVersion(const byte* input, word32* inOutIdx, int* version)
{
    word32 idx = *inOutIdx;

    CYASSL_ENTER("GetExplicitVersion");
    if (input[idx++] == (ASN_CONTEXT_SPECIFIC | ASN_CONSTRUCTED)) {
        *inOutIdx = ++idx;  /* eat header */
        return GetMyVersion(input, inOutIdx, version);
    }

    /* go back as is */
    *version = 0;

    return 0;
}


CYASSL_LOCAL int GetInt(mp_int* mpi, const byte* input, word32* inOutIdx,
                  word32 maxIdx)
{
    word32 i = *inOutIdx;
    byte   b = input[i++];
    int    length;

    if (b != ASN_INTEGER)
        return ASN_PARSE_E;

    if (GetLength(input, &i, &length, maxIdx) < 0)
        return ASN_PARSE_E;

    if ( (b = input[i++]) == 0x00)
        length--;
    else
        i--;

    if (mp_init(mpi) != MP_OKAY)
        return MP_INIT_E;

    if (mp_read_unsigned_bin(mpi, (byte*)input + i, length) != 0) {
        mp_clear(mpi);
        return ASN_GETINT_E;
    }

    *inOutIdx = i + length;
    return 0;
}


static int GetObjectId(const byte* input, word32* inOutIdx, word32* oid,
                     word32 maxIdx)
{
    int    length;
    word32 i = *inOutIdx;
    byte   b;
    *oid = 0;
    
    b = input[i++];
    if (b != ASN_OBJECT_ID) 
        return ASN_OBJECT_ID_E;
    
    if (GetLength(input, &i, &length, maxIdx) < 0)
        return ASN_PARSE_E;
    
    while(length--)
        *oid += input[i++];
    /* just sum it up for now */
    
    *inOutIdx = i;
    
    return 0;
}


CYASSL_LOCAL int GetAlgoId(const byte* input, word32* inOutIdx, word32* oid,
                     word32 maxIdx)
{
    int    length;
    word32 i = *inOutIdx;
    byte   b;
    *oid = 0;
   
    CYASSL_ENTER("GetAlgoId");

    if (GetSequence(input, &i, &length, maxIdx) < 0)
        return ASN_PARSE_E;
    
    b = input[i++];
    if (b != ASN_OBJECT_ID) 
        return ASN_OBJECT_ID_E;
    
    if (GetLength(input, &i, &length, maxIdx) < 0)
        return ASN_PARSE_E;
    
    while(length--) {
        /* odd HC08 compiler behavior here when input[i++] */
        *oid += input[i];
        i++;
    }
    /* just sum it up for now */
    
    /* could have NULL tag and 0 terminator, but may not */
    b = input[i++];
    
    if (b == ASN_TAG_NULL) {
        b = input[i++];
        if (b != 0)
            return ASN_EXPECT_0_E;
    }
    else
    /* go back, didn't have it */
        i--;
    
    *inOutIdx = i;
    
    return 0;
}

#ifndef NO_RSA


#ifdef HAVE_CAVIUM

static int GetCaviumInt(byte** buff, word16* buffSz, const byte* input,
                        word32* inOutIdx, word32 maxIdx, void* heap)
{
    word32 i = *inOutIdx;
    byte   b = input[i++];
    int    length;

    if (b != ASN_INTEGER)
        return ASN_PARSE_E;

    if (GetLength(input, &i, &length, maxIdx) < 0)
        return ASN_PARSE_E;

    if ( (b = input[i++]) == 0x00)
        length--;
    else
        i--;

    *buffSz = (word16)length;
    *buff   = XMALLOC(*buffSz, heap, DYNAMIC_TYPE_CAVIUM_RSA);
    if (*buff == NULL)
        return MEMORY_E;

    XMEMCPY(*buff, input + i, *buffSz);

    *inOutIdx = i + length;
    return 0;
}

static int CaviumRsaPrivateKeyDecode(const byte* input, word32* inOutIdx,
                                     RsaKey* key, word32 inSz)
{
    int   version, length;
    void* h = key->heap;

    if (GetSequence(input, inOutIdx, &length, inSz) < 0)
        return ASN_PARSE_E;

    if (GetMyVersion(input, inOutIdx, &version) < 0)
        return ASN_PARSE_E;

    key->type = RSA_PRIVATE;

    if (GetCaviumInt(&key->c_n,  &key->c_nSz,   input, inOutIdx, inSz, h) < 0 ||
        GetCaviumInt(&key->c_e,  &key->c_eSz,   input, inOutIdx, inSz, h) < 0 ||
        GetCaviumInt(&key->c_d,  &key->c_dSz,   input, inOutIdx, inSz, h) < 0 ||
        GetCaviumInt(&key->c_p,  &key->c_pSz,   input, inOutIdx, inSz, h) < 0 ||
        GetCaviumInt(&key->c_q,  &key->c_qSz,   input, inOutIdx, inSz, h) < 0 ||
        GetCaviumInt(&key->c_dP, &key->c_dP_Sz, input, inOutIdx, inSz, h) < 0 ||
        GetCaviumInt(&key->c_dQ, &key->c_dQ_Sz, input, inOutIdx, inSz, h) < 0 ||
        GetCaviumInt(&key->c_u,  &key->c_uSz,   input, inOutIdx, inSz, h) < 0 )
            return ASN_RSA_KEY_E;

    return 0;
}


#endif /* HAVE_CAVIUM */

int RsaPrivateKeyDecode(const byte* input, word32* inOutIdx, RsaKey* key,
                        word32 inSz)
{
    int    version, length;

#ifdef HAVE_CAVIUM
    if (key->magic == CYASSL_RSA_CAVIUM_MAGIC)
        return CaviumRsaPrivateKeyDecode(input, inOutIdx, key, inSz);
#endif

    if (GetSequence(input, inOutIdx, &length, inSz) < 0)
        return ASN_PARSE_E;

    if (GetMyVersion(input, inOutIdx, &version) < 0)
        return ASN_PARSE_E;

    key->type = RSA_PRIVATE;

    if (GetInt(&key->n,  input, inOutIdx, inSz) < 0 ||
        GetInt(&key->e,  input, inOutIdx, inSz) < 0 ||
        GetInt(&key->d,  input, inOutIdx, inSz) < 0 ||
        GetInt(&key->p,  input, inOutIdx, inSz) < 0 ||
        GetInt(&key->q,  input, inOutIdx, inSz) < 0 ||
        GetInt(&key->dP, input, inOutIdx, inSz) < 0 ||
        GetInt(&key->dQ, input, inOutIdx, inSz) < 0 ||
        GetInt(&key->u,  input, inOutIdx, inSz) < 0 )  return ASN_RSA_KEY_E;

    return 0;
}

#endif /* NO_RSA */

/* Remove PKCS8 header, move beginning of traditional to beginning of input */
int ToTraditional(byte* input, word32 sz)
{
    word32 inOutIdx = 0, oid;
    int    version, length;

    if (GetSequence(input, &inOutIdx, &length, sz) < 0)
        return ASN_PARSE_E;

    if (GetMyVersion(input, &inOutIdx, &version) < 0)
        return ASN_PARSE_E;
    
    if (GetAlgoId(input, &inOutIdx, &oid, sz) < 0)
        return ASN_PARSE_E;

    if (input[inOutIdx] == ASN_OBJECT_ID) {
        /* pkcs8 ecc uses slightly different format */
        inOutIdx++;  /* past id */
        if (GetLength(input, &inOutIdx, &length, sz) < 0)
            return ASN_PARSE_E;
        inOutIdx += length;  /* over sub id, key input will verify */
    }
    
    if (input[inOutIdx++] != ASN_OCTET_STRING)
        return ASN_PARSE_E;
    
    if (GetLength(input, &inOutIdx, &length, sz) < 0)
        return ASN_PARSE_E;
    
    XMEMMOVE(input, input + inOutIdx, length);

    return length;
}


#ifndef NO_PWDBASED

/* Check To see if PKCS version algo is supported, set id if it is return 0
   < 0 on error */
static int CheckAlgo(int first, int second, int* id, int* version)
{
    *id      = ALGO_ID_E;
    *version = PKCS5;   /* default */

    if (first == 1) {
        switch (second) {
        case 1:
            *id = PBE_SHA1_RC4_128;
            *version = PKCS12;
            return 0;
        case 3:
            *id = PBE_SHA1_DES3;
            *version = PKCS12;
            return 0;
        default:
            return ALGO_ID_E;
        }
    }

    if (first != PKCS5)
        return ASN_INPUT_E;  /* VERSION ERROR */

    if (second == PBES2) {
        *version = PKCS5v2;
        return 0;
    }

    switch (second) {
    case 3:                   /* see RFC 2898 for ids */
        *id = PBE_MD5_DES;
        return 0;
    case 10:
        *id = PBE_SHA1_DES;
        return 0;
    default:
        return ALGO_ID_E;

    }
}


/* Check To see if PKCS v2 algo is supported, set id if it is return 0
   < 0 on error */
static int CheckAlgoV2(int oid, int* id)
{
    switch (oid) {
    case 69:
        *id = PBE_SHA1_DES;
        return 0;
    case 652:
        *id = PBE_SHA1_DES3;
        return 0;
    default:
        return ALGO_ID_E;

    }
}


/* Decrypt intput in place from parameters based on id */
static int DecryptKey(const char* password, int passwordSz, byte* salt,
                      int saltSz, int iterations, int id, byte* input,
                      int length, int version, byte* cbcIv)
{
    int typeH;
    int derivedLen;
    int decryptionType;
    int ret = 0;
#ifdef CYASSL_SMALL_STACK
    byte* key;
#else
    byte key[MAX_KEY_SIZE];
#endif

    switch (id) {
        case PBE_MD5_DES:
            typeH = MD5;
            derivedLen = 16;           /* may need iv for v1.5 */
            decryptionType = DES_TYPE;
            break;

        case PBE_SHA1_DES:
            typeH = SHA;
            derivedLen = 16;           /* may need iv for v1.5 */
            decryptionType = DES_TYPE;
            break;

        case PBE_SHA1_DES3:
            typeH = SHA;
            derivedLen = 32;           /* may need iv for v1.5 */
            decryptionType = DES3_TYPE;
            break;

        case PBE_SHA1_RC4_128:
            typeH = SHA;
            derivedLen = 16;
            decryptionType = RC4_TYPE;
            break;

        default:
            return ALGO_ID_E;
    }

#ifdef CYASSL_SMALL_STACK
    key = (byte*)XMALLOC(MAX_KEY_SIZE, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (key == NULL)
        return MEMORY_E;
#endif

    if (version == PKCS5v2)
        ret = PBKDF2(key, (byte*)password, passwordSz, salt, saltSz, iterations,
               derivedLen, typeH);
    else if (version == PKCS5)
        ret = PBKDF1(key, (byte*)password, passwordSz, salt, saltSz, iterations,
               derivedLen, typeH);
    else if (version == PKCS12) {
        int  i, idx = 0;
        byte unicodePasswd[MAX_UNICODE_SZ];

        if ( (passwordSz * 2 + 2) > (int)sizeof(unicodePasswd)) {
#ifdef CYASSL_SMALL_STACK
            XFREE(key, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif
            return UNICODE_SIZE_E; 
        }

        for (i = 0; i < passwordSz; i++) {
            unicodePasswd[idx++] = 0x00;
            unicodePasswd[idx++] = (byte)password[i];
        }
        /* add trailing NULL */
        unicodePasswd[idx++] = 0x00;
        unicodePasswd[idx++] = 0x00;

        ret =  PKCS12_PBKDF(key, unicodePasswd, idx, salt, saltSz,
                            iterations, derivedLen, typeH, 1);
        if (decryptionType != RC4_TYPE)
            ret += PKCS12_PBKDF(cbcIv, unicodePasswd, idx, salt, saltSz,
                                iterations, 8, typeH, 2);
    }
    else {
#ifdef CYASSL_SMALL_STACK
        XFREE(key, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif
        return ALGO_ID_E;
    }

    if (ret != 0) {
#ifdef CYASSL_SMALL_STACK
        XFREE(key, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif
        return ret;
    }

    switch (decryptionType) {
#ifndef NO_DES3
        case DES_TYPE:
        {
            Des    dec;
            byte*  desIv = key + 8;

            if (version == PKCS5v2 || version == PKCS12)
                desIv = cbcIv;

            ret = Des_SetKey(&dec, key, desIv, DES_DECRYPTION);
            if (ret != 0) {
#ifdef CYASSL_SMALL_STACK
                XFREE(key, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif
                return ret;
            }

            Des_CbcDecrypt(&dec, input, input, length);
            break;
        }

        case DES3_TYPE:
        {
            Des3   dec;
            byte*  desIv = key + 24;

            if (version == PKCS5v2 || version == PKCS12)
                desIv = cbcIv;
            ret = Des3_SetKey(&dec, key, desIv, DES_DECRYPTION);
            if (ret != 0) {
#ifdef CYASSL_SMALL_STACK
                XFREE(key, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif
                return ret;
            }
            ret = Des3_CbcDecrypt(&dec, input, input, length);
            if (ret != 0) {
#ifdef CYASSL_SMALL_STACK
                XFREE(key, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif
                return ret;
            }
            break;
        }
#endif
#ifndef NO_RC4
        case RC4_TYPE:
        {
            Arc4    dec;

            Arc4SetKey(&dec, key, derivedLen);
            Arc4Process(&dec, input, input, length);
            break;
        }
#endif

        default:
#ifdef CYASSL_SMALL_STACK
            XFREE(key, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif
            return ALGO_ID_E; 
    }

#ifdef CYASSL_SMALL_STACK
    XFREE(key, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif

    return 0;
}


/* Remove Encrypted PKCS8 header, move beginning of traditional to beginning
   of input */
int ToTraditionalEnc(byte* input, word32 sz,const char* password,int passwordSz)
{
    word32 inOutIdx = 0, oid;
    int    first, second, length, version, saltSz, id;
    int    iterations = 0;
#ifdef CYASSL_SMALL_STACK
    byte*  salt = NULL;
    byte*  cbcIv = NULL;
#else
    byte   salt[MAX_SALT_SIZE];
    byte   cbcIv[MAX_IV_SIZE];
#endif
    
    if (GetSequence(input, &inOutIdx, &length, sz) < 0)
        return ASN_PARSE_E;

    if (GetAlgoId(input, &inOutIdx, &oid, sz) < 0)
        return ASN_PARSE_E;
    
    first  = input[inOutIdx - 2];   /* PKCS version alwyas 2nd to last byte */
    second = input[inOutIdx - 1];   /* version.algo, algo id last byte */

    if (CheckAlgo(first, second, &id, &version) < 0)
        return ASN_INPUT_E;  /* Algo ID error */

    if (version == PKCS5v2) {

        if (GetSequence(input, &inOutIdx, &length, sz) < 0)
            return ASN_PARSE_E;

        if (GetAlgoId(input, &inOutIdx, &oid, sz) < 0)
            return ASN_PARSE_E;

        if (oid != PBKDF2_OID)
            return ASN_PARSE_E;
    }

    if (GetSequence(input, &inOutIdx, &length, sz) < 0)
        return ASN_PARSE_E;

    if (input[inOutIdx++] != ASN_OCTET_STRING)
        return ASN_PARSE_E;
    
    if (GetLength(input, &inOutIdx, &saltSz, sz) < 0)
        return ASN_PARSE_E;

    if (saltSz > MAX_SALT_SIZE)
        return ASN_PARSE_E;
     
#ifdef CYASSL_SMALL_STACK
    salt = (byte*)XMALLOC(MAX_SALT_SIZE, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (salt == NULL)
        return MEMORY_E;
#endif

    XMEMCPY(salt, &input[inOutIdx], saltSz);
    inOutIdx += saltSz;

    if (GetShortInt(input, &inOutIdx, &iterations) < 0) {
#ifdef CYASSL_SMALL_STACK
        XFREE(salt,  NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif
        return ASN_PARSE_E;
    }

#ifdef CYASSL_SMALL_STACK
    cbcIv = (byte*)XMALLOC(MAX_IV_SIZE, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (cbcIv == NULL) {
        XFREE(salt,  NULL, DYNAMIC_TYPE_TMP_BUFFER);
        return MEMORY_E;
    }
#endif

    if (version == PKCS5v2) {
        /* get encryption algo */
        if (GetAlgoId(input, &inOutIdx, &oid, sz) < 0) {
#ifdef CYASSL_SMALL_STACK
            XFREE(salt,  NULL, DYNAMIC_TYPE_TMP_BUFFER);
            XFREE(cbcIv, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif
            return ASN_PARSE_E;
        }

        if (CheckAlgoV2(oid, &id) < 0) {
#ifdef CYASSL_SMALL_STACK
            XFREE(salt,  NULL, DYNAMIC_TYPE_TMP_BUFFER);
            XFREE(cbcIv, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif
            return ASN_PARSE_E;  /* PKCS v2 algo id error */
        }

        if (input[inOutIdx++] != ASN_OCTET_STRING) {
#ifdef CYASSL_SMALL_STACK
            XFREE(salt,  NULL, DYNAMIC_TYPE_TMP_BUFFER);
            XFREE(cbcIv, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif
            return ASN_PARSE_E;
        }
    
        if (GetLength(input, &inOutIdx, &length, sz) < 0) {
#ifdef CYASSL_SMALL_STACK
            XFREE(salt,  NULL, DYNAMIC_TYPE_TMP_BUFFER);
            XFREE(cbcIv, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif
            return ASN_PARSE_E;
        }

        XMEMCPY(cbcIv, &input[inOutIdx], length);
        inOutIdx += length;
    }

    if (input[inOutIdx++] != ASN_OCTET_STRING) {
#ifdef CYASSL_SMALL_STACK
        XFREE(salt,  NULL, DYNAMIC_TYPE_TMP_BUFFER);
        XFREE(cbcIv, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif
        return ASN_PARSE_E;
    }

    if (GetLength(input, &inOutIdx, &length, sz) < 0) {
#ifdef CYASSL_SMALL_STACK
        XFREE(salt,  NULL, DYNAMIC_TYPE_TMP_BUFFER);
        XFREE(cbcIv, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif
        return ASN_PARSE_E;
    }

    if (DecryptKey(password, passwordSz, salt, saltSz, iterations, id,
                   input + inOutIdx, length, version, cbcIv) < 0) {
#ifdef CYASSL_SMALL_STACK
        XFREE(salt,  NULL, DYNAMIC_TYPE_TMP_BUFFER);
        XFREE(cbcIv, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif
        return ASN_INPUT_E;  /* decrypt failure */
    }

#ifdef CYASSL_SMALL_STACK
    XFREE(salt,  NULL, DYNAMIC_TYPE_TMP_BUFFER);
    XFREE(cbcIv, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif

    XMEMMOVE(input, input + inOutIdx, length);
    return ToTraditional(input, length);
}

#endif /* NO_PWDBASED */

#ifndef NO_RSA

int RsaPublicKeyDecode(const byte* input, word32* inOutIdx, RsaKey* key,
                       word32 inSz)
{
    int    length;

    if (GetSequence(input, inOutIdx, &length, inSz) < 0)
        return ASN_PARSE_E;

    key->type = RSA_PUBLIC;

#if defined(OPENSSL_EXTRA) || defined(RSA_DECODE_EXTRA)
    {
    byte b = input[*inOutIdx];
    if (b != ASN_INTEGER) {
        /* not from decoded cert, will have algo id, skip past */
        if (GetSequence(input, inOutIdx, &length, inSz) < 0)
            return ASN_PARSE_E;
        
        b = input[(*inOutIdx)++];
        if (b != ASN_OBJECT_ID) 
            return ASN_OBJECT_ID_E;
        
        if (GetLength(input, inOutIdx, &length, inSz) < 0)
            return ASN_PARSE_E;
        
        *inOutIdx += length;   /* skip past */
        
        /* could have NULL tag and 0 terminator, but may not */
        b = input[(*inOutIdx)++];
        
        if (b == ASN_TAG_NULL) {
            b = input[(*inOutIdx)++];
            if (b != 0) 
                return ASN_EXPECT_0_E;
        }
        else
        /* go back, didn't have it */
            (*inOutIdx)--;
        
        /* should have bit tag length and seq next */
        b = input[(*inOutIdx)++];
        if (b != ASN_BIT_STRING)
            return ASN_BITSTR_E;
        
        if (GetLength(input, inOutIdx, &length, inSz) < 0)
            return ASN_PARSE_E;
        
        /* could have 0 */
        b = input[(*inOutIdx)++];
        if (b != 0)
            (*inOutIdx)--;
        
        if (GetSequence(input, inOutIdx, &length, inSz) < 0)
            return ASN_PARSE_E;
    }  /* end if */
    }  /* openssl var block */
#endif /* OPENSSL_EXTRA */

    if (GetInt(&key->n,  input, inOutIdx, inSz) < 0 ||
        GetInt(&key->e,  input, inOutIdx, inSz) < 0 )  return ASN_RSA_KEY_E;

    return 0;
}

int RsaPublicKeyDecodeRaw(const byte* n, word32 nSz, const byte* e, word32 eSz,
                          RsaKey* key)
{
    if (n == NULL || e == NULL || key == NULL)
        return BAD_FUNC_ARG;

    key->type = RSA_PUBLIC;

    if (mp_init(&key->n) != MP_OKAY)
        return MP_INIT_E;

    if (mp_read_unsigned_bin(&key->n, n, nSz) != 0) {
        mp_clear(&key->n);
        return ASN_GETINT_E;
    }

    if (mp_init(&key->e) != MP_OKAY) {
        mp_clear(&key->n);
        return MP_INIT_E;
    }

    if (mp_read_unsigned_bin(&key->e, e, eSz) != 0) {
        mp_clear(&key->n);
        mp_clear(&key->e);
        return ASN_GETINT_E;
    }

    return 0;
}

#endif

#ifndef NO_DH

int DhKeyDecode(const byte* input, word32* inOutIdx, DhKey* key, word32 inSz)
{
    int    length;

    if (GetSequence(input, inOutIdx, &length, inSz) < 0)
        return ASN_PARSE_E;

    if (GetInt(&key->p,  input, inOutIdx, inSz) < 0 ||
        GetInt(&key->g,  input, inOutIdx, inSz) < 0 )  return ASN_DH_KEY_E;

    return 0;
}

int DhSetKey(DhKey* key, const byte* p, word32 pSz, const byte* g, word32 gSz)
{
    if (key == NULL || p == NULL || g == NULL || pSz == 0 || gSz == 0)
        return BAD_FUNC_ARG;

    /* may have leading 0 */
    if (p[0] == 0) {
        pSz--; p++;
    }

    if (g[0] == 0) {
        gSz--; g++;
    }

    if (mp_init(&key->p) != MP_OKAY)
        return MP_INIT_E;
    if (mp_read_unsigned_bin(&key->p, p, pSz) != 0) {
        mp_clear(&key->p);
        return ASN_DH_KEY_E;
    }

    if (mp_init(&key->g) != MP_OKAY) {
        mp_clear(&key->p);
        return MP_INIT_E;
    }
    if (mp_read_unsigned_bin(&key->g, g, gSz) != 0) {
        mp_clear(&key->g);
        mp_clear(&key->p);
        return ASN_DH_KEY_E;
    }

    return 0;
}


int DhParamsLoad(const byte* input, word32 inSz, byte* p, word32* pInOutSz,
                 byte* g, word32* gInOutSz)
{
    word32 i = 0;
    byte   b;
    int    length;

    if (GetSequence(input, &i, &length, inSz) < 0)
        return ASN_PARSE_E;

    b = input[i++];
    if (b != ASN_INTEGER)
        return ASN_PARSE_E;

    if (GetLength(input, &i, &length, inSz) < 0)
        return ASN_PARSE_E;

    if ( (b = input[i++]) == 0x00)
        length--;
    else
        i--;

    if (length <= (int)*pInOutSz) {
        XMEMCPY(p, &input[i], length);
        *pInOutSz = length;
    }
    else
        return BUFFER_E;

    i += length;

    b = input[i++];
    if (b != ASN_INTEGER)
        return ASN_PARSE_E;

    if (GetLength(input, &i, &length, inSz) < 0)
        return ASN_PARSE_E;

    if (length <= (int)*gInOutSz) {
        XMEMCPY(g, &input[i], length);
        *gInOutSz = length;
    }
    else
        return BUFFER_E;

    return 0;
}

#endif /* NO_DH */


#ifndef NO_DSA

int DsaPublicKeyDecode(const byte* input, word32* inOutIdx, DsaKey* key,
                        word32 inSz)
{
    int    length;

    if (GetSequence(input, inOutIdx, &length, inSz) < 0)
        return ASN_PARSE_E;

    if (GetInt(&key->p,  input, inOutIdx, inSz) < 0 ||
        GetInt(&key->q,  input, inOutIdx, inSz) < 0 ||
        GetInt(&key->g,  input, inOutIdx, inSz) < 0 ||
        GetInt(&key->y,  input, inOutIdx, inSz) < 0 )  return ASN_DH_KEY_E;

    key->type = DSA_PUBLIC;
    return 0;
}


int DsaPrivateKeyDecode(const byte* input, word32* inOutIdx, DsaKey* key,
                        word32 inSz)
{
    int    length, version;

    if (GetSequence(input, inOutIdx, &length, inSz) < 0)
        return ASN_PARSE_E;

    if (GetMyVersion(input, inOutIdx, &version) < 0)
        return ASN_PARSE_E;

    if (GetInt(&key->p,  input, inOutIdx, inSz) < 0 ||
        GetInt(&key->q,  input, inOutIdx, inSz) < 0 ||
        GetInt(&key->g,  input, inOutIdx, inSz) < 0 ||
        GetInt(&key->y,  input, inOutIdx, inSz) < 0 ||
        GetInt(&key->x,  input, inOutIdx, inSz) < 0 )  return ASN_DH_KEY_E;

    key->type = DSA_PRIVATE;
    return 0;
}

#endif /* NO_DSA */


void InitDecodedCert(DecodedCert* cert, byte* source, word32 inSz, void* heap)
{
    cert->publicKey       = 0;
    cert->pubKeySize      = 0;
    cert->pubKeyStored    = 0;
    cert->version         = 0;
    cert->signature       = 0;
    cert->subjectCN       = 0;
    cert->subjectCNLen    = 0;
    cert->subjectCNEnc    = CTC_UTF8;
    cert->subjectCNStored = 0;
    cert->altNames        = NULL;
#ifndef IGNORE_NAME_CONSTRAINTS
    cert->altEmailNames   = NULL;
    cert->permittedNames  = NULL;
    cert->excludedNames   = NULL;
#endif /* IGNORE_NAME_CONSTRAINTS */
    cert->issuer[0]       = '\0';
    cert->subject[0]      = '\0';
    cert->source          = source;  /* don't own */
    cert->srcIdx          = 0;
    cert->maxIdx          = inSz;    /* can't go over this index */
    cert->heap            = heap;
    XMEMSET(cert->serial, 0, EXTERNAL_SERIAL_SIZE);
    cert->serialSz        = 0;
    cert->extensions      = 0;
    cert->extensionsSz    = 0;
    cert->extensionsIdx   = 0;
    cert->extAuthInfo     = NULL;
    cert->extAuthInfoSz   = 0;
    cert->extCrlInfo      = NULL;
    cert->extCrlInfoSz    = 0;
    XMEMSET(cert->extSubjKeyId, 0, SHA_SIZE);
    cert->extSubjKeyIdSet = 0;
    XMEMSET(cert->extAuthKeyId, 0, SHA_SIZE);
    cert->extAuthKeyIdSet = 0;
    cert->extKeyUsageSet  = 0;
    cert->extKeyUsage     = 0;
    cert->extExtKeyUsageSet = 0;
    cert->extExtKeyUsage    = 0;
    cert->isCA            = 0;
#ifdef HAVE_PKCS7
    cert->issuerRaw       = NULL;
    cert->issuerRawLen    = 0;
#endif
#ifdef CYASSL_CERT_GEN
    cert->subjectSN       = 0;
    cert->subjectSNLen    = 0;
    cert->subjectSNEnc    = CTC_UTF8;
    cert->subjectC        = 0;
    cert->subjectCLen     = 0;
    cert->subjectCEnc     = CTC_PRINTABLE;
    cert->subjectL        = 0;
    cert->subjectLLen     = 0;
    cert->subjectLEnc     = CTC_UTF8;
    cert->subjectST       = 0;
    cert->subjectSTLen    = 0;
    cert->subjectSTEnc    = CTC_UTF8;
    cert->subjectO        = 0;
    cert->subjectOLen     = 0;
    cert->subjectOEnc     = CTC_UTF8;
    cert->subjectOU       = 0;
    cert->subjectOULen    = 0;
    cert->subjectOUEnc    = CTC_UTF8;
    cert->subjectEmail    = 0;
    cert->subjectEmailLen = 0;
#endif /* CYASSL_CERT_GEN */
    cert->beforeDate      = NULL;
    cert->beforeDateLen   = 0;
    cert->afterDate       = NULL;
    cert->afterDateLen    = 0;
#ifdef OPENSSL_EXTRA
    XMEMSET(&cert->issuerName, 0, sizeof(DecodedName));
    XMEMSET(&cert->subjectName, 0, sizeof(DecodedName));
    cert->extBasicConstSet = 0;
    cert->extBasicConstCrit = 0;
    cert->extBasicConstPlSet = 0;
    cert->pathLength = 0;
    cert->extSubjAltNameSet = 0;
    cert->extSubjAltNameCrit = 0;
    cert->extAuthKeyIdCrit = 0;
    cert->extSubjKeyIdCrit = 0;
    cert->extKeyUsageCrit = 0;
    cert->extExtKeyUsageCrit = 0;
    cert->extExtKeyUsageSrc = NULL;
    cert->extExtKeyUsageSz = 0;
    cert->extExtKeyUsageCount = 0;
    cert->extAuthKeyIdSrc = NULL;
    cert->extAuthKeyIdSz = 0;
    cert->extSubjKeyIdSrc = NULL;
    cert->extSubjKeyIdSz = 0;
#endif /* OPENSSL_EXTRA */
#if defined(OPENSSL_EXTRA) || !defined(IGNORE_NAME_CONSTRAINTS)
    cert->extNameConstraintSet = 0;
#endif /* OPENSSL_EXTRA || !IGNORE_NAME_CONSTRAINTS */
#ifdef HAVE_ECC
    cert->pkCurveOID = 0;
#endif /* HAVE_ECC */
#ifdef CYASSL_SEP
    cert->deviceTypeSz = 0;
    cert->deviceType = NULL;
    cert->hwTypeSz = 0;
    cert->hwType = NULL;
    cert->hwSerialNumSz = 0;
    cert->hwSerialNum = NULL;
    #ifdef OPENSSL_EXTRA
        cert->extCertPolicySet = 0;
        cert->extCertPolicyCrit = 0;
    #endif /* OPENSSL_EXTRA */
#endif /* CYASSL_SEP */
}


void FreeAltNames(DNS_entry* altNames, void* heap)
{
    (void)heap;

    while (altNames) {
        DNS_entry* tmp = altNames->next;

        XFREE(altNames->name, heap, DYNAMIC_TYPE_ALTNAME);
        XFREE(altNames,       heap, DYNAMIC_TYPE_ALTNAME);
        altNames = tmp;
    }
}

#ifndef IGNORE_NAME_CONSTRAINTS

void FreeNameSubtrees(Base_entry* names, void* heap)
{
    (void)heap;

    while (names) {
        Base_entry* tmp = names->next;

        XFREE(names->name, heap, DYNAMIC_TYPE_ALTNAME);
        XFREE(names,       heap, DYNAMIC_TYPE_ALTNAME);
        names = tmp;
    }
}

#endif /* IGNORE_NAME_CONSTRAINTS */

void FreeDecodedCert(DecodedCert* cert)
{
    if (cert->subjectCNStored == 1)
        XFREE(cert->subjectCN, cert->heap, DYNAMIC_TYPE_SUBJECT_CN);
    if (cert->pubKeyStored == 1)
        XFREE(cert->publicKey, cert->heap, DYNAMIC_TYPE_PUBLIC_KEY);
    if (cert->altNames)
        FreeAltNames(cert->altNames, cert->heap);
#ifndef IGNORE_NAME_CONSTRAINTS
    if (cert->altEmailNames)
        FreeAltNames(cert->altEmailNames, cert->heap);
    if (cert->permittedNames)
        FreeNameSubtrees(cert->permittedNames, cert->heap);
    if (cert->excludedNames)
        FreeNameSubtrees(cert->excludedNames, cert->heap);
#endif /* IGNORE_NAME_CONSTRAINTS */
#ifdef CYASSL_SEP
    XFREE(cert->deviceType, cert->heap, 0);
    XFREE(cert->hwType, cert->heap, 0);
    XFREE(cert->hwSerialNum, cert->heap, 0);
#endif /* CYASSL_SEP */
#ifdef OPENSSL_EXTRA
    if (cert->issuerName.fullName != NULL)
        XFREE(cert->issuerName.fullName, NULL, DYNAMIC_TYPE_X509);
    if (cert->subjectName.fullName != NULL)
        XFREE(cert->subjectName.fullName, NULL, DYNAMIC_TYPE_X509);
#endif /* OPENSSL_EXTRA */
}


static int GetCertHeader(DecodedCert* cert)
{
    int ret = 0, len;
    byte serialTmp[EXTERNAL_SERIAL_SIZE];
#if defined(CYASSL_SMALL_STACK) && defined(USE_FAST_MATH)
    mp_int* mpi = NULL;
#else
    mp_int stack_mpi;
    mp_int* mpi = &stack_mpi;
#endif

    if (GetSequence(cert->source, &cert->srcIdx, &len, cert->maxIdx) < 0)
        return ASN_PARSE_E;

    cert->certBegin = cert->srcIdx;

    if (GetSequence(cert->source, &cert->srcIdx, &len, cert->maxIdx) < 0)
        return ASN_PARSE_E;
    cert->sigIndex = len + cert->srcIdx;

    if (GetExplicitVersion(cert->source, &cert->srcIdx, &cert->version) < 0)
        return ASN_PARSE_E;

#if defined(CYASSL_SMALL_STACK) && defined(USE_FAST_MATH)
    mpi = (mp_int*)XMALLOC(sizeof(mp_int), NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (mpi == NULL)
        return MEMORY_E;
#endif

    if (GetInt(mpi, cert->source, &cert->srcIdx, cert->maxIdx) < 0) {
#if defined(CYASSL_SMALL_STACK) && defined(USE_FAST_MATH)
        XFREE(mpi, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif
        return ASN_PARSE_E;
    }

    len = mp_unsigned_bin_size(mpi);
    if (len < (int)sizeof(serialTmp)) {
        if ( (ret = mp_to_unsigned_bin(mpi, serialTmp)) == MP_OKAY) {
            XMEMCPY(cert->serial, serialTmp, len);
            cert->serialSz = len;
        }
    }
    mp_clear(mpi);

#if defined(CYASSL_SMALL_STACK) && defined(USE_FAST_MATH)
    XFREE(mpi, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif

    return ret;
}

#if !defined(NO_RSA)
/* Store Rsa Key, may save later, Dsa could use in future */
static int StoreRsaKey(DecodedCert* cert)
{
    int    length;
    word32 recvd = cert->srcIdx;

    if (GetSequence(cert->source, &cert->srcIdx, &length, cert->maxIdx) < 0)
        return ASN_PARSE_E;
   
    recvd = cert->srcIdx - recvd;
    length += recvd;

    while (recvd--)
       cert->srcIdx--;

    cert->pubKeySize = length;
    cert->publicKey = cert->source + cert->srcIdx;
    cert->srcIdx += length;

    return 0;
}
#endif


#ifdef HAVE_ECC

    /* return 0 on sucess if the ECC curve oid sum is supported */
    static int CheckCurve(word32 oid)
    {
        if (oid != ECC_256R1 && oid != ECC_384R1 && oid != ECC_521R1 && oid !=
                   ECC_160R1 && oid != ECC_192R1 && oid != ECC_224R1)
            return ALGO_ID_E; 

        return 0;
    }

#endif /* HAVE_ECC */


static int GetKey(DecodedCert* cert)
{
    int length;
#ifdef HAVE_NTRU
    int tmpIdx = cert->srcIdx;
#endif

    if (GetSequence(cert->source, &cert->srcIdx, &length, cert->maxIdx) < 0)
        return ASN_PARSE_E;
   
    if (GetAlgoId(cert->source, &cert->srcIdx, &cert->keyOID, cert->maxIdx) < 0)
        return ASN_PARSE_E;

    switch (cert->keyOID) {
   #ifndef NO_RSA
        case RSAk:
        {
            byte b = cert->source[cert->srcIdx++];
            if (b != ASN_BIT_STRING)
                return ASN_BITSTR_E;

            if (GetLength(cert->source,&cert->srcIdx,&length,cert->maxIdx) < 0)
                return ASN_PARSE_E;
            b = cert->source[cert->srcIdx++];
            if (b != 0x00)
                return ASN_EXPECT_0_E;
    
            return StoreRsaKey(cert);
        }

    #endif /* NO_RSA */
    #ifdef HAVE_NTRU
        case NTRUk:
        {
            const byte* key = &cert->source[tmpIdx];
            byte*       next = (byte*)key;
            word16      keyLen;
            word32      rc;
            word32      remaining = cert->maxIdx - cert->srcIdx;
#ifdef CYASSL_SMALL_STACK
            byte*       keyBlob = NULL;
#else
            byte        keyBlob[MAX_NTRU_KEY_SZ];
#endif
            rc = ntru_crypto_ntru_encrypt_subjectPublicKeyInfo2PublicKey(key,
                                &keyLen, NULL, &next, &remaining);
            if (rc != NTRU_OK)
                return ASN_NTRU_KEY_E;
            if (keyLen > MAX_NTRU_KEY_SZ)
                return ASN_NTRU_KEY_E;

#ifdef CYASSL_SMALL_STACK
            keyBlob = (byte*)XMALLOC(MAX_NTRU_KEY_SZ, NULL,
                                                       DYNAMIC_TYPE_TMP_BUFFER);
            if (keyBlob == NULL)
                return MEMORY_E;
#endif

            rc = ntru_crypto_ntru_encrypt_subjectPublicKeyInfo2PublicKey(key,
                                &keyLen, keyBlob, &next, &remaining);
            if (rc != NTRU_OK) {
#ifdef CYASSL_SMALL_STACK
                XFREE(keyBlob, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif
                return ASN_NTRU_KEY_E;
            }

            if ( (next - key) < 0) {
#ifdef CYASSL_SMALL_STACK
                XFREE(keyBlob, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif
                return ASN_NTRU_KEY_E;
            }

            cert->srcIdx = tmpIdx + (int)(next - key);

            cert->publicKey = (byte*) XMALLOC(keyLen, cert->heap,
                                              DYNAMIC_TYPE_PUBLIC_KEY);
            if (cert->publicKey == NULL) {
#ifdef CYASSL_SMALL_STACK
                XFREE(keyBlob, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif
                return MEMORY_E;
            }
            XMEMCPY(cert->publicKey, keyBlob, keyLen);
            cert->pubKeyStored = 1;
            cert->pubKeySize   = keyLen;

#ifdef CYASSL_SMALL_STACK
            XFREE(keyBlob, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif

            return 0;
        }
    #endif /* HAVE_NTRU */
    #ifdef HAVE_ECC
        case ECDSAk:
        {
            int    oidSz = 0;
            byte   b = cert->source[cert->srcIdx++];
        
            if (b != ASN_OBJECT_ID) 
                return ASN_OBJECT_ID_E;

            if (GetLength(cert->source,&cert->srcIdx,&oidSz,cert->maxIdx) < 0)
                return ASN_PARSE_E;

            while(oidSz--)
                cert->pkCurveOID += cert->source[cert->srcIdx++];

            if (CheckCurve(cert->pkCurveOID) < 0)
                return ECC_CURVE_OID_E;

            /* key header */
            b = cert->source[cert->srcIdx++];
            if (b != ASN_BIT_STRING)
                return ASN_BITSTR_E;

            if (GetLength(cert->source,&cert->srcIdx,&length,cert->maxIdx) < 0)
                return ASN_PARSE_E;
            b = cert->source[cert->srcIdx++];
            if (b != 0x00)
                return ASN_EXPECT_0_E;

            /* actual key, use length - 1 since ate preceding 0 */
            length -= 1;

            cert->publicKey = (byte*) XMALLOC(length, cert->heap,
                                              DYNAMIC_TYPE_PUBLIC_KEY);
            if (cert->publicKey == NULL)
                return MEMORY_E;
            XMEMCPY(cert->publicKey, &cert->source[cert->srcIdx], length);
            cert->pubKeyStored = 1;
            cert->pubKeySize   = length;

            cert->srcIdx += length;

            return 0;
        }
    #endif /* HAVE_ECC */
        default:
            return ASN_UNKNOWN_OID_E;
    }
}


/* process NAME, either issuer or subject */
static int GetName(DecodedCert* cert, int nameType)
{
    Sha    sha;     /* MUST have SHA-1 hash for cert names */
    int    length;  /* length of all distinguished names */
    int    dummy;
    int    ret;
    char* full = (nameType == ISSUER) ? cert->issuer : cert->subject;
    word32 idx;
    #ifdef OPENSSL_EXTRA
        DecodedName* dName =
                  (nameType == ISSUER) ? &cert->issuerName : &cert->subjectName;
    #endif /* OPENSSL_EXTRA */

    CYASSL_MSG("Getting Cert Name");

    if (cert->source[cert->srcIdx] == ASN_OBJECT_ID) {
        CYASSL_MSG("Trying optional prefix...");

        if (GetLength(cert->source, &cert->srcIdx, &length, cert->maxIdx) < 0)
            return ASN_PARSE_E;

        cert->srcIdx += length;
        CYASSL_MSG("Got optional prefix");
    }

    /* For OCSP, RFC2560 section 4.1.1 states the issuer hash should be
     * calculated over the entire DER encoding of the Name field, including
     * the tag and length. */
    idx = cert->srcIdx;
    if (GetSequence(cert->source, &cert->srcIdx, &length, cert->maxIdx) < 0)
        return ASN_PARSE_E;

    ret = InitSha(&sha);
    if (ret != 0)
        return ret;
    ShaUpdate(&sha, &cert->source[idx], length + cert->srcIdx - idx);
    if (nameType == ISSUER)
        ShaFinal(&sha, cert->issuerHash);
    else
        ShaFinal(&sha, cert->subjectHash);

    length += cert->srcIdx;
    idx = 0;

#ifdef HAVE_PKCS7
    /* store pointer to raw issuer */
    if (nameType == ISSUER) {
        cert->issuerRaw = &cert->source[cert->srcIdx];
        cert->issuerRawLen = length - cert->srcIdx;
    }
#endif
#ifndef IGNORE_NAME_CONSTRAINTS
    if (nameType == SUBJECT) {
        cert->subjectRaw = &cert->source[cert->srcIdx];
        cert->subjectRawLen = length - cert->srcIdx;
    }
#endif

    while (cert->srcIdx < (word32)length) {
        byte   b;
        byte   joint[2];
        byte   tooBig = FALSE;
        int    oidSz;

        if (GetSet(cert->source, &cert->srcIdx, &dummy, cert->maxIdx) < 0) {
            CYASSL_MSG("Cert name lacks set header, trying sequence");
        }

        if (GetSequence(cert->source, &cert->srcIdx, &dummy, cert->maxIdx) < 0)
            return ASN_PARSE_E;

        b = cert->source[cert->srcIdx++];
        if (b != ASN_OBJECT_ID) 
            return ASN_OBJECT_ID_E;

        if (GetLength(cert->source, &cert->srcIdx, &oidSz, cert->maxIdx) < 0)
            return ASN_PARSE_E;

        XMEMCPY(joint, &cert->source[cert->srcIdx], sizeof(joint));

        /* v1 name types */
        if (joint[0] == 0x55 && joint[1] == 0x04) {
            byte   id;
            byte   copy = FALSE;
            int    strLen;

            cert->srcIdx += 2;
            id = cert->source[cert->srcIdx++]; 
            b  = cert->source[cert->srcIdx++]; /* encoding */

            if (GetLength(cert->source, &cert->srcIdx, &strLen,
                          cert->maxIdx) < 0)
                return ASN_PARSE_E;

            if ( (strLen + 14) > (int)(ASN_NAME_MAX - idx)) {
                /* include biggest pre fix header too 4 = "/serialNumber=" */
                CYASSL_MSG("ASN Name too big, skipping");
                tooBig = TRUE;
            }

            if (id == ASN_COMMON_NAME) {
                if (nameType == SUBJECT) {
                    cert->subjectCN = (char *)&cert->source[cert->srcIdx];
                    cert->subjectCNLen = strLen;
                    cert->subjectCNEnc = b;
                }

                if (!tooBig) {
                    XMEMCPY(&full[idx], "/CN=", 4);
                    idx += 4;
                    copy = TRUE;
                }
                #ifdef OPENSSL_EXTRA
                    dName->cnIdx = cert->srcIdx;
                    dName->cnLen = strLen;
                #endif /* OPENSSL_EXTRA */
            }
            else if (id == ASN_SUR_NAME) {
                if (!tooBig) {
                    XMEMCPY(&full[idx], "/SN=", 4);
                    idx += 4;
                    copy = TRUE;
                }
                #ifdef CYASSL_CERT_GEN
                    if (nameType == SUBJECT) {
                        cert->subjectSN = (char*)&cert->source[cert->srcIdx];
                        cert->subjectSNLen = strLen;
                        cert->subjectSNEnc = b;
                    }
                #endif /* CYASSL_CERT_GEN */
                #ifdef OPENSSL_EXTRA
                    dName->snIdx = cert->srcIdx;
                    dName->snLen = strLen;
                #endif /* OPENSSL_EXTRA */
            }
            else if (id == ASN_COUNTRY_NAME) {
                if (!tooBig) {
                    XMEMCPY(&full[idx], "/C=", 3);
                    idx += 3;
                    copy = TRUE;
                }
                #ifdef CYASSL_CERT_GEN
                    if (nameType == SUBJECT) {
                        cert->subjectC = (char*)&cert->source[cert->srcIdx];
                        cert->subjectCLen = strLen;
                        cert->subjectCEnc = b;
                    }
                #endif /* CYASSL_CERT_GEN */
                #ifdef OPENSSL_EXTRA
                    dName->cIdx = cert->srcIdx;
                    dName->cLen = strLen;
                #endif /* OPENSSL_EXTRA */
            }
            else if (id == ASN_LOCALITY_NAME) {
                if (!tooBig) {
                    XMEMCPY(&full[idx], "/L=", 3);
                    idx += 3;
                    copy = TRUE;
                }
                #ifdef CYASSL_CERT_GEN
                    if (nameType == SUBJECT) {
                        cert->subjectL = (char*)&cert->source[cert->srcIdx];
                        cert->subjectLLen = strLen;
                        cert->subjectLEnc = b;
                    }
                #endif /* CYASSL_CERT_GEN */
                #ifdef OPENSSL_EXTRA
                    dName->lIdx = cert->srcIdx;
                    dName->lLen = strLen;
                #endif /* OPENSSL_EXTRA */
            }
            else if (id == ASN_STATE_NAME) {
                if (!tooBig) {
                    XMEMCPY(&full[idx], "/ST=", 4);
                    idx += 4;
                    copy = TRUE;
                }
                #ifdef CYASSL_CERT_GEN
                    if (nameType == SUBJECT) {
                        cert->subjectST = (char*)&cert->source[cert->srcIdx];
                        cert->subjectSTLen = strLen;
                        cert->subjectSTEnc = b;
                    }
                #endif /* CYASSL_CERT_GEN */
                #ifdef OPENSSL_EXTRA
                    dName->stIdx = cert->srcIdx;
                    dName->stLen = strLen;
                #endif /* OPENSSL_EXTRA */
            }
            else if (id == ASN_ORG_NAME) {
                if (!tooBig) {
                    XMEMCPY(&full[idx], "/O=", 3);
                    idx += 3;
                    copy = TRUE;
                }
                #ifdef CYASSL_CERT_GEN
                    if (nameType == SUBJECT) {
                        cert->subjectO = (char*)&cert->source[cert->srcIdx];
                        cert->subjectOLen = strLen;
                        cert->subjectOEnc = b;
                    }
                #endif /* CYASSL_CERT_GEN */
                #ifdef OPENSSL_EXTRA
                    dName->oIdx = cert->srcIdx;
                    dName->oLen = strLen;
                #endif /* OPENSSL_EXTRA */
            }
            else if (id == ASN_ORGUNIT_NAME) {
                if (!tooBig) {
                    XMEMCPY(&full[idx], "/OU=", 4);
                    idx += 4;
                    copy = TRUE;
                }
                #ifdef CYASSL_CERT_GEN
                    if (nameType == SUBJECT) {
                        cert->subjectOU = (char*)&cert->source[cert->srcIdx];
                        cert->subjectOULen = strLen;
                        cert->subjectOUEnc = b;
                    }
                #endif /* CYASSL_CERT_GEN */
                #ifdef OPENSSL_EXTRA
                    dName->ouIdx = cert->srcIdx;
                    dName->ouLen = strLen;
                #endif /* OPENSSL_EXTRA */
            }
            else if (id == ASN_SERIAL_NUMBER) {
                if (!tooBig) {
                   XMEMCPY(&full[idx], "/serialNumber=", 14);
                   idx += 14;
                   copy = TRUE;
                }
                #ifdef OPENSSL_EXTRA
                    dName->snIdx = cert->srcIdx;
                    dName->snLen = strLen;
                #endif /* OPENSSL_EXTRA */
            }

            if (copy && !tooBig) {
                XMEMCPY(&full[idx], &cert->source[cert->srcIdx], strLen);
                idx += strLen;
            }

            cert->srcIdx += strLen;
        }
        else {
            /* skip */
            byte email = FALSE;
            byte uid   = FALSE;
            int  adv;

            if (joint[0] == 0x2a && joint[1] == 0x86)  /* email id hdr */
                email = TRUE;

            if (joint[0] == 0x9  && joint[1] == 0x92)  /* uid id hdr */
                uid = TRUE;

            cert->srcIdx += oidSz + 1;

            if (GetLength(cert->source, &cert->srcIdx, &adv, cert->maxIdx) < 0)
                return ASN_PARSE_E;

            if (adv > (int)(ASN_NAME_MAX - idx)) {
                CYASSL_MSG("ASN name too big, skipping");
                tooBig = TRUE;
            }

            if (email) {
                if ( (14 + adv) > (int)(ASN_NAME_MAX - idx)) {
                    CYASSL_MSG("ASN name too big, skipping");
                    tooBig = TRUE;
                }
                if (!tooBig) {
                    XMEMCPY(&full[idx], "/emailAddress=", 14);
                    idx += 14;
                }

                #ifdef CYASSL_CERT_GEN
                    if (nameType == SUBJECT) {
                        cert->subjectEmail = (char*)&cert->source[cert->srcIdx];
                        cert->subjectEmailLen = adv;
                    }
                #endif /* CYASSL_CERT_GEN */
                #ifdef OPENSSL_EXTRA
                    dName->emailIdx = cert->srcIdx;
                    dName->emailLen = adv;
                #endif /* OPENSSL_EXTRA */
                #ifndef IGNORE_NAME_CONSTRAINTS
                    {
                        DNS_entry* emailName = NULL;

                        emailName = (DNS_entry*)XMALLOC(sizeof(DNS_entry),
                                              cert->heap, DYNAMIC_TYPE_ALTNAME);
                        if (emailName == NULL) {
                            CYASSL_MSG("\tOut of Memory");
                            return MEMORY_E;
                        }
                        emailName->name = (char*)XMALLOC(adv + 1,
                                              cert->heap, DYNAMIC_TYPE_ALTNAME);
                        if (emailName->name == NULL) {
                            CYASSL_MSG("\tOut of Memory");
                            return MEMORY_E;
                        }
                        XMEMCPY(emailName->name,
                                              &cert->source[cert->srcIdx], adv);
                        emailName->name[adv] = 0;

                        emailName->next = cert->altEmailNames;
                        cert->altEmailNames = emailName;
                    }
                #endif /* IGNORE_NAME_CONSTRAINTS */
                if (!tooBig) {
                    XMEMCPY(&full[idx], &cert->source[cert->srcIdx], adv);
                    idx += adv;
                }
            }

            if (uid) {
                if ( (5 + adv) > (int)(ASN_NAME_MAX - idx)) {
                    CYASSL_MSG("ASN name too big, skipping");
                    tooBig = TRUE;
                }
                if (!tooBig) {
                    XMEMCPY(&full[idx], "/UID=", 5);
                    idx += 5;

                    XMEMCPY(&full[idx], &cert->source[cert->srcIdx], adv);
                    idx += adv;
                }
                #ifdef OPENSSL_EXTRA
                    dName->uidIdx = cert->srcIdx;
                    dName->uidLen = adv;
                #endif /* OPENSSL_EXTRA */
            }

            cert->srcIdx += adv;
        }
    }
    full[idx++] = 0;

    #ifdef OPENSSL_EXTRA
    {
        int totalLen = 0;

        if (dName->cnLen != 0)
            totalLen += dName->cnLen + 4;
        if (dName->snLen != 0)
            totalLen += dName->snLen + 4;
        if (dName->cLen != 0)
            totalLen += dName->cLen + 3;
        if (dName->lLen != 0)
            totalLen += dName->lLen + 3;
        if (dName->stLen != 0)
            totalLen += dName->stLen + 4;
        if (dName->oLen != 0)
            totalLen += dName->oLen + 3;
        if (dName->ouLen != 0)
            totalLen += dName->ouLen + 4;
        if (dName->emailLen != 0)
            totalLen += dName->emailLen + 14;
        if (dName->uidLen != 0)
            totalLen += dName->uidLen + 5;
        if (dName->serialLen != 0)
            totalLen += dName->serialLen + 14;

        dName->fullName = (char*)XMALLOC(totalLen + 1, NULL, DYNAMIC_TYPE_X509);
        if (dName->fullName != NULL) {
            idx = 0;

            if (dName->cnLen != 0) {
                dName->entryCount++;
                XMEMCPY(&dName->fullName[idx], "/CN=", 4);
                idx += 4;
                XMEMCPY(&dName->fullName[idx],
                                     &cert->source[dName->cnIdx], dName->cnLen);
                dName->cnIdx = idx;
                idx += dName->cnLen;
            }
            if (dName->snLen != 0) {
                dName->entryCount++;
                XMEMCPY(&dName->fullName[idx], "/SN=", 4);
                idx += 4;
                XMEMCPY(&dName->fullName[idx],
                                     &cert->source[dName->snIdx], dName->snLen);
                dName->snIdx = idx;
                idx += dName->snLen;
            }
            if (dName->cLen != 0) {
                dName->entryCount++;
                XMEMCPY(&dName->fullName[idx], "/C=", 3);
                idx += 3;
                XMEMCPY(&dName->fullName[idx],
                                       &cert->source[dName->cIdx], dName->cLen);
                dName->cIdx = idx;
                idx += dName->cLen;
            }
            if (dName->lLen != 0) {
                dName->entryCount++;
                XMEMCPY(&dName->fullName[idx], "/L=", 3);
                idx += 3;
                XMEMCPY(&dName->fullName[idx],
                                       &cert->source[dName->lIdx], dName->lLen);
                dName->lIdx = idx;
                idx += dName->lLen;
            }
            if (dName->stLen != 0) {
                dName->entryCount++;
                XMEMCPY(&dName->fullName[idx], "/ST=", 4);
                idx += 4;
                XMEMCPY(&dName->fullName[idx],
                                     &cert->source[dName->stIdx], dName->stLen);
                dName->stIdx = idx;
                idx += dName->stLen;
            }
            if (dName->oLen != 0) {
                dName->entryCount++;
                XMEMCPY(&dName->fullName[idx], "/O=", 3);
                idx += 3;
                XMEMCPY(&dName->fullName[idx],
                                       &cert->source[dName->oIdx], dName->oLen);
                dName->oIdx = idx;
                idx += dName->oLen;
            }
            if (dName->ouLen != 0) {
                dName->entryCount++;
                XMEMCPY(&dName->fullName[idx], "/OU=", 4);
                idx += 4;
                XMEMCPY(&dName->fullName[idx],
                                     &cert->source[dName->ouIdx], dName->ouLen);
                dName->ouIdx = idx;
                idx += dName->ouLen;
            }
            if (dName->emailLen != 0) {
                dName->entryCount++;
                XMEMCPY(&dName->fullName[idx], "/emailAddress=", 14);
                idx += 14;
                XMEMCPY(&dName->fullName[idx],
                               &cert->source[dName->emailIdx], dName->emailLen);
                dName->emailIdx = idx;
                idx += dName->emailLen;
            }
            if (dName->uidLen != 0) {
                dName->entryCount++;
                XMEMCPY(&dName->fullName[idx], "/UID=", 5);
                idx += 5;
                XMEMCPY(&dName->fullName[idx],
                                   &cert->source[dName->uidIdx], dName->uidLen);
                dName->uidIdx = idx;
                idx += dName->uidLen;
            }
            if (dName->serialLen != 0) {
                dName->entryCount++;
                XMEMCPY(&dName->fullName[idx], "/serialNumber=", 14);
                idx += 14;
                XMEMCPY(&dName->fullName[idx],
                             &cert->source[dName->serialIdx], dName->serialLen);
                dName->serialIdx = idx;
                idx += dName->serialLen;
            }
            dName->fullName[idx] = '\0';
            dName->fullNameLen = totalLen;
        }
    }
    #endif /* OPENSSL_EXTRA */

    return 0;
}


#ifndef NO_TIME_H

/* to the second */
static int DateGreaterThan(const struct tm* a, const struct tm* b)
{
    if (a->tm_year > b->tm_year)
        return 1;

    if (a->tm_year == b->tm_year && a->tm_mon > b->tm_mon)
        return 1;
    
    if (a->tm_year == b->tm_year && a->tm_mon == b->tm_mon &&
           a->tm_mday > b->tm_mday)
        return 1;

    if (a->tm_year == b->tm_year && a->tm_mon == b->tm_mon &&
        a->tm_mday == b->tm_mday && a->tm_hour > b->tm_hour)
        return 1;

    if (a->tm_year == b->tm_year && a->tm_mon == b->tm_mon &&
        a->tm_mday == b->tm_mday && a->tm_hour == b->tm_hour &&
        a->tm_min > b->tm_min)
        return 1;

    if (a->tm_year == b->tm_year && a->tm_mon == b->tm_mon &&
        a->tm_mday == b->tm_mday && a->tm_hour == b->tm_hour &&
        a->tm_min  == b->tm_min  && a->tm_sec > b->tm_sec)
        return 1;

    return 0; /* false */
}


static INLINE int DateLessThan(const struct tm* a, const struct tm* b)
{
    return DateGreaterThan(b,a);
}


/* like atoi but only use first byte */
/* Make sure before and after dates are valid */
int ValidateDate(const byte* date, byte format, int dateType)
{
    time_t ltime;
    struct tm  certTime;
    struct tm* localTime;
    int    i = 0;

    ltime = XTIME(0);
    XMEMSET(&certTime, 0, sizeof(certTime));

    if (format == ASN_UTC_TIME) {
        if (btoi(date[0]) >= 5)
            certTime.tm_year = 1900;
        else
            certTime.tm_year = 2000;
    }
    else  { /* format == GENERALIZED_TIME */
        certTime.tm_year += btoi(date[i++]) * 1000;
        certTime.tm_year += btoi(date[i++]) * 100;
    }

    /* adjust tm_year, tm_mon */
    GetTime((int*)&certTime.tm_year, date, &i); certTime.tm_year -= 1900;
    GetTime((int*)&certTime.tm_mon,  date, &i); certTime.tm_mon  -= 1;
    GetTime((int*)&certTime.tm_mday, date, &i);
    GetTime((int*)&certTime.tm_hour, date, &i);
    GetTime((int*)&certTime.tm_min,  date, &i);
    GetTime((int*)&certTime.tm_sec,  date, &i);
        
        if (date[i] != 'Z') {     /* only Zulu supported for this profile */
        CYASSL_MSG("Only Zulu time supported for this profile"); 
        return 0;
    }

    localTime = XGMTIME(&ltime);

    if (dateType == BEFORE) {
        if (DateLessThan(localTime, &certTime))
            return 0;
    }
    else
        if (DateGreaterThan(localTime, &certTime))
            return 0;

    return 1;
}

#endif /* NO_TIME_H */


static int GetDate(DecodedCert* cert, int dateType)
{
    int    length;
    byte   date[MAX_DATE_SIZE];
    byte   b;
    word32 startIdx = 0;

    if (dateType == BEFORE)
        cert->beforeDate = &cert->source[cert->srcIdx];
    else
        cert->afterDate = &cert->source[cert->srcIdx];
    startIdx = cert->srcIdx;

    b = cert->source[cert->srcIdx++];
    if (b != ASN_UTC_TIME && b != ASN_GENERALIZED_TIME)
        return ASN_TIME_E;

    if (GetLength(cert->source, &cert->srcIdx, &length, cert->maxIdx) < 0)
        return ASN_PARSE_E;

    if (length > MAX_DATE_SIZE || length < MIN_DATE_SIZE)
        return ASN_DATE_SZ_E;

    XMEMCPY(date, &cert->source[cert->srcIdx], length);
    cert->srcIdx += length;

    if (dateType == BEFORE)
        cert->beforeDateLen = cert->srcIdx - startIdx;
    else
        cert->afterDateLen  = cert->srcIdx - startIdx;

    if (!XVALIDATE_DATE(date, b, dateType)) {
        if (dateType == BEFORE)
            return ASN_BEFORE_DATE_E;
        else
            return ASN_AFTER_DATE_E;
    }

    return 0;
}


static int GetValidity(DecodedCert* cert, int verify)
{
    int length;
    int badDate = 0;

    if (GetSequence(cert->source, &cert->srcIdx, &length, cert->maxIdx) < 0)
        return ASN_PARSE_E;

    if (GetDate(cert, BEFORE) < 0 && verify)
        badDate = ASN_BEFORE_DATE_E;           /* continue parsing */
    
    if (GetDate(cert, AFTER) < 0 && verify)
        return ASN_AFTER_DATE_E;
   
    if (badDate != 0)
        return badDate;

    return 0;
}


int DecodeToKey(DecodedCert* cert, int verify)
{
    int badDate = 0;
    int ret;

    if ( (ret = GetCertHeader(cert)) < 0)
        return ret;

    CYASSL_MSG("Got Cert Header");

    if ( (ret = GetAlgoId(cert->source, &cert->srcIdx, &cert->signatureOID,
                          cert->maxIdx)) < 0)
        return ret;

    CYASSL_MSG("Got Algo ID");

    if ( (ret = GetName(cert, ISSUER)) < 0)
        return ret;

    if ( (ret = GetValidity(cert, verify)) < 0)
        badDate = ret;

    if ( (ret = GetName(cert, SUBJECT)) < 0)
        return ret;

    CYASSL_MSG("Got Subject Name");

    if ( (ret = GetKey(cert)) < 0)
        return ret;

    CYASSL_MSG("Got Key");

    if (badDate != 0)
        return badDate;

    return ret;
}


static int GetSignature(DecodedCert* cert)
{
    int    length;
    byte   b = cert->source[cert->srcIdx++];

    if (b != ASN_BIT_STRING)
        return ASN_BITSTR_E;

    if (GetLength(cert->source, &cert->srcIdx, &length, cert->maxIdx) < 0)
        return ASN_PARSE_E;

    cert->sigLength = length;

    b = cert->source[cert->srcIdx++];
    if (b != 0x00)
        return ASN_EXPECT_0_E;

    cert->sigLength--;
    cert->signature = &cert->source[cert->srcIdx];
    cert->srcIdx += cert->sigLength;

    return 0;
}


static word32 SetDigest(const byte* digest, word32 digSz, byte* output)
{
    output[0] = ASN_OCTET_STRING;
    output[1] = (byte)digSz;
    XMEMCPY(&output[2], digest, digSz);

    return digSz + 2;
} 


static word32 BytePrecision(word32 value)
{
    word32 i;
    for (i = sizeof(value); i; --i)
        if (value >> ((i - 1) * CYASSL_BIT_SIZE))
            break;

    return i;
}


CYASSL_LOCAL word32 SetLength(word32 length, byte* output)
{
    word32 i = 0, j;

    if (length < ASN_LONG_LENGTH)
        output[i++] = (byte)length;
    else {
        output[i++] = (byte)(BytePrecision(length) | ASN_LONG_LENGTH);
      
        for (j = BytePrecision(length); j; --j) {
            output[i] = (byte)(length >> ((j - 1) * CYASSL_BIT_SIZE));
            i++;
        }
    }

    return i;
}


CYASSL_LOCAL word32 SetSequence(word32 len, byte* output)
{
    output[0] = ASN_SEQUENCE | ASN_CONSTRUCTED;
    return SetLength(len, output + 1) + 1;
}

CYASSL_LOCAL word32 SetOctetString(word32 len, byte* output)
{
    output[0] = ASN_OCTET_STRING;
    return SetLength(len, output + 1) + 1;
}

/* Write a set header to output */
CYASSL_LOCAL word32 SetSet(word32 len, byte* output)
{
    output[0] = ASN_SET | ASN_CONSTRUCTED;
    return SetLength(len, output + 1) + 1;
}

CYASSL_LOCAL word32 SetImplicit(byte tag, byte number, word32 len, byte* output)
{

    output[0] = ((tag == ASN_SEQUENCE || tag == ASN_SET) ? ASN_CONSTRUCTED : 0)
                    | ASN_CONTEXT_SPECIFIC | number;
    return SetLength(len, output + 1) + 1;
}

CYASSL_LOCAL word32 SetExplicit(byte number, word32 len, byte* output)
{
    output[0] = ASN_CONSTRUCTED | ASN_CONTEXT_SPECIFIC | number;
    return SetLength(len, output + 1) + 1;
}


#if defined(HAVE_ECC) && (defined(CYASSL_CERT_GEN) || defined(CYASSL_KEY_GEN))

static word32 SetCurve(ecc_key* key, byte* output)
{

    /* curve types */
    static const byte ECC_192v1_AlgoID[] = { 0x2a, 0x86, 0x48, 0xCE, 0x3d,
                                             0x03, 0x01, 0x01};
    static const byte ECC_256v1_AlgoID[] = { 0x2a, 0x86, 0x48, 0xCE, 0x3d,
                                            0x03, 0x01, 0x07};
    static const byte ECC_160r1_AlgoID[] = { 0x2b, 0x81, 0x04, 0x00,
                                             0x02};
    static const byte ECC_224r1_AlgoID[] = { 0x2b, 0x81, 0x04, 0x00,
                                             0x21};
    static const byte ECC_384r1_AlgoID[] = { 0x2b, 0x81, 0x04, 0x00,
                                             0x22};
    static const byte ECC_521r1_AlgoID[] = { 0x2b, 0x81, 0x04, 0x00,
                                             0x23};

    int    oidSz = 0;
    int    idx = 0;
    int    lenSz = 0;
    const  byte* oid = 0;

    output[0] = ASN_OBJECT_ID;
    idx++;

    switch (key->dp->size) {
        case 20:
            oidSz = sizeof(ECC_160r1_AlgoID);
            oid   =        ECC_160r1_AlgoID;
            break;

        case 24:
            oidSz = sizeof(ECC_192v1_AlgoID);
            oid   =        ECC_192v1_AlgoID;
            break;

        case 28:
            oidSz = sizeof(ECC_224r1_AlgoID);
            oid   =        ECC_224r1_AlgoID;
            break;

        case 32:
            oidSz = sizeof(ECC_256v1_AlgoID);
            oid   =        ECC_256v1_AlgoID;
            break;

        case 48:
            oidSz = sizeof(ECC_384r1_AlgoID);
            oid   =        ECC_384r1_AlgoID;
            break;

        case 66:
            oidSz = sizeof(ECC_521r1_AlgoID);
            oid   =        ECC_521r1_AlgoID;
            break;

        default:
            return ASN_UNKNOWN_OID_E;
    }
    lenSz = SetLength(oidSz, output+idx);
    idx += lenSz;

    XMEMCPY(output+idx, oid, oidSz);
    idx += oidSz;

    return idx;
}

#endif /* HAVE_ECC && CYASSL_CERT_GEN */


CYASSL_LOCAL word32 SetAlgoID(int algoOID, byte* output, int type, int curveSz)
{
    /* adding TAG_NULL and 0 to end */
    
    /* hashTypes */
    static const byte shaAlgoID[]    = { 0x2b, 0x0e, 0x03, 0x02, 0x1a,
                                         0x05, 0x00 };
    static const byte sha256AlgoID[] = { 0x60, 0x86, 0x48, 0x01, 0x65, 0x03,
                                         0x04, 0x02, 0x01, 0x05, 0x00 };
    static const byte sha384AlgoID[] = { 0x60, 0x86, 0x48, 0x01, 0x65, 0x03,
                                         0x04, 0x02, 0x02, 0x05, 0x00 };
    static const byte sha512AlgoID[] = { 0x60, 0x86, 0x48, 0x01, 0x65, 0x03,
                                         0x04, 0x02, 0x03, 0x05, 0x00 };
    static const byte md5AlgoID[]    = { 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d,
                                         0x02, 0x05, 0x05, 0x00  };
    static const byte md2AlgoID[]    = { 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d,
                                         0x02, 0x02, 0x05, 0x00};

    /* blkTypes, no NULL tags because IV is there instead */
    static const byte desCbcAlgoID[]  = { 0x2B, 0x0E, 0x03, 0x02, 0x07 };
    static const byte des3CbcAlgoID[] = { 0x2A, 0x86, 0x48, 0x86, 0xF7,
                                          0x0D, 0x03, 0x07 };

    /* RSA sigTypes */
    #ifndef NO_RSA
        static const byte md5wRSA_AlgoID[] = { 0x2a, 0x86, 0x48, 0x86, 0xf7,
                                            0x0d, 0x01, 0x01, 0x04, 0x05, 0x00};
        static const byte shawRSA_AlgoID[] = { 0x2a, 0x86, 0x48, 0x86, 0xf7,
                                            0x0d, 0x01, 0x01, 0x05, 0x05, 0x00};
        static const byte sha256wRSA_AlgoID[] = { 0x2a, 0x86, 0x48, 0x86, 0xf7,
                                            0x0d, 0x01, 0x01, 0x0b, 0x05, 0x00};
        static const byte sha384wRSA_AlgoID[] = {0x2a, 0x86, 0x48, 0x86, 0xf7,
                                            0x0d, 0x01, 0x01, 0x0c, 0x05, 0x00};
        static const byte sha512wRSA_AlgoID[] = {0x2a, 0x86, 0x48, 0x86, 0xf7,
                                            0x0d, 0x01, 0x01, 0x0d, 0x05, 0x00};
    #endif /* NO_RSA */
 
    /* ECDSA sigTypes */
    #ifdef HAVE_ECC 
        static const byte shawECDSA_AlgoID[] = { 0x2a, 0x86, 0x48, 0xCE, 0x3d,
                                                 0x04, 0x01, 0x05, 0x00};
        static const byte sha256wECDSA_AlgoID[] = { 0x2a, 0x86, 0x48, 0xCE,0x3d,
                                                 0x04, 0x03, 0x02, 0x05, 0x00};
        static const byte sha384wECDSA_AlgoID[] = { 0x2a, 0x86, 0x48, 0xCE,0x3d,
                                                 0x04, 0x03, 0x03, 0x05, 0x00};
        static const byte sha512wECDSA_AlgoID[] = { 0x2a, 0x86, 0x48, 0xCE,0x3d,
                                                 0x04, 0x03, 0x04, 0x05, 0x00};
    #endif /* HAVE_ECC */
 
    /* RSA keyType */
    #ifndef NO_RSA
        static const byte RSA_AlgoID[] = { 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d,
                                            0x01, 0x01, 0x01, 0x05, 0x00};
    #endif /* NO_RSA */

    #ifdef HAVE_ECC 
        /* ECC keyType */
        /* no tags, so set tagSz smaller later */
        static const byte ECC_AlgoID[] = { 0x2a, 0x86, 0x48, 0xCE, 0x3d,
                                           0x02, 0x01};
    #endif /* HAVE_ECC */

    int    algoSz = 0;
    int    tagSz  = 2;   /* tag null and terminator */
    word32 idSz, seqSz;
    const  byte* algoName = 0;
    byte ID_Length[MAX_LENGTH_SZ];
    byte seqArray[MAX_SEQ_SZ + 1];  /* add object_id to end */

    if (type == hashType) {
        switch (algoOID) {
        case SHAh:
            algoSz = sizeof(shaAlgoID);
            algoName = shaAlgoID;
            break;

        case SHA256h:
            algoSz = sizeof(sha256AlgoID);
            algoName = sha256AlgoID;
            break;

        case SHA384h:
            algoSz = sizeof(sha384AlgoID);
            algoName = sha384AlgoID;
            break;

        case SHA512h:
            algoSz = sizeof(sha512AlgoID);
            algoName = sha512AlgoID;
            break;

        case MD2h:
            algoSz = sizeof(md2AlgoID);
            algoName = md2AlgoID;
            break;

        case MD5h:
            algoSz = sizeof(md5AlgoID);
            algoName = md5AlgoID;
            break;

        default:
            CYASSL_MSG("Unknown Hash Algo");
            return 0;  /* UNKOWN_HASH_E; */
        }
    }
    else if (type == blkType) {
        switch (algoOID) {
        case DESb:
            algoSz = sizeof(desCbcAlgoID);
            algoName = desCbcAlgoID;
            tagSz = 0;
            break;
        case DES3b:
            algoSz = sizeof(des3CbcAlgoID);
            algoName = des3CbcAlgoID;
            tagSz = 0;
            break;
        default:
            CYASSL_MSG("Unknown Block Algo");
            return 0;
        }
    }
    else if (type == sigType) {    /* sigType */
        switch (algoOID) {
        #ifndef NO_RSA
            case CTC_MD5wRSA:
                algoSz = sizeof(md5wRSA_AlgoID);
                algoName = md5wRSA_AlgoID;
                break;

            case CTC_SHAwRSA:
                algoSz = sizeof(shawRSA_AlgoID);
                algoName = shawRSA_AlgoID;
                break;

            case CTC_SHA256wRSA:
                algoSz = sizeof(sha256wRSA_AlgoID);
                algoName = sha256wRSA_AlgoID;
                break;

            case CTC_SHA384wRSA:
                algoSz = sizeof(sha384wRSA_AlgoID);
                algoName = sha384wRSA_AlgoID;
                break;

            case CTC_SHA512wRSA:
                algoSz = sizeof(sha512wRSA_AlgoID);
                algoName = sha512wRSA_AlgoID;
                break;
        #endif /* NO_RSA */
        #ifdef HAVE_ECC 
            case CTC_SHAwECDSA:
                algoSz = sizeof(shawECDSA_AlgoID);
                algoName = shawECDSA_AlgoID;
                break;

            case CTC_SHA256wECDSA:
                algoSz = sizeof(sha256wECDSA_AlgoID);
                algoName = sha256wECDSA_AlgoID;
                break;

            case CTC_SHA384wECDSA:
                algoSz = sizeof(sha384wECDSA_AlgoID);
                algoName = sha384wECDSA_AlgoID;
                break;

            case CTC_SHA512wECDSA:
                algoSz = sizeof(sha512wECDSA_AlgoID);
                algoName = sha512wECDSA_AlgoID;
                break;
        #endif /* HAVE_ECC */
        default:
            CYASSL_MSG("Unknown Signature Algo");
            return 0;
        }
    }
    else if (type == keyType) {    /* keyType */
        switch (algoOID) {
        #ifndef NO_RSA
            case RSAk:
                algoSz = sizeof(RSA_AlgoID);
                algoName = RSA_AlgoID;
                break;
        #endif /* NO_RSA */
        #ifdef HAVE_ECC 
            case ECDSAk:
                algoSz = sizeof(ECC_AlgoID);
                algoName = ECC_AlgoID;
                tagSz = 0;
                break;
        #endif /* HAVE_ECC */
        default:
            CYASSL_MSG("Unknown Key Algo");
            return 0;
        }
    }
    else {
        CYASSL_MSG("Unknown Algo type");
        return 0;
    }

    idSz  = SetLength(algoSz - tagSz, ID_Length); /* don't include tags */
    seqSz = SetSequence(idSz + algoSz + 1 + curveSz, seqArray); 
                 /* +1 for object id, curveID of curveSz follows for ecc */
    seqArray[seqSz++] = ASN_OBJECT_ID;

    XMEMCPY(output, seqArray, seqSz);
    XMEMCPY(output + seqSz, ID_Length, idSz);
    XMEMCPY(output + seqSz + idSz, algoName, algoSz);

    return seqSz + idSz + algoSz;

}


word32 EncodeSignature(byte* out, const byte* digest, word32 digSz, int hashOID)
{
    byte digArray[MAX_ENCODED_DIG_SZ];
    byte algoArray[MAX_ALGO_SZ];
    byte seqArray[MAX_SEQ_SZ];
    word32 encDigSz, algoSz, seqSz; 

    encDigSz = SetDigest(digest, digSz, digArray);
    algoSz   = SetAlgoID(hashOID, algoArray, hashType, 0);
    seqSz    = SetSequence(encDigSz + algoSz, seqArray);

    XMEMCPY(out, seqArray, seqSz);
    XMEMCPY(out + seqSz, algoArray, algoSz);
    XMEMCPY(out + seqSz + algoSz, digArray, encDigSz);

    return encDigSz + algoSz + seqSz;
}


int GetCTC_HashOID(int type)
{
    switch (type) {
#ifdef CYASSL_MD2
        case MD2:
            return MD2h;
#endif
#ifndef NO_MD5
        case MD5:
            return MD5h;
#endif
#ifndef NO_SHA
        case SHA:
            return SHAh;
#endif
#ifndef NO_SHA256
        case SHA256:
            return SHA256h;
#endif
#ifdef CYASSL_SHA384
        case SHA384:
            return SHA384h;
#endif
#ifdef CYASSL_SHA512
        case SHA512:
            return SHA512h;
#endif
        default:
            return 0;
    };
}


/* return true (1) or false (0) for Confirmation */
static int ConfirmSignature(const byte* buf, word32 bufSz,
    const byte* key, word32 keySz, word32 keyOID,
    const byte* sig, word32 sigSz, word32 sigOID,
    void* heap)
{
    int  typeH = 0, digestSz = 0, ret = 0;
#ifdef CYASSL_SMALL_STACK
    byte* digest;
#else
    byte digest[MAX_DIGEST_SIZE];
#endif

#ifdef CYASSL_SMALL_STACK
    digest = (byte*)XMALLOC(MAX_DIGEST_SIZE, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (digest == NULL)
        return 0; /* not confirmed */
#endif

    (void)key;
    (void)keySz;
    (void)sig;
    (void)sigSz;
    (void)heap;

    switch (sigOID) {
    #ifndef NO_MD5
        case CTC_MD5wRSA:
        if (Md5Hash(buf, bufSz, digest) == 0) {
            typeH    = MD5h;
            digestSz = MD5_DIGEST_SIZE;
        }
        break;
    #endif
    #if defined(CYASSL_MD2)
        case CTC_MD2wRSA:
        if (Md2Hash(buf, bufSz, digest) == 0) {
            typeH    = MD2h;
            digestSz = MD2_DIGEST_SIZE;
        }
        break;
    #endif
    #ifndef NO_SHA
        case CTC_SHAwRSA:
        case CTC_SHAwDSA:
        case CTC_SHAwECDSA:
        if (ShaHash(buf, bufSz, digest) == 0) {    
            typeH    = SHAh;
            digestSz = SHA_DIGEST_SIZE;                
        }
        break;
    #endif
    #ifndef NO_SHA256
        case CTC_SHA256wRSA:
        case CTC_SHA256wECDSA:
        if (Sha256Hash(buf, bufSz, digest) == 0) {    
            typeH    = SHA256h;
            digestSz = SHA256_DIGEST_SIZE;
        }
        break;
    #endif
    #ifdef CYASSL_SHA512
        case CTC_SHA512wRSA:
        case CTC_SHA512wECDSA:
        if (Sha512Hash(buf, bufSz, digest) == 0) {    
            typeH    = SHA512h;
            digestSz = SHA512_DIGEST_SIZE;
        }
        break;
    #endif
    #ifdef CYASSL_SHA384
        case CTC_SHA384wRSA:
        case CTC_SHA384wECDSA:
        if (Sha384Hash(buf, bufSz, digest) == 0) {    
            typeH    = SHA384h;
            digestSz = SHA384_DIGEST_SIZE;
        }            
        break;
    #endif
        default:
            CYASSL_MSG("Verify Signautre has unsupported type");
    }
    
    if (typeH == 0) {
#ifdef CYASSL_SMALL_STACK
        XFREE(digest, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif
        return 0; /* not confirmed */
    }

    switch (keyOID) {
    #ifndef NO_RSA
        case RSAk:
        {
            word32 idx = 0;
            int    encodedSigSz, verifySz;
            byte*  out;
#ifdef CYASSL_SMALL_STACK
            RsaKey* pubKey;
            byte* plain;
            byte* encodedSig;
#else
            RsaKey pubKey[1];
            byte plain[MAX_ENCODED_SIG_SZ];
            byte encodedSig[MAX_ENCODED_SIG_SZ];
#endif

#ifdef CYASSL_SMALL_STACK
            pubKey = (RsaKey*)XMALLOC(sizeof(RsaKey), NULL,
                                                       DYNAMIC_TYPE_TMP_BUFFER);
            plain = (byte*)XMALLOC(MAX_ENCODED_SIG_SZ, NULL,
                                                       DYNAMIC_TYPE_TMP_BUFFER);
            encodedSig = (byte*)XMALLOC(MAX_ENCODED_SIG_SZ, NULL,
                                                       DYNAMIC_TYPE_TMP_BUFFER);
            
            if (pubKey == NULL || plain == NULL || encodedSig == NULL) {
                CYASSL_MSG("Failed to allocate memory at ConfirmSignature");
                
                if (pubKey)
                    XFREE(pubKey, NULL, DYNAMIC_TYPE_TMP_BUFFER);
                if (plain)
                    XFREE(plain, NULL, DYNAMIC_TYPE_TMP_BUFFER);
                if (encodedSig)
                    XFREE(encodedSig, NULL, DYNAMIC_TYPE_TMP_BUFFER);
                
                break; /* not confirmed */
            }
#endif

            if (sigSz > MAX_ENCODED_SIG_SZ) {
                CYASSL_MSG("Verify Signautre is too big");
            }
            else if (InitRsaKey(pubKey, heap) != 0) {
                CYASSL_MSG("InitRsaKey failed");
            }
            else if (RsaPublicKeyDecode(key, &idx, pubKey, keySz) < 0) {
                CYASSL_MSG("ASN Key decode error RSA");
            }
            else {
                XMEMCPY(plain, sig, sigSz);

                if ((verifySz = RsaSSL_VerifyInline(plain, sigSz, &out,
                                                                 pubKey)) < 0) {
                    CYASSL_MSG("Rsa SSL verify error");
                }
                else {
                    /* make sure we're right justified */
                    encodedSigSz =
                        EncodeSignature(encodedSig, digest, digestSz, typeH);
                    if (encodedSigSz != verifySz ||
                                XMEMCMP(out, encodedSig, encodedSigSz) != 0) {
                        CYASSL_MSG("Rsa SSL verify match encode error");
                    }
                    else
                        ret = 1; /* match */

                    #ifdef CYASSL_DEBUG_ENCODING
                    {
                        int x;
                        
                        printf("cyassl encodedSig:\n");
                        
                        for (x = 0; x < encodedSigSz; x++) {
                            printf("%02x ", encodedSig[x]);
                            if ( (x % 16) == 15)
                                printf("\n");
                        }
                        
                        printf("\n");
                        printf("actual digest:\n");
                        
                        for (x = 0; x < verifySz; x++) {
                            printf("%02x ", out[x]);
                            if ( (x % 16) == 15)
                                printf("\n");
                        }
                        
                        printf("\n");
                    }
                    #endif /* CYASSL_DEBUG_ENCODING */
                    
                }
                
            }
            
            FreeRsaKey(pubKey);
            
#ifdef CYASSL_SMALL_STACK
            XFREE(pubKey,     NULL, DYNAMIC_TYPE_TMP_BUFFER);
            XFREE(plain,      NULL, DYNAMIC_TYPE_TMP_BUFFER);
            XFREE(encodedSig, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif
            break;
        }

    #endif /* NO_RSA */
    #ifdef HAVE_ECC
        case ECDSAk:
        {
            int verify = 0;
#ifdef CYASSL_SMALL_STACK
            ecc_key* pubKey;
#else
            ecc_key pubKey[1];
#endif

#ifdef CYASSL_SMALL_STACK
            pubKey = (ecc_key*)XMALLOC(sizeof(ecc_key), NULL,
                                                       DYNAMIC_TYPE_TMP_BUFFER);
            if (pubKey == NULL) {
                CYASSL_MSG("Failed to allocate pubKey");
                break; /* not confirmed */
            }
#endif

            if (ecc_import_x963(key, keySz, pubKey) < 0) {
                CYASSL_MSG("ASN Key import error ECC");
            }
            else {   
                if (ecc_verify_hash(sig, sigSz, digest, digestSz, &verify,
                                                                pubKey) != 0) {
                    CYASSL_MSG("ECC verify hash error");
                }
                else if (1 != verify) {
                    CYASSL_MSG("ECC Verify didn't match");
                } else
                    ret = 1; /* match */

                ecc_free(pubKey);
            }
#ifdef CYASSL_SMALL_STACK
            XFREE(pubKey, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif
            break;
        }
    #endif /* HAVE_ECC */
        default:
            CYASSL_MSG("Verify Key type unknown");
    }
    
#ifdef CYASSL_SMALL_STACK
    XFREE(digest, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif

    return ret;
}


#ifndef IGNORE_NAME_CONSTRAINTS

static int MatchBaseName(int type, const char* name, int nameSz,
                                                   const char* base, int baseSz)
{
    if (base == NULL || baseSz <= 0 || name == NULL || nameSz <= 0 ||
            name[0] == '.' || nameSz < baseSz ||
            (type != ASN_RFC822_TYPE && type != ASN_DNS_TYPE))
        return 0;

    /* If an email type, handle special cases where the base is only
     * a domain, or is an email address itself. */
    if (type == ASN_RFC822_TYPE) {
        const char* p = NULL;
        int count = 0;

        if (base[0] != '.') {
            p = base;
            count = 0;

            /* find the '@' in the base */
            while (*p != '@' && count < baseSz) {
                count++;
                p++;
            }

            /* No '@' in base, reset p to NULL */
            if (count >= baseSz)
                p = NULL;
        }

        if (p == NULL) {
            /* Base isn't an email address, it is a domain name,
             * wind the name forward one character past its '@'. */
            p = name;
            count = 0;
            while (*p != '@' && count < baseSz) {
                count++;
                p++;
            }

            if (count < baseSz && *p == '@') {
                name = p + 1;
                nameSz -= count + 1;
            }
        }
    }

    if ((type == ASN_DNS_TYPE || type == ASN_RFC822_TYPE) && base[0] == '.') {
        int szAdjust = nameSz - baseSz;
        name += szAdjust;
        nameSz -= szAdjust;
    }

    while (nameSz > 0) {
        if (XTOLOWER(*name++) != XTOLOWER(*base++))
            return 0;
        nameSz--;
    }

    return 1;
}


static int ConfirmNameConstraints(Signer* signer, DecodedCert* cert)
{
    if (signer == NULL || cert == NULL)
        return 0;

    /* Check against the excluded list */
    if (signer->excludedNames) {
        Base_entry* base = signer->excludedNames;

        while (base != NULL) {
            if (base->type == ASN_DNS_TYPE) {
                DNS_entry* name = cert->altNames;
                while (name != NULL) {
                    if (MatchBaseName(ASN_DNS_TYPE,
                                          name->name, (int)XSTRLEN(name->name),
                                          base->name, base->nameSz))
                        return 0;
                    name = name->next;
                }
            }
            else if (base->type == ASN_RFC822_TYPE) {
                DNS_entry* name = cert->altEmailNames;
                while (name != NULL) {
                    if (MatchBaseName(ASN_RFC822_TYPE,
                                          name->name, (int)XSTRLEN(name->name),
                                          base->name, base->nameSz))
                        return 0;

                    name = name->next;
                }
            }
            else if (base->type == ASN_DIR_TYPE) {
                if (cert->subjectRawLen == base->nameSz &&
                    XMEMCMP(cert->subjectRaw, base->name, base->nameSz) == 0) {

                    return 0;
                }
            }
            base = base->next;
        }
    }

    /* Check against the permitted list */
    if (signer->permittedNames != NULL) {
        int needDns = 0;
        int matchDns = 0;
        int needEmail = 0;
        int matchEmail = 0;
        int needDir = 0;
        int matchDir = 0;
        Base_entry* base = signer->permittedNames;

        while (base != NULL) {
            if (base->type == ASN_DNS_TYPE) {
                DNS_entry* name = cert->altNames;

                if (name != NULL)
                    needDns = 1;

                while (name != NULL) {
                    matchDns = MatchBaseName(ASN_DNS_TYPE,
                                          name->name, (int)XSTRLEN(name->name),
                                          base->name, base->nameSz);
                    name = name->next;
                }
            }
            else if (base->type == ASN_RFC822_TYPE) {
                DNS_entry* name = cert->altEmailNames;

                if (name != NULL)
                    needEmail = 1;

                while (name != NULL) {
                    matchEmail = MatchBaseName(ASN_DNS_TYPE,
                                          name->name, (int)XSTRLEN(name->name),
                                          base->name, base->nameSz);
                    name = name->next;
                }
            }
            else if (base->type == ASN_DIR_TYPE) {
                needDir = 1;
                if (cert->subjectRaw != NULL &&
                    cert->subjectRawLen == base->nameSz &&
                    XMEMCMP(cert->subjectRaw, base->name, base->nameSz) == 0) {

                    matchDir = 1;
                }
            }
            base = base->next;
        }

        if ((needDns && !matchDns) || (needEmail && !matchEmail) ||
            (needDir && !matchDir)) {

            return 0;
        }
    }

    return 1;
}

#endif /* IGNORE_NAME_CONSTRAINTS */


static int DecodeAltNames(byte* input, int sz, DecodedCert* cert)
{
    word32 idx = 0;
    int length = 0;

    CYASSL_ENTER("DecodeAltNames");

    if (GetSequence(input, &idx, &length, sz) < 0) {
        CYASSL_MSG("\tBad Sequence");
        return ASN_PARSE_E;
    }

    while (length > 0) {
        byte       b = input[idx++];

        length--;

        /* Save DNS Type names in the altNames list. */
        /* Save Other Type names in the cert's OidMap */
        if (b == (ASN_CONTEXT_SPECIFIC | ASN_DNS_TYPE)) {
            DNS_entry* dnsEntry;
            int strLen;
            word32 lenStartIdx = idx;

            if (GetLength(input, &idx, &strLen, sz) < 0) {
                CYASSL_MSG("\tfail: str length");
                return ASN_PARSE_E;
            }
            length -= (idx - lenStartIdx);

            dnsEntry = (DNS_entry*)XMALLOC(sizeof(DNS_entry), cert->heap,
                                        DYNAMIC_TYPE_ALTNAME);
            if (dnsEntry == NULL) {
                CYASSL_MSG("\tOut of Memory");
                return ASN_PARSE_E;
            }

            dnsEntry->name = (char*)XMALLOC(strLen + 1, cert->heap,
                                         DYNAMIC_TYPE_ALTNAME);
            if (dnsEntry->name == NULL) {
                CYASSL_MSG("\tOut of Memory");
                XFREE(dnsEntry, cert->heap, DYNAMIC_TYPE_ALTNAME);
                return ASN_PARSE_E;
            }

            XMEMCPY(dnsEntry->name, &input[idx], strLen);
            dnsEntry->name[strLen] = '\0';

            dnsEntry->next = cert->altNames;
            cert->altNames = dnsEntry;

            length -= strLen;
            idx    += strLen;
        }
#ifndef IGNORE_NAME_CONSTRAINTS
        else if (b == (ASN_CONTEXT_SPECIFIC | ASN_RFC822_TYPE)) {
            DNS_entry* emailEntry;
            int strLen;
            word32 lenStartIdx = idx;

            if (GetLength(input, &idx, &strLen, sz) < 0) {
                CYASSL_MSG("\tfail: str length");
                return ASN_PARSE_E;
            }
            length -= (idx - lenStartIdx);

            emailEntry = (DNS_entry*)XMALLOC(sizeof(DNS_entry), cert->heap,
                                        DYNAMIC_TYPE_ALTNAME);
            if (emailEntry == NULL) {
                CYASSL_MSG("\tOut of Memory");
                return ASN_PARSE_E;
            }

            emailEntry->name = (char*)XMALLOC(strLen + 1, cert->heap,
                                         DYNAMIC_TYPE_ALTNAME);
            if (emailEntry->name == NULL) {
                CYASSL_MSG("\tOut of Memory");
                XFREE(emailEntry, cert->heap, DYNAMIC_TYPE_ALTNAME);
                return ASN_PARSE_E;
            }

            XMEMCPY(emailEntry->name, &input[idx], strLen);
            emailEntry->name[strLen] = '\0';

            emailEntry->next = cert->altEmailNames;
            cert->altEmailNames = emailEntry;

            length -= strLen;
            idx    += strLen;
        }
#endif /* IGNORE_NAME_CONSTRAINTS */
#ifdef CYASSL_SEP
        else if (b == (ASN_CONTEXT_SPECIFIC | ASN_CONSTRUCTED | ASN_OTHER_TYPE))
        {
            int strLen;
            word32 lenStartIdx = idx;
            word32 oid = 0;

            if (GetLength(input, &idx, &strLen, sz) < 0) {
                CYASSL_MSG("\tfail: other name length");
                return ASN_PARSE_E;
            }
            /* Consume the rest of this sequence. */
            length -= (strLen + idx - lenStartIdx);

            if (GetObjectId(input, &idx, &oid, sz) < 0) {
                CYASSL_MSG("\tbad OID");
                return ASN_PARSE_E;
            }

            if (oid != HW_NAME_OID) {
                CYASSL_MSG("\tincorrect OID");
                return ASN_PARSE_E;
            }

            if (input[idx++] != (ASN_CONTEXT_SPECIFIC | ASN_CONSTRUCTED)) {
                CYASSL_MSG("\twrong type");
                return ASN_PARSE_E;
            }

            if (GetLength(input, &idx, &strLen, sz) < 0) {
                CYASSL_MSG("\tfail: str len");
                return ASN_PARSE_E;
            }

            if (GetSequence(input, &idx, &strLen, sz) < 0) {
                CYASSL_MSG("\tBad Sequence");
                return ASN_PARSE_E;
            }

            if (input[idx++] != ASN_OBJECT_ID) {
                CYASSL_MSG("\texpected OID");
                return ASN_PARSE_E;
            }

            if (GetLength(input, &idx, &strLen, sz) < 0) {
                CYASSL_MSG("\tfailed: str len");
                return ASN_PARSE_E;
            }

            cert->hwType = (byte*)XMALLOC(strLen, cert->heap, 0);
            if (cert->hwType == NULL) {
                CYASSL_MSG("\tOut of Memory");
                return MEMORY_E;
            }

            XMEMCPY(cert->hwType, &input[idx], strLen);
            cert->hwTypeSz = strLen;
            idx += strLen;

            if (input[idx++] != ASN_OCTET_STRING) {
                CYASSL_MSG("\texpected Octet String");
                return ASN_PARSE_E;
            }

            if (GetLength(input, &idx, &strLen, sz) < 0) {
                CYASSL_MSG("\tfailed: str len");
                return ASN_PARSE_E;
            }

            cert->hwSerialNum = (byte*)XMALLOC(strLen + 1, cert->heap, 0);
            if (cert->hwSerialNum == NULL) {
                CYASSL_MSG("\tOut of Memory");
                return MEMORY_E;
            }

            XMEMCPY(cert->hwSerialNum, &input[idx], strLen);
            cert->hwSerialNum[strLen] = '\0';
            cert->hwSerialNumSz = strLen;
            idx += strLen;
        }
#endif /* CYASSL_SEP */
        else {
            int strLen;
            word32 lenStartIdx = idx;

            CYASSL_MSG("\tUnsupported name type, skipping");

            if (GetLength(input, &idx, &strLen, sz) < 0) {
                CYASSL_MSG("\tfail: unsupported name length");
                return ASN_PARSE_E;
            }
            length -= (strLen + idx - lenStartIdx);
            idx += strLen;
        }
    }
    return 0;
}


static int DecodeBasicCaConstraint(byte* input, int sz, DecodedCert* cert)
{
    word32 idx = 0;
    int length = 0;

    CYASSL_ENTER("DecodeBasicCaConstraint");
    if (GetSequence(input, &idx, &length, sz) < 0) {
        CYASSL_MSG("\tfail: bad SEQUENCE");
        return ASN_PARSE_E;
    }

    if (length == 0)
        return 0;

    /* If the basic ca constraint is false, this extension may be named, but
     * left empty. So, if the length is 0, just return. */

    if (input[idx++] != ASN_BOOLEAN)
    {
        CYASSL_MSG("\tfail: constraint not BOOLEAN");
        return ASN_PARSE_E;
    }

    if (GetLength(input, &idx, &length, sz) < 0)
    {
        CYASSL_MSG("\tfail: length");
        return ASN_PARSE_E;
    }

    if (input[idx++])
        cert->isCA = 1;

    #ifdef OPENSSL_EXTRA
        /* If there isn't any more data, return. */
        if (idx >= (word32)sz)
            return 0;

        /* Anything left should be the optional pathlength */
        if (input[idx++] != ASN_INTEGER) {
            CYASSL_MSG("\tfail: pathlen not INTEGER");
            return ASN_PARSE_E;
        }

        if (input[idx++] != 1) {
            CYASSL_MSG("\tfail: pathlen too long");
            return ASN_PARSE_E;
        }

        cert->pathLength = input[idx];
        cert->extBasicConstPlSet = 1;
    #endif /* OPENSSL_EXTRA */

    return 0;
}


#define CRLDP_FULL_NAME 0
    /* From RFC3280 SS4.2.1.14, Distribution Point Name*/
#define GENERALNAME_URI 6
    /* From RFC3280 SS4.2.1.7, GeneralName */

static int DecodeCrlDist(byte* input, int sz, DecodedCert* cert)
{
    word32 idx = 0;
    int length = 0;

    CYASSL_ENTER("DecodeCrlDist");

    /* Unwrap the list of C) 2ribution Points*/2014 if (GetSequence(input, &idx, &length, sz) < 0)2014 e itreturn ASN_PARSE_E6-2014 wolfSSL Ina singleis file is part of  yaSSL.
 *
 * CyaSSL is free software; you can redistribute it and/or modify
 * it under thTh GNU General Public Lhas three explicit ops paal membersibute *  First check for ais file is pat of NameistribuaSSL.
 *
 free [idx] == (modiCONSTRUCTED | modiCONTEXT_SPECIFIC | 0)ribute{ibute it idx++;Y or FITNE*
 * CLyou c free software; you can redistribute it  it and/or modify
 * it underHOUT ANY WARRANTY; witc License for GNU Genhout eveanty of
 * MERCHout even the impliCRLDP_FULL_NAMENTABILIBILITY or FITNFITNESS FOR A PARTIARTICULAR PURPOSE.  See the
 * GNU General Public License for for more details.
 *
 * You shouHOUT ANY WARRANTY; without eveanty of
 * MERCHGENERAL, wr_URIite to the the Free Software
are
 * Foundation, Inc.Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA USA
 */

#ifdef HAVE_CONFIG_H
    #i */
cert->extCrlInfoSz =  you cTP_SYS
    #includendif

#include  = free  +NESSTP_SYS
    #includedx +assl/ctaocrypt/integer}gs.h>

#ifndeels * but md2.h>
#inc, or
is isn't a URI, skip it. WITHOUTde <cyassl/csl/ctaocrypt/coding.h>
lude <cyastaocrypt/md2.h>
#ude <cyassl/ctaof no, wrpt/hmac.h>
#include <cyasssl/ctaocrypt/coding}-2014 wolCe hope threasonFlags WITHOUT ANY dx < (word32)sz && You shoulWARRANTY; without even the implied warranty of
 * MERCH1NTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 *3.h>
#include <cyassl/ctaocrypt/logging.h>

#incRLIssuersl/ctaocrypt/random.h>


#ifndef NO_RC4
    #include <cyassl/ctaocrypt/arc4.h>
#endif

#ifdef HA2E_NTRU
    #include "ntru_crypto.h"
#endif

#ifdef HAVE_ECC
    #include <cyassl/ctaocrypt/ecc.h>
#endif

#ifdef CYASSL_DEBUG_ENCODING
    #ifdrypt/random.h>


#ifTABILITY or FITNasn.c
 MSG("\tThere are moregramGNU General Public Lrecords, " copy of the GNU Gen"but we only usenc.
 f in tone.006-taocrypt/loand/or 0;
}


static ic LpyrighAuthude (byte*
    #,))
  sz,   #defdCert*
#inc)
/*
buteReadXTIME(tl)  (fnc.
 ine ority ude rmas parAccessses pari. ICRIUMif


#(t))
any i    s,MTIME(c)without savingnc.
 es par.
 WITTY or .h>


nclud=) myRC4
  tssl/ctaf),(t))
  DATE bt))
  dler((doid6-2014 asn.c
 *
 * Copyrighine XVAL006-2014 wolfSSL Inc.
 *
 * ThiAIAssl/ctaocrypt* CyaSSL is free software; you can redistribute it and/or modify
 * it underwhileUE  1
#endif
#ifndeITY or FITN the terms of the GAIA
#include <c *
 * CyaSSL is free software; you can redistribute it  for more details.
 *
 * You shouoidf),(t))
  t1) pic32_tObjectId free software;oid(c) gmtime((c))
    #define XVALIDATE_DATE(d, f, t) /* Odefisupport NetURIs right now>
#include <cb/ctaocryANTY++]OR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should hb.h>
#endif

#include <cyassl/ctaocrypt/settindef NO_RC4
 t) Valid=efin_OCSP_OIDribute it Free Software
endif

#iine XVAL<cyassl/ctaocrypt/integer_MDK_ARM.h"
    #/ctaocrypt/asn.h>
#include <break-crypt.h>
#include <clude <cyassl/ctaocrypt/loTIME(c) my_gmtime((c))
    #define KeyIdIDATE_DATE(d, f, t) ValidateDate((d), (f)ateHandler((d),(f),(t))
    #else
      VALIDf),(t) t) (0)
    #endif
    #defin))
  006-2014  *
 * CyaSSL is free software; you can redistrLSE
    #define FALSE 0
#fail: should be a SEQUENCE\n    #defcrypt/ecc.h>
#endif

#ifdef define TRUE TE_DATE(d,  !>
#endif

#include <cyassl0)here that WINCE uses, so rinfo: OPTIONAL itemER_Tnot available
       since the EPO(t))
  define TRUER PURPOSE.  See the
 * GNU General Publiere that WINCE uses, so really extens pardatassl/cta      since the EPOCH 
    */

    struct t#ifdef OPEN.c
 *XTRAfdef CYAS_MDK_ARM.h"
 ))
  Src = &    #incluifdef CYASSunday [0-6] */
	incyassl/ctaocrypt#endifefine_wday;	/* da WITnctions, lse
    = SHA_SIZEh [1-31] */
XMEMCPY(Sunday [0-6] */
	i, f,crypt/asn,ssl/cta   #definde <cyasinclude "cySha shaifdef CYASIME)
 InitSha(&sha     since CULAIME)!=ime((c))
    #define XVretifdef CYASShaUpdateard d_zone;	/* timezone abbreviater);
  Finalrn timeSunday [0-6] */
	i   #define XGMTIME(c) my_gmtime((c))
    #defSubj))
    #define XVALIDATE_DATE(d, f, t)  ValidateDate((d), (f), (t))
#elif defined(USER_TIME)
    /* user time, and gmtime te((d), (e functions, 	int	tm_sec;		/*modiOCTET_STRINGhere that WINCE uses, so really just need sn ime_t time(t      since the EPOCH 
    */

    struct tm {
23] */
	int	tm_mday;	/* day of the month [1-31] */
	int	tm_mon;		/* months since January [0-11] */
	int	tm_year;	/* years since 1900 */
	int	tm_wday;	/* days since Sunday [0te((d), (nt	tm_yday;	/* days since January 1 alidateDat
	int	tm_isdst;	/* Daylight Savings Time flag */
	long	tm_gmtofIGNER_DIGEST	/* offset from CUT in seconds */
te((d), (_zone;	/* timezone abbreviation */
    };
    typedef long time_t;

    /* forward declaration */
    struct tm* gmtime(const time_t* timer);
    extern time_t XTIME(time_t * timer);

    #define XGMTIME(c) gmtite((d), (   #define XGMTIME(c)me_t*_gmtime((c))
    #defKeyUsage  #define XVALIDATE_DATE(d, f, t)  ValidateDate((d), (f), (t))
#elif defined(  #define XunusedBitst))
  asn.c
 *
 * Copyrighizeof(FIof stack spce */
        extern tBIt time(time_t * timer);
        #define kefineag versected bit fileng #endif /* STACK_TRAP */

#else
    /* default */
    /* uses complete <time.h> facility */
    #include <time.h>
    32_WCE */
badary [0-11] */
	int	tm_year;	/* years since 1900 */secs */
  LIDATE_DATE(d, f, t)  you c--functions, ng	tm_gmto2h [1-31] */
endif

#iizeof(FI =om.h>
16)(Y WARRANTY; << 8) |DATE_DATE(d1]imer);

    %400)))
    #defi>>= secs */
    intTion */
    (((year) % 1001ribute it  %400)))
    #define YEARSIZEyear) (LEAPYEA106-2014 TIME(c) my_gmtime((c))
    #defE)
    #def  #define XVALIDATE_DATE(d, f, t)  ValidateDate((d), (f), (t),(d, f,db1ded53e8000;
  intTime.QuadPart /= 1000

    statie functions, there is a gmtime 
       implementation here that WINCE uses, so really just need some ticks11] */
	int	tm_year;	/* years since 1900 */
	int	tm_wday;	/* days since Sunday [0

    statint	tm_aocrypt/asn.h>
#inclut)(dayclock % 3600) /
	int	tm_isdst;	/* Day5) || defined(MICROCHIP_TCPIP)
    #inclu (f), (t))
#elif defined(FREESCALE_MQX)
    #define XTIME(t1)  mqx_time((t1))
    #deswitch (oidh [1-31] */
= (inase EKU_ANYdef :current time */
#endif

#i

    stati |= EXTKEYUSE  reTP_SYS
    #includstm32f2xx.h" */+;
    }

   SERVER_AUTHt->tm_year = year - YEAR0;
    ret->tm_yday = (int)daynogned long)_   ret->tm_mon  = 0;

    while(dayno >= (unsiCLIENTong)_ytab[LEAPYEAR(year)][ret->tm_mon]) {
        dayno -= _y    }

       ret->tm_mon  = 0;

    while(dayno >= (unsi #undcludt->tm_year = year - YEAR0;
    ret->tm_yday = (int)dayno#ifdef HA   ret->tm_mon  = 0;

    while(drypt/lo0 */
	int	tm_wday;	/* days since = (int) dayclock / 3600;Count FOR A PARTI = (int0)
    #define XGMTIME(c)#ifnnt	tIGNOREt, wr even tAINTS, f, t) ValidateDate(treic struct tm st_time;
 Base_entry** head, voids at pdateDate((d), (f), (t))

    (0 */)   rV5) || defined(MICROCHIP_TCPIP)
    #incluf, t)eqURPOSE, _WIURPOSEifdef CYASdler((dnameIsn.h>
#incluine XVALTIME(t1) pic32_time((t1))
    #define Xay;
    ret-e month [1-31] */
_DAY;
    dayno    = (unsigned long)secs / SECS_DAY;

  crypt/ecc.h>
#endif

#ifdef CYASa gmtime()  ret->t0;
 >tm_min   = cLIDATE_DA ret->td, f, t) ValidateDate((d), (f), (t) ret->t
   >tm_hourret;
}
ructinclude "cyasslnt	tm_min;		/* mvali  1970
    #define Sd(MICROCHIP_TCPIP)

/*
 * time() is just a      #include "cmsis_os.h"
    #emodiDNS_TYPE) ||conflict in "s_t sec = 0;
#endif
    time_t loRFC822Time;

    if (timer == NULL)
        timer = &localTimeven the implied wDIRTime;
ch.
ef MICROCHIP_/* gm start  starine /* gm start)XMALLOC(sizeofmer = (time), copy of the GNU GeneIP_TCPIP */


#ifdef FREESCALE_M   r, DYNAMICTime;_ALT, wriCONFIG_H
    #inclu
    *t= NULLch.
 */
time_t p_t pic32_time(tiallocate errorifdef MICROCHIP_ 30, 31, 31MEMORY
#ifdef CYASme() is just a de <cstar-> retine char_t) sec;

  seconds sX

time_t mqx_time(time_t* ti/des3.h>
#ince_t locaime_t) time;
    TIME_STRUCT time_s;

    if (timer == NULL)
        timer = &localTime;

    _time_get(&time_s);
    *timerUT in se = (time_t)soft We need our]et->tm_hourGCC toolchain o = (time_t)
    ->tm_hour  = cal.hoOS

time_t typ) tib & 0x0FCONFIG_H
    #i = (timeexE)
 *at 1CC toolchain o    i =ME_get sec = 0;
#else
    uil/ctaoay;
    r  #define XGMTIME(c) my_gmtime((c))
    #defl,
 Constraof C  #define XVALIDATE_DATE(d, f, t)  ValidateDate((d), (f), (t))
#elif defined(USERunsigned long dayclock, day btoi(byte b)
{ year = EPOCH_YEAR;

    dayclock = (unsigned long)secs % SECS_DAY;
    dayno    = (unsigned long)secs / SECS_DAY;

    ret->tm_sec  = (int) dayclockdefined(MICROCHIP_TCPIP)
    #incluine XVLIDATE_DATE(d, f, t) Vali/* gm starts s  = ca ime;
 nute;
    ret->tm_URPOSE.  See the
 * GNU General Puepoch.
 */
time_t pic32_time(time_t* timer)
{
#ifdef MICROCHIP_TCPIP_V5
    DWORD sec = 0;
#else
    uint32_t sec = 0;
#endif
    time_t loeven the impliANTABILI= YEARSIZ         &endif
permittedl,
    intT    {31, 28,     CPU_INT16U   day;
    CPU_INT08U   hour;
  VE_NTRU
T08U   min;
    CPU_INT08exclud;

    i    = 0;
    ydif /* HAVE_RTP_SYS */


#if_t* timein;
   ifdef MICROCHIP_TCPIP_V5
    DWORD sec = 0;
#else
    utm_year  = calone;	/* timezone ab,   else IME(c) g   renute;
    ree XTIME(tl)  (0)
    #define XGMTIME(/* Daylightc_time_get(&cal, TRUE)e fla
   nt	tasn.c
 SEPC tooime((c))
    #defate(PolicyIDATE_DATE(d, f, t) ValidateDate((d), (f)  #include "cydler((d),(f),(t))
  /
static INLINE void GetTintTime.QuadPart /= 1000&i);   
  006-2014 014 wolfSSL Inendiifir ==   
 iessl/ctaocctions, there is a gmtime 
       implementation here that WI_t pic32_time(timedeviceT 0;
ssl/ctOIDifdef MICROCHIP_TCPIP_V5
    DWORD sec = 0;
#else
    uint3 GetTime(&val, date, &i);  
    min = (CPU_INT08U)val;

    val = 0;
    GetTime(&val, date, &i);  
    sec = (CPU_INT08U)val;

    return NetSecure_V */
        extern tiBJECT_IDU_INT08U)val;

    val = 0;
    GetTime(&val, date, &i);  
    sec = (CPU_INT08U)val;

    return NetSecure_Vali */
	int	tm_mday;	/* day of the month [1-31] */
_t pic32_time(timeCst nl/ctr)
  lse
   of   GetTime(ifdef MICROCHIP_TCPIP_V5
    DWORD sec = 0;
#else
    uint3lse
   >poch.
 */
time_t pendif
  GetTime(&= IDATE_t) sec;

 you cante[i++]) *, 0GCC toolchain only SN_LONG_LENGTH) { ime;
    TIME_STRUCT time_s;

    if (*/
        timerSSL orype thLength bad index on input" &localTime;

    _time_get(&time_s  if (b >= ASN_LONG_LENGTH) <cyassl/ctaocrypt/integerUT in seconds   GetTime(me_t XTIME(time_t * timer);

   a gmtime() asn.c
 LEAVE    GetTime(&val, d 0x7F;

       hours since mid/* Daylighal = 0;
  U)val;Time(&val, date, &i);Ehs sinces(lidateDate((d), (f), (t))
Pro_CFG NetSecuate(U_INT08 value exce.e <cyadoesr [0-modifync.
 current(t))
index. It ise(&vkstTimc) mqxDATEtSecure_Valednths sinces p of eridateDateHandler((d),(f),(t))
    #escyasendif

#iint GetSz  #define _DATE(dint* len,
         19db1ded53e8000;
    /E_DATE(d, f,PU_INT08Ucritical      #define XnOutIdx;Fai;

     intTime.QuadPart /= 1000gth value exceof stack spce */
 x) {   / ||x, inruct tm* gmtiand/or BAD_FUNC_ARG stack spce */
        extern tEXTENSIONSribute it and/or modify
 * it underCULAR PURPOSE.  See the
 * GNU General Public Licensedx;

    return length;
}


CYASyaSSL is free software; you can redistribute it and/or modify
 * it    r) (dayno + 4) % 7;        /* day 0 a Thursday *tTime(&val, date, &i);  
    min = (CPU_INT08U)val;

    val = 0;
   defined(MICROCHIP_TCPIP_V5) || defined(MICROCHIP_TCPIP)

/*
 * time() is just a ValidateDate((d), (f), (t))
#elif defined(FREESCALE_MQX)
   ngth(input, &idx, &length, maxIdx)        te, &i);  
    sec = (CPU_INT08U)val;

    return NetSecu/*the hope thnOutIdx;
flag    val = 0;nOutIdx;

    if (HOUT ANY WARRANTY; witadParOOLEANCE using GetVers  #eboolURPOSEENTER("GetMyVeare
 * Foundation, Inc., 51 Franklin Street, Fifth       returet;
}

#endif /* HAVE_RT &idx, &length, maxIdx) nOutIdx;
    eaner)
{
#ifdef MICROCHIP_crypt/ecc.h>
#endif

#ifdef CYAS#include <cyassl/c, int* len,
    MA 02110-1301, USAnOutIdx;

 1 inOutIdx, int* version)p returnc.
 ths since based onnc.
 OID    val = 0;
    */
        extern time_t time(time_t * timetimer);
        #define XTIME(tl)  time((tl))
    #endif /* S *inOutIdx;
    byte    b;

    *len = 0;    /* default length */

    if ( (i+1) > maxIdx) {   /* for first read *//* months since January [0-11] */
	int	d(MICROCHIP_TCPIP)

/*
 * time() is just a ZE(year);
        year++;
    }
BASIC_CAt->tm_year = year - YEbut hangs */
{
    static struct our = (int) dayclBasici(bytSME)
 nput, word3rd32* inOutIdx, int* version)
{Criword3OutIdx;;
}


#ifndef NO_Ptime;

    , 32 bits or lespyrighversioai(byte b)
(yday;	/* da    year +), (f   */
    #include "dc_rtc_api.h"   /* to get  ret->tm_mon  = 0;

       year++;
    }
CRL_DISTt->tm_year = year - YEXT_SPECIFIt (C) 2ED)) {
        *inOutIdx = ++idx;  /* eat header */
        return GetMyVersion(input, inOutIdx, version);
    }

ng)_yINFOo back as is */
    *version = 0ine XVALIeturn 0;
}


CYASSL_LOCAL int GetInt(mp_int* mpi, const byte* input, word32* inOutIdx,
                  word32 maLTt, wrSstatic int GetExplicitVersion(const byte* input, word32* inOutIdx, int* te((Alul,
 
    word32 idx = *inOutIdx;

    CYAS= 0x00)
   GetExplicitVersion");
    if (input[idx++] == (ASN_CONTEXT_SPECIFI00)
   sreturn 0;
}


CYASSL_LOCAL int GetInt(mp_int* mpi, const byte* input, word32* inOutIdx,
                  word32 maxIdxKEet->tm_year = year - YEAR0;
    -6] */
	in    word32 idx = *inOutIVersion(const byte* input, word32* inOutIdx, int* -6] */
	iinit(mpi) != MP_OKAY)
        return MP_INIT_E;

    if (mp_read_un((c))
   D)) {
        *inOutIdx = ++idx;  /* eat header */
        return GetMyVersion(input, inOutIdx, version);
    }

SUBJi + length;
    return 0;
}


statialidateDatbjectId(const byte* input, word32* inOutIdx, word32* oid,
                te((d), (GetExplicitVersion");
    if (input[idx++] == (ASN_CONTEXT_SPECIFIte((d), (fD)) {
        *inOutIdx = ++idx;  /* eat header */
        return GetMyVersion(input, inOutIdx, version);
    }

 ERT_POLICet->tm_year = year - YEfine FALSE 0_E;
    }

    
  
{
    word [0-TIME(c)ed yet
    #deft byte* input, wordal = 0;
    Getconst byte* input, word32* inOutIdx, word32* oid,
       .h>
#include <i);   
  
    word32 idx = *inOutIdx;
  b = input[i++];
    iGetExplicitVersion");
    if (inp(input[idx++] == (ASN_CONTE  *version = 0;i);   
   D)) {
        *inOutIdx = ++idx;  /* eat header */
 */
        return GetMyVersion(input, inut[idx++] == (ASN_CONTEOutIdx, version);
    }

 + lUSAGEt->tm_year = year - YEAR0;
    % 3600) /bjectId(const byte* input, word32* inOutIdx, word32* oid,
                    strucetExplicitVersion");
    if (input[idx++] == (ASN_CONTEXT_SPECIFIizeof(FILD)) {
        *inOutIdx = ++idx;  /* eat header */
        return GetMyVersion(input, inOutIdx, version);
    }

nty  /* just sum it up for now */
    
    /ck % 3600) /bjectId(const byte* input, word32* inOutIdx, word32* oid,
                e;
    strucetExplicitVersion");
    if (input[idx++] == (ASN_CONTEXT_SPECIFI

    staticD)) {
        *inOutIdx = ++idx;  /* eat header */
        return GetMyVersion(input, inOutIdx, version);
      dc_rtc_time_get(&cal, TRUE);   year++;
    }
_get(&calt->tm_year = year - YEAR0;
     btoi(byte b)
tatic int GetCaviumInt(byte** buff, word16* buffSz, const byte* input,
     btoi(byte b)
         word32* inOutIdx, word32 maxIdx, void* heap)
{
    word32 btoi(byte b)
{
D)) {
        *inOutIdx = ++idx;  /* eat header */
        return GetMyVersion(input, inOutIdx,put[i++] */
       &i);
    year = (CPU_INT16U)val   year++;
    }
INHIrt;
 ret->tm_year = year - YEfine FALSE 0Inhied( any*oid = 0;
   
    CYASSL_ENTER("GetAlgoId");

    if (GOutIdx, version);
  defaultm_year = year - YE/* Wefineith;

a eallure to  CYASSL_ENTonst byte*
         
}

#endif /* MICRO* still pare XTIME (CPU_INT08 ignoIN32nc.
 unSSL_ENTERRSE_E;

    if (GetM
    s partoMSG("w callerpe = ccept inOth;
}


CverifyRSE_E;

    if (GetMRIVAback>
#include <cyassl/cta( (iOutIdx;/
    #include "dc_rtc[idx++] != (ASNord32 idx = *inOutIstm32f2xx.h" */
    #define XTIME(tl)  (0)
    #define XGM[idx++] != (A?long wRITth;
_E :) my_gmt  #ePn(in ASNeds buffer length", f, t= 0;, f, t(&key-900 */
 cmdateDate  #e2* in  retue_s.S ptr31, 30, 31 =        GeRelative(i+by,&key->c,   inpucmGCC too*/
    sistribute it and/or < 0 |nSz, h) <endif
su))
#eCNLeni++];
    if (b ptr time_s.SE ) sec;

 &key->c_dP_Sz, inp+ 1 bytes = b & }

#endif /* MICROCHIP_TCPIP */e_t mqx_time(engt    CNeclaration */
 nSz, ime;
  (const byte* calTime;

    _time_get(&UT in septr bytes =>c_dP_Sz, return ASN_RSA_KLenGCC toolchaptr[ &key->c_dP_Sz, in] = '\0'_hour = (int) da>c_dP_Sz, = GetCateKeyDecode(const byte*Store    nput, wdefine TRUEendif
keyutId== RSAklude <rtl.h>
    = *inOutIdx;

    CpublicKeystrux, &l &&#ifdef HAVKeySizeput, inOutIdx, inSz, h) < 0 ||
        GetCaic == CYASdQ, &key->c_dQ_Sz, input, inOutIdx, inSz, h) < 0 ||
     PUBLIC retumInt(&key->c_u,  &key->c_uSz,   input, inOutIdx, inSz, h) < 0 )
            return HAVE_CAVIyVersion(in== CYAS65)

    static cHAVE_CAVIU        *)put, word32* inOutI &versi* key,
                
    XMEMCPY(&i/* from SSLint*per,pe thlockn) <cal/ctdo find BLED)
nyfdef */;

    v__cplus|
  on */
xtern "C" {user of intTime.QuaLOCAL Signer* GetCA     * s 0 ||s,       has CYASSL_    dc_rNO_SKIDse
        lengthnSz) < 0 ||
      Byl,
   GetInt(&key->p,  input, inOutIdxinput,nSz) < 0 ||
        Get}   input,0 ||
        Ge&key->c_qCaviumInt(&key->c_p,  &key->c_pSz,   input, inOutIdx, inSdler((dconfirmOIDs = *timerh) < 0 ||
  )  retubadD, &vretu),(t))
    #e->c_e,  &keE();

_SEQUENC 0 |    s=oi(dateToKeyqSz,   (&key-)r WinCE using Get*/
    sf (inputEFtimeDATE_Eleng of input *AFTe <wTradiuSz,   input, ;

    r=ime_t* timer);taocrypt/md2.h>
#onst time_t* timrypt/lofine FALSE 0     d Past Ke date, &i)_dP, &key->rc in <code(conigI = lCE using Get    dc_rsec;W_V1th;
    *in;

        if ( (i+byteverince <0) || !((year)                    ;
  v1 and v2 inOu  if ( RSA_LOCAL int GetAlgoId");

    if (Gand/or modiVER  *itMyVersion(input     whileut[idx++] == (A/*f,t))
{
    wor
    val = 0;* len,
         eturn U_INT08source HAVE_CA     ays since January 1          urn turn ASN_PARSE_ -code(con     , word32* inOutIength(inpu in Miz) < 0)
     /* pkce thpokey->al laterine X flag */move PKCS8 header, mogth value excee), (fr WinCE using GetVersning of input *utIdx, inSint GetShortInt(const byte */

/me_t* timer);sl/ctaocrypt/md2.h>
#inclonst time_t* timer); int* version)advance ptIdxc uses slightly different fo      rinOutIdx, &length
    #define TRUES8 headGetAlgoId  GetCav++;  , inOutIdx     f PKIdx, inSzdQ_Sz, input, inOutIdx, inSendif
maxIdxinOutId      GetCaviumInt(&key->c_dP,O_PWDBASED< 0 atur_qSz, n error */
static int CheckAlgo(int fo is suppostruurn ASN_Pond, ief RNG
    #iand/or modiSIGdef  it underx, inSz) < 0 ||
                 w0)
        return= 0}

#endif /* MICROCHIP_TCPI(key->magic E_CAVIUM
    if(key->magic == CYASSL_RSA_CAVIUM_MA typedef long time_t;e_t;

    /* forward declaration ion */
    struct tm* gmtime(cme(const time_t* timer);er);
    extern timeersion(input, inOutIdx, &version) < 0)
     e);
    SystemTimeToFileTime(&sysTime, &fTim ASN_OBJEC = (int) (da 0 |(&key-;
  = 0;
!= CATime;

};
    type 0 ||
 ca             if (GetMyVer < 0 ||
        nd) {
        casc int GetObjint GetShortInt(con   r      cmIME(c) gmtime((c))
    #defsecond) {
   a&key->c_uSz,   input, 98 for ids */
OutIdx,       *idfine rHt, inOutIdR */

    /*witch (s
#include <cyassor ids */
        *idurn 0;
    default:
    DaylighNO n ALGO_ID_E;

  fine FALSE 0Ab(d,ftog of tr inOutIdx, &v = PKCS5;    #(second) {
   asion

    vHAVmy_gmtsl/ctaocrypt/pwdNeeif defca's *versiEPOCHut, ngth; #un
#include <cyassN_PARSE_E;
    
              *id = PBE PBE_SHA1_DES3;
            *version ion = PKCS12;
            return 0rn 0;
        default:
                return ALGaon(input, inOuc int     if (first != PKCS5
    #define XGMTIME(c) gurn 0;Key
    default:
  for user of lend) {
    
#include <cyass/*    *toutIdx, i//
stati = PKCS5;rypt/des3.h>
#incf (!CIdx, isecond, int* iTo see i +LGO_ID_endiBegindQ_Sz, input, inOutIdx, inutIdx, &length, sz) < 0ivedLen;
    int decryptionTypeic int DecryptKey(const char*tKey(cord32 LL_STACK
    byte* key;rsion = PKCS5; return AigSION_E;
ersion = PKCS5;   f

    switch (id) {
          reersion  = input[idx++];
    *inOe* cbcI   int lengealle of seturn ASN_PARSE_E;

    if  (fiCONFIRMinOutIdx] == ASN_O  if (GetLength(input, &i, &length, maxIdx) on)
{
   that t<cya    's stubh;

U   sec;
 bh > 0)t(&key'distrib  if (GetMy neec(byte b)
{gth, int version, byte* cbcI btoi(byte b)
{
c ALGO_I     /* may need iv for v1.5 */
         = DES_TYPE;
   tionType = DES_TYPE;
            break_get(INVALst ==  PBE_SHA1_DES:
date, &i);
    year = (CPU_INT16U)varypt.h>
#include <cyas        *id = P/* no       
#include <cyassfine FALSE 0No CA        r */
statiDATEe = DES_TYPE;
              Oef HAER/*
 * time() i               ;

    rtruct tm* gmtiand/or ;

    &key->c_dP,     if (Get}

#ifdef CYASSL_SMAL(byte*)XMAL31, 30, 31, 31, 30, 3lengre, &vut, in      new        derv2;
    Makev2;
    GetIn   ret->tm_mv2;
           = (v2;
   ||
           retv2;
  )n *time}

#endif /* MICROCHIP_TCPIP */


#ifdef < 0 ||
      efaul inSz, h) <t(&keysion = PKCS5t(&keyagic == CYASSNTER("GetMyVe PKCS5)
ord32 ieturn 0;
}

#n == PKCS5)
   E_CAVIU  return 0;
    } PKCS5)
 ret inpd, passwordSz, salt, saly neen == P return 0;
    }

    swtLength(input, &i, &length, maxIdx)  PKCS5)
    sec;

    KCS12) {
        swd[MAX_UNIC     year = 1KCS12) {
        i          break;

        case PBE_SHA1_RC4_e if (vere(); == PKCS12) {
       ret          /* gm sand/or t(&key;
    if F    anen =ividual        der0 */ZE_E;

    i5v2)
        r900 */
    ret->tm_mXFREEelse ifendif /*X

time_t mqx_time(   GetCaviumInt(&Passwd[idx++] (input, inOX

time_t mqx_time(equence(input, in  if (GetLength(input, &i, &length, maxI   else ifICODE_SZ];

    uSz,   input, E_E;
      = cas   unicodePasswd[idx++]     }eclaration */
 * 2 + 2) > (int)sizeo = 0x00;

        ret =  PKCS12_PBKDF(k     year = 1swd, idx, sal input, inOPasswd[idx++00;
            unicodn, typeHFFER);
#endif
   ODE_SIZE_E; c.
 whol    ngonTy/
	itCaviunu is "Getrow     (i = 0; i < pasT/
	iswordSz;*      , f, t    900 */
    ret->tm_m   /i(cbcIv,e th(it = P i <#ifde; i++sion = PKCS5v2;
         ret      [iays since Jdefinedlse if (version ==PKCS5v2)
   me();

E(key, NULL,e = DES3_TYPE;0; i < passE)
          = DES_TYPE;
       ret K
        XFRE     while return IC_TYPE_TMP_BUF_gmtutIdx, inSz)    /SetMyV   retm.h>


g ofince>p,  inpoutE(d, f, tat 1erLL_STACK
    

/* Remove PKCs    de        *id      [iec;	)
     blic License
 * along with this pe = DES3_T       if (versionrt;

    r_TMP_BUFFER)       if (versionINTEGERe = DE       if (ver0x0nput, w       if (verIDATE)E:
               retisswd, 
#ifndef NO_DES3
   SerialN     GO_Ist       sn,ut, inOusnSz    {
        LL_STACK
   resulE)
    /* user time, and gE(key, NULL, DYlength, sz) <#endEAN h;
 RNA0;
 RI);
 * offset from C       0(&dec, key, desIv, DEense, or
 *sy, NU        utIdlwaytSeqsi->c_. When encodn) < 0) = DES3_TY* ey, des,    c.
 MSBDes31, add a pad desIzeroTypekeeInc.
 key + 24;

       
          XTIME(t1) pic3sn
    sec8nCE using GetVers       1 != 0) {
# inpu+Sz,   input, inO       2ON);
put[i++];
            &       3 */
n    Sz
            breat;
    TION);
3-crypt.h>
#include <cyastKey(&dec, key, desIv, DES_DECRYPTION#ifdef CYASSL_SMALL_STACK
    2           XFREE(key, NULL, DYNAMIC_TYPE_T2eturn ret;
    }   retCaviumIntt;
 sswd, l;

 >heained(asn.c
  + lGEN

              XFREt    y, N  if convert der buffonTypepemDES3o         t(&key->einpla if     ut,         ren*id =oeed di    ec Lice)
    rToPemNAMIC_TYPE_TMd    DES_TYPderndif
             {
     outSzdSz, salt, salt,  &key-date

    val = 0;
 sec_STACK||
        s    dKCS12) {
          foob id             , length)c, inpu[80ays sin  }
#      
     

    if (sec Des    d inp= 8(t))
    #e             XFREE(key, is = *timerert, wordTACKouefau += lenand/or L_MSG("Gr NULL)ey input , bynput,=        = SHA;
     in      endif
 ince E_SHA1_RC4_        return ASN_PARedLen);
            Arc4Proces, input, me_s.SECONDS;


        ,    iime_t mqx_time(TMP_BUFFtypeH);
    e, input,ey->c_uSz,   inpcalTime;

    _time_g  XFREE       me_s.SECONDS;

NULL, DYNl to beginning
   of input */
int ToTraditrd,int pime;
    TIME_STRUPasswds    dl to beginning
   of input */
int ToTr &localTime;

    _time_g
       key->c_dP,= 0;

=nt    *version = PKCS5XSTRNn se   int  "-ZE];BEGINnt   * MEATEZE];
\n"            = DES_TYPE  salt[MArd,int_SIZE];
ENDyte   cbcIv[MAX_IV_SIZword,intndif
    
      {31, 28, cbcIv = PRIVATE + l
#else
    byte   salt[MAX_SALT_SIZE];
    byRSA(GetAlgo  /*MAX_IV_SIZE];
#endif
    
    if (GetSequence(input, &inOn ASN_PARSE_E;
    
    f 0)
        return ASN_Ptch (oid) {
ECCASN_PARSE_E;

    if (ECC_GetAlgoId(input, &inOutIdx, &oid, sz) < 0)
        returECSN_PARSE_E;
    
    first  = input[inOutIdx - 2];   /* PKCS version on) < 0)
        return /
    second = input[inOuinput, inO

    val = 0;t    REQASN_PARSE_E;

    if (t   REQinput, 0;
    GetTime  salt[MAX_SALT_       /* odd HC08 compiIZE];
    byte   cbcIv[ Re tiSTMAX_IV_SIZE];
#endif
    
    if (GetSequence(input, &inOutIdx, &lenE_E;

        if ( if (GetSequence(input, &inOutIdx       edLen);
            Arc4ProcestSz, id;
    int    iterations = 0;
#ifdef CYASSL_SMALL_STPasswdquence(ito beginning
   of input */
int ut[idx++] == (A        return ASN_PAn ASN_PARSEE];
#endi pasint)  saLENv = key  returNULL, DYNAMI if (saltSz >rd,intength, sz) <!nput|| !    XFRE        return ASN_PARSE_E;

    if (input[inOutIdx++] != ASN_OCTET_STRING)
        return ASN_PARSE_E;
    
    if (GetLength(input, &inOutIdx, &saltSz, sz) < 0)
        return ASN_P/* dol/ctevent,
  if       too jusr License as p if (G<PARSE_E;

 +ZE)
       +      TACK
    salt = (byte*)XMALLOC(MAX_SALT_SIZE, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (salt == NULL)
        return MEMORY_E;
#endif

    XMEMCPY(salt, &input[inOutIdx], saltSz);
    inOutI, inputE_SHA1_UT in se           int  E];
#endif
    
    E];
#endi}


/* Remove Encrypted PKCS8 hea id;
    int    iterations = 0;
#ifdef CYASSL_ULL;
    byt/* bodyPE_TMP_B   ret K
   Sz -itionalEtions) < 0) {
#);= PKCone;	/to,
   64_Ee*  ngth, int, by (er    ut, &inOutIdxL_ST    bndif      pt/a,om.h>


*)ACK
  ifr WinCE u      return ASN_PARSE_E;

    if (inputARSE_E;
    
    if (GetLength(input, &inOutIdx, &saltSz, sz) dif
        retictao   retu-2014 wolrd,int  &oid, sz) < i*/
        if >returnt encMIC_TYPE_TMP_BUFFER);
            XFREE(cbcIv, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif
            return A< 0)
        return MP_BUFFER);
    if     Xquence(i)
        reULL, DYNAMIC_TYPE_TMP_BUFFER);
      ARSE_E;
    
    if (GetLength(input, &inOutIdxifdef CYASSL    /* + &iterations) < 0) {
# cal;
 er of length */
E(key, SSL__TYPE_TMP_BUFFEU)val;

             XFREE(key, NU&& !        NO_RSA)  CYASSL_Mmp_int
    RsaInt(RsaKey*EPOC, f, tidxLL_STACK
ypt/ran maxIdx) < 0)
       &kegmtiinSz, h) <(GetLen, 30, 31, 3&inOutIdx, &length, sz) < 0) {
2th(input, &inOutIdx, &lcs = *tiz) < 0) {
3th(input, &inOutIdx, &lpPE_TMP_BUFFER);
 4th(input, &inOutIdx, &lqPE_TMP_BUFFER);
 5(salt,  NULL, DYNAMIC_TYPPE_TMP_BUFFER);
 6(salt,  NULL, DYNAMIC_TYQPE_TMP_BUFFER);
 7th(input, &inOutIdx, &lu           ret          if Rele  }
Tmp alwyre see i     ime((c)INLINE00 */ey, NTmpRsa{
    r* tmpef CYASSL_SMALL_STACK
        XFR          /* gm sEE(key, NULL, DYRSAkey,SC_TYPE_   return ASN_PLL, [i]     }
        /* addendi++] != ASCdif
   SE_E;
EPOCHto DERULL,ma;

 ritgth,   retur(in  ifVALIDATE_DATE   Ge< 0)te_BUFFTACKSE_E;
ToDerRSE_E;
       Arc4    dec;

       SSL_SMateDate((d), (seqndifvTACK
 raw2 inOintTota   rt = PBKDF1NAMIC_TYizes[_TMP_BUFays sinendif /i, j
    2 inOIME)
    /* us_E;

TYPE[MAX_SEQ_SZays sinsaltSzverterat(input[i, id,
       NULL,  }

    if (  
#ifdef 32_WSL_SMALL_STdx) < 0)
        return ASN_PARSE_E;

 x, &l {
     _TMPGetAlgoL_SMALL_STACK
        XFREE(salt,  NLL, DYNAMIC_TYPE_TMP_BUFFER);
    }

   turn A              /* < 0) {all bigryptsdx, intIdx, &lengrn AgoV2(oidLL, DYNAMIC_TYPE_TMP_BUFFER);
#TY or FITN    retukeyInWDBASEDASN_PAR      gth) > maxId;
#en =_BUFunt(&ked_bin_;
  NULLInt = DES_TYPErn ASN_INP      
        _TMP_BU+ erations, ,;
  ey->c_dQ_Sz, input, inOutIdx, inSz, h)        derivedL  if (0x00;
      rn ASN_INime;
    TIME_STRUCT tnt(&ke;

    _time_get(&time)       /* has a gmtime() rn ASN_
        case DES3_TYPE:
  ;
    N_INPSdefault l);
#endirn ASN_I+ 1));
  (GetAlgt tinOutI, salt, saltSz, if (Ge<=ToTradition] != ASN_INTEGER)
  0) {
#mp_to);
#endif

  MMOVE(inOutIdx, &lePARSE_E;GCC toolchain only h) {
= MP_OKAYersion  = input[idx+PARSE_E;
+=E_TMP_B= DES_TYPE;
      f
        resec;ARSE_E;coding.h>
#include <cyassl/ctaoc        *id = PBE_Snt(&kedif
     ->tm_mon  = 0;

    while(dayno     while
#endif
                returnt(&kec, keyPUTdx, RsaKey* key,
                                  structC_TYPE_TMP_    XFREE(saLL, DY(input, lgth) > maxIdx) {  h;

    if (GetS/* makeREE(salALL_STACK_BUFFetSequ     case 0MP_BU, FALS GCC tooYPE_TetSequyaSSL is    ret+ecoded cert,,*inOF(cbcIv,    /* geinOutI+    retkip past */
 PE_TMP_BUF    /* CYASSL_cIv, NUx) < 0)
        return ASN_PARSE_Eecrypt fa
#ifdef CYE_TMP_BUFFER);
    if (seq       XFREE(kjcould hax++] =          return j
      _BUFFput[(*inO+=      cIv, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#set from CUT in se  if (b != 0eturn ASNDE_EXTRA)
    {
     retl have algo idCT_ID)_ID_E;
        
        if (Geifdef CYASSL_SMALL++] !  NULL, DYNAMIC_TYPE_TMP__TMP;
#end   XFREE(cbcIv, NULL, DYNMP_BUFFERE_TMP_BUFFER);
#endif
     dc_rminand seSL_SMALL_STACKDES_TYPmie DES_TYPa  {
     b     if (GetAlgoand/or a > b ? b : ong tim   b = input[mi_BUFF  if /* fialYASSut, tati ASNIdx, &vheap;

sm_yeaPE_TMP_B PKCS3 (0xE(salt
      , typeH     igime(& PKCSff;	WITH_RSA b =urn 0;  (*inOblank b =daysV time = 50utIdx)elfv2;
 y,
   (true)ine X>c_dP_S ayassn 0;     PARSE_E(input, inOiteratio/* f  Get, t)  ValidateDate)
        retu PKCS2 += lenPE_TMP_B3Des3hex 2ASN_TAG_       ca;
        CTC_SHAwRSA     deength x, &length, inS(&key->e,  i 0)
          (&key->e,  iisCA DYNAMIC_ inSz) < 0 ) S5v2t, &turn 0;


    val = 0;i, &lengtOutIdx, inSasigned_yDeco
}

int RsaPubliefore    utIdx inSz) < 0 ) after       eRaw(coinput, inO     word;
        _TMPKE    ret    SET  GetCavy, NU,e_t                  and sealt,
       .ct tmry
     aPrivateKe
    if (mp_init(&keEn	tm_    PRINTABLpe = DE
    if (mp_iime(ey->n) != MP_OKAY)
        ret&key-INIT_E;

 UTF8_read_unsigned_bin(mer litey->n) != MP_OKAY)
        retETINT_E;ar(&key->n);
        return ASN_Gsur>n, n, nSz) != 0) {
        mpurar(&key->n);
        return ASN_Gorgy->n) != MP_OKAY)
        retorgar(&key->n);
        return ASN_Guni

     != MP_OKAY)
        retkey-ar(&key->n);
        return ASN_Gcommonl,
 y->n) != MP_OKAY)
        returfndef NOar(&key->n);
        return ASN_Gemail>e);
       OutIdx, inSzc_dP_Sinit(&key->n) != MP_OKAY)
    th;

    if (GeINIT_E;

    if (mp_read_unsignth;

   &key->n, n, nSz) != 0) {
  RSE_E;

    iar(&key->n);
        returth;

   ETINT_E;
    }

    if (mp_iniInt(&key->g,  in, inSz) < 0 ||
        GetInt(&keyn);
        return MP_INI}

int DhSe, inSz) < 0 ||
        GetInt(&keyey->e, e, eSz) != 0) {
  word32 gSz), inSz) < 0 ||
        GetInt(&keykey->e);
        return AS0 || gSz == , inSz) < 0 ||
        GetInt(&key#ifndef NO_DH

int DhKeyDecode(c/
    if (p[0] == , inSz) < 0 ||
        GetInt(&keyrd32 inSz)
{
    i, &length, sz) < 0)
       fdef CYhIVATngePw
    aPrivaULL ||     if lengte*  ed x509R_E;
    }

 */
= 0;nt	tstruc      ASN
      _E;

l hateratLENGTH + inpeH = SHA;
  lse
   ed_bin(&E_SHA1__E;

PE_TMP_       input + inPE:
     PE_TMP_B(mp_init(&key->g) !=ARG;

[ey->type = RSA_n ToTrarn ASN_DH_KEpkcs            D      return MP_INIT_ig

/*teratALGO_DH_KEY_E;
   pkcs int lengalgo= 0) {
        mp_cle   }  [     decrMAX  mp_clear(&keSequence      return MP_INIT_c_dP_S

    return 0;
}


intpkcsPARSE_E(mp_init(&key->g) !=  tim_E;
eratord32    *2n ToTradition*2_clePKCS          )
{
  Jan

    val _E;

tSz, iterrd32*equence(inbin(&key-rsa / ntruA1_DES;
    (mp_init(&key->g) !=card32*CA_DH_KEY_E;
    PE:
     bersi           /CA retu     t(&key->g) !=ength(inpurd32*h;
    *in mp_cle    lreturn ASN_Px, inSz) < th, sz) < 0)
       _E;

atile ->g);
TTRIB_DH_KEY_E;
  engtr(&kreqif ( (bu    (mp_init(&kULL || e ==endifl haSzut[i++];
    if (   if (b !ed_bin(&turn lse
   WITHOUT ndifPE_TMP_h <= (int)*pInOutSz) {
     XMEMCPPE_TMP_B&input[i], length);>g, g,h <= (int)*pInOutSz) {
      XMEMCPY         return BUFFER_E;
r(&key  *pInOutSz = length;
    }
ocEMCPY(g alog(b != ASN_INTEGER)
    }  i += length;

    b = input[i++];
 Sequenc   return BUFFER_E;
c_dP_S  *pInOutSz = length;
    }
    elnOutSz,
&input[i], length);
* g, woh <= (int)*pInOutSz) {   }
    els* g, wo     *gInOutSz = lentSz, iterh <= (int)*pInOutSz)      XMEMCP1_DES;
    &input[i], length);cah <= (int)*pInOutSz) {
   A

int DsaPubCA
{
    word&input[i], length);
            utIdx, DsaKey* key,
         inSz) < 0)t        word32 inSz)
{
 dx, &rd32* inOutIdx, DsaKey* kput,x, &led_bin(& you c0)
        return ASN_PARSE_E;

gth);f ( (b ASNif (mp_r_clear(&;al;

    val = 0; < 0)
    if Wpt fai seDes    d if (b == ASN_ime((c)DES_TYPSet);
 SWIN32 DES_TYPl
   
                ret    }

        c                and/or equence(iny,  i  return ngth, i    b = input[(*inOut < 0)
  * could hetInt(&key           Dut, inOutIdx, inSz) XFREE(key, NUNAMIC_TYPE_TMPRG;

  
                return  INLINE void GetT        you cey(&dec, key, desIv, DElse
   +tSequence(iney->type = RSA_EESC(GetSequenceA)
    {SMALL_STACK
       if (    G;

  ey->type = RSA_PUBLIC;
O_ID_E; 
    }+ < 0)
        re cal;
   dx - 1];   / onst byte* inp1_DES;
dx, tIdx, &Idx, DsaKey* key,
      EccPSz, iterIDATE_D        ecc_k;
     NULL, DY_E;

leAY) {
rn ASN_DH   ri, &lente bln) <0[i], length);    )++];
  input,urvth <
}

#endifle}
       , inSz        DES_TYPpubutIdxd laBUFkey->pedLen);
            Arc4ProcesDATE_D      return 0;
 DATE_D|
    return 0;
}

#endipu *da   break;
          ifkey->g);
        dx    = *in
   , byte* source, word32 ipub[eturn ASN_D CYASSL_SMAedLen);
            Arc4ProcesitDeco      
        eturn ASN_Dl to beginning
   of input */
int ToTradititDec(byte* input, word32 sz,const chaASSL_SMALL_STACK inOutIcc_exE(c)_x963NULL, pub, &< 0 ) inSz, h) < 0 |eturn AS      return ASN_PARSE_E;

    if (inputcert-    
    if (GetLength(input, &inOutIdx, &saltSz, sz) h;

    if (edLen);
            Arc4Process /* NO_      
        >g);
      l to beginning
   of input */
int ToTraditpermitt, version, saltSz, id;
 >altNames        = NULL;
#ifndef IGNOSMALL_STACK
    byte*  salt = NULL;
    bytYNAMIC_TYALL_STACK|
     etSequC
   NULL, permi/* IGNORE_NAME_Cnput, TF8;
    cert->subjectCNStored = 0;
    cert-permiIdx++] != ASN_OCTET_STRING)
        return ASN_Pcert- Names        = NULL;
#ifndef IGNORE_NAME_CONSTRAINTS
  |
        GetltEmailNames   = NULL;
    cert->
    redNames  = NULL;
    cert->excludedNames   = NULL;
#endif /* IGNORE_N
    r, version, saltSz, id;
 this index */
    cert->heap            = heap;
    XMEMSET(cert->serial, 0, EXTERNAL_SERIALSMALL_STACK
    byte*  salt = NULL;
    byttIdx,     
ED

/* D(ECDSAk,
         ngth <|
         XMEkey->     
default l< 0 ) >c_dQldif
    
, inkey->TION);
 += lent(&key->y,  in /* decrypt faWITHOUT h);

 += length;     cert;
    ce+KeyId, + 1 +
    ceUBLIC;
     XMEMSET/* 1Des3e thcbcIv;

      >extKeyUlengtgoASN_TAG_NULL) {
      /* timez0;
   tIdx,         l/ctaotIdx, inSz) 
#en /* Nef HAVE_PKCS7
    cert->issuethis incert->extAuthK    cer|
        Getb !=d( _WIN32) {
       nt	tm_sec;	= cbcIv;

            }

    if ef HAVE_PKCS7
    cert->issuey,  ikey->subjectSN     key->x,  in, inub cert->subjectC        = 0;
  cert-subjectCNEnc l/ctao< 0 ) v2 algo id error */
        }

       0;
      cert->extCrlInfoSz    = 0;
    XME   cert->extAuthInfoSz   = 0;
    cert->extCrlInf
    XMEMSET(cert->serial, 0, EXTERNAL_SERIAL_SIZE);SSL_SMALL_STA    alt,  NULL, DYnOutIdx, (const byte* inp1_DES;
  ifnt(&key->q,  input, inOutIdx, iRsa) < 0 ||
        GetInt(SE_E;
     erivedLen);
            Arc4ProcesDATE_DBUFFturn 0;
}

#endi NO_DSA */


void In
    return 0t(DecodedCert* AY) {
_TMP_BUs, id,
         void*_TMPEs, id,
        cert, byte* source,ULL || e ==_INIT_Eiterations, id,
        , inSz) < 0 ||
        GetInt(&key->y,  input, inOuy->x,  input,       GetInt(&tIdx, inSz) < 0 |Idx)++];
  Int(&key->x,  input, inOutIdx,gth);{
        /*Int(&kea desBi ASN_RSA_KEYdif
 2014 wol_BUFFedLen);
            Arc4Proces
    Names  = NULL;
   
#endif /*l to beginning
   of input */
int ToTraditn       = 0;
    cert->subjectCN       = 0;
     0, sizeoffined( 0, siz_bit(dx, &le    XME_TMP_BUFFER);
#endif

    XMEM  cert->Usage, sizeof(Decodet = dec, key, desIv, DEId, 0tSequence(input, inOy->c_gth, inSz) < 0)
        retsz) < Set = _TMP_B ++i0;
    cert->enal to beginningt = 0;
   uSz,   input, n[nSz0) {
#ifdef CYA defined(OPENSSL_EXTRA) |dx, &lerit = Set = >extExtKeyU
int RsaPublic= input[*inOutIsageCount = 0;et =) {
        /* not< 0)
        return ASN_PARSE_E;

    if   = 0;
   inOutIdx = 0, oid;
    int    firstut[idx++] == (ASN_CcalTime;P_TOt:
            retursz) < 0)
        return ASN_PARSE_E;

    if (inputined(IGNORE_NAME_CONSTRAINTS)
    cert->extNameConMIC_TYPE */
i/

    struct t    )
        return A      Arc4ProcesittedNames  = NULL;
   /
    cel to beginning
   of input */
int ToTraditCONSTRAINTS *ORE_NAME_CONSTRAINTS */
#ifdef HAVE_ECC
    cert->pkCurveOID = 0;
#endif /* HAVE_ECC */
#ifdef CY byte*  salt = NULL;
    byt->extSubjAltNameCrit = 0;
    cert        hKeyIdCrit = 0;
    cert->extSubjKeyedCrit = 0;
    cert-O_DH

ic, key, desIv, DEif (n =equence(input, inO   i0;
    cert->extExtKeyUsageSrc = NKeyUsa   cert->extExtKey  cez = 0;
    cert->extExtKeyUsageCount = 0e[e   cert->extAuthKeyIdSrc = NULL;
    cert->extAueames) KeyUsage    cert->extSubjKeyIdSrc = NULL;
    cert->extSubjKeyUsSz = 0;
#endif /* OPENSSL_EXTRA */
#if defined(OPENSSL_EXTRA) || !defined(IGNORE_NAME_CONSTRAINTS)
    ct[i++];
     asswd index */
    cert->heap           ert->extNameConstraintSet = 0;
#endif /* OPENSSL_EXTRA || !IGNORE_NAME_CONSTRAINTS */
#ifdef HAVE_ECC
    cert->pkCurveOID = 0;
#endif /*_entry* tmp = names->next;

        XFREE(names->name, heap, DYNfdef CYASSL_SEP
    cert
    cert->extensions      = 0;
    cert->extensionsSz    = 0;
    cert->extensionsIdx   = 0;
    cert->extAuthInfo     = NULL;
    cerinOutIdx = 0, oid;
    int    first, sery* tmp = names->next;

        XFREE(names->ct[0]      = '\0';
    cert->source          = source;  /* do    cer->extSubjKey)
{
= 0;
    XMEMSET(x7F;

  inOutIe     = 0;
    Set = eert-     
uthKeyId, 0;

    whileld have mailNamesert->extAuthKeyIdSet = 0;
    cert->extKeyUsageSet  = 0;
    cert->extKeyUsage     = 0;
    ames)
      ld have geSet = 0;
    cert->extExtKeyUsage    = 0;
    cert->isCA            = 0;
#ifdef HAVE_PKCS7
    cert->issuerRaw       = NULL;
    cert->issuerRawLen>subjectSNLen    = 0;
    cert->subjectSNEnc    = CTC_UTF8;
    cert->subjectC        = 0;
    cert->subjectCLen     = 0;
    cert-seq cert->subjectC        = 0;
      b = input[(*iurn sec;
};
    cert-_BUFFER);          if (b !timezthKesubjectCLen     0;
    cert-= 0;
#endif
#ifdef CYASSL_CERT_LTNAsubjectCLen          ULL, DYNAMIC_TYPE_TMP_BUFFER);
      nSET(    = 0;
    cert->subjectSTLen    = 0;
   e*/
}


static int GetCertHeader(DecodedCert* ce0;
    MEMORY_E;
    }
#endif

    if (version == tO        = 0;
 SL_SMALL_STACKEY_E;
tob if       dNULL, DYand/or 0) {
#       + 0x3);
    if < 0) {
im  if (b == 
    matIdx, inSz) 
    SetTime
    mp_tm*int  inSz)
{
    int    length,    byte*  d       if (verp_int(nt  ->tm_year % 10000) /certBt->heap    return ASN_PARSE_E;

    cert->certB)  / certrt->srcIdx;

    if (GetSequence(cert->source,REE(/ t->srt->srcIdx;

    if (GetSeint  
    cert->cer  
         return ASN_PARS + cert->monin = rt->srcIdx;

    if (GetSecert->source,x;

    if (GetExplicitVersion(cert->sourday, &cert->srcIdx, &cert->version) < 0)
   _SMAx;

    if (GetExplicitVersion(cert->souhour, &cert->srcIdx, &cert->version) < 0)
   DYNAx;

    if (GetExplicitVersion(cert->sourie, &cert->srcIdx, &cert->version) < 0)
   i    return ASN_PARSE_E;

#if defined(CYASSsec, &cert->srcIdx, &cert->version) < 0)
  STACx;

   r* passwoGetExplit RsaZ', &lenZuluint*ffine*/p,  input, ite* n, word32 nSzLengthpy       }

#iSz,   L_STACK
     XFREE(salt,ime((c))
  n = &lengit
        GetInt(, t)  ValidateDateal.day; ASN_EXPEasn.c
 *
 * CoserialTmp)) 006-2014 wol source;eak;
      cert->sinOutIdx += length;                     int der)
{
    if t->extExtKeyUsa          if (b !YPE_TMP                SSL_SMALL_STACK) &subjectCLmpi);

#if defined(CYA len;
               SSL_SMAL)
{
    i
}

#endif /* MICROCHIP_TCPIP */


#ifdef FREESCALEn;
        }
    ndif /*    retu DYNAMIC_TYPE_TMP_BUFFER) len;
        }
     0;
}


intould htati    r_E;

    x, innow until recv+Idx, &lengt< (int)sizeof(SetalTmp)) {
        if ( * mpnput, inOput, inOutIdx  byterd32* gInOutSzce, word32 i;
    )
        return  = *timer  byte     GetInt()
{
      GetInt(bin(mpi, ser &st_, DYNAtick  int  >source, &cnow->srcIdx--;

       rsio(recvd-ckof(uXTIME(ert->srcrecv  ifXGMicKey&ert->06-2014 wol  byte recvE_SHA1_ength;

 cert->pubx) < 0)xtKeyUsag/ctaocrIZED_icKe 0;
}
#endifltNames(cURPOSE.def HAV   /*0;
    byte ) {
        DNgltSz        ret pInOutract 1x, &    cfdef compli   XMlength;

   .    mpi -_RSA_KEY_mk &st(&ength06-2014 woladjus, serialT_256R1 &&cert-+= 19, inSz) _256R1 && /

 +=/
}
1;
    cce(cert-id != m is supporn 0 on s NULL, n 0 on su+ifdef HAVe oid suNULL, DYNAM1 &&    irt->srcIdx;

    ifgth;

    return 0;
}
E;
   

#ifdef HAVE_ECC

    /* returth += rucess if the ECC curve oid sum _ECC *orted */
    static int CheckCurv PKCatic int GetKey(Decode1 && oid +=cIdx, &lenCC_384R1 && oid != ECC_521R1 && oid !=
                   ECC_160R1 && oid != ECC_192R1 && oid != ECC_224R1)
         if (Gth += r NULL,   int tm return 0;
    }

#e     XMEMCPY(cert->serial, serialTmp, len);
          

        switch (}
    mp_clear(mpi);

#if defined(CYASS  byteb != ASN_MATH)
    XFREE(mpi, NULL, DYNAMIIT_STRINturn ASturn ASE;

  could use in futurebyte b = cert->sou++] != ASASN OutIdxd l,
  fiel   if) {
        mp_xIdx) <0)
  x, inSz, h)ivedLenngth;

    if (Gert->ct

   ectSNLvalu, &input[i], length);f (Geert->source[cert->s  if (GetInt(&key->p,   0x00)
       ype
    else
        retur= 0;
of= 32; i], length);cs *
    else
        retur

#iwedx++];
efinen) < 0is (0) ASN_PARSE_E;
d_bin(  }
 _get(mp_re*  = 0     XMEtSNLen }N_PARSE_E;
 nOut/
    inpuch 0)
   , inn = l  if (GetSeAMIC_T      , (tn ret k */
l,
 e = DE   }
    
       ZE(year)   
          }
0m_year = d use i ret->nit(&ke  int     }
1maxIdx - cert->srcIdx;&key- CYASSL_SMAL2maxIdx - cert->srcIdx;ETINT_E; CYASSL_SMAL3_STACK
            byteu);
    c_SMAL4maxIdx - cert->srcIdx;orgf
          5maxIdx - cert->srcIdx;key-f
          6maxIdx - cert->srcIdx;
#fndef NOf
          7maxIdx - cert->srcIdx;rd32 GetLengheap;

    if (G hours since mid    if  (byte*)key;
  OutIdtSNL          word16       }
#Ge2    ime(ord32      rc;
            word32      remaining = cert->maxIdx - cert->srcIdx;
#ifdefEnc CYASSL_SMALL_STACK
            byte*   MALLOC(MAX_NTRU= NULL;
#else
            byte MALLOC(MAX_NTRUob[MAX_NTRU_KEY_SZ];
#endiMALLOC(MAX_NTRU  rc = ntru_crypto_ntru_enMALLOC(MAX_NTRUtPublicKeyInfo2PublicKey(keMALLOC(MAX_NTRU                       &keyLen, NMALLOC(MAXNTRU_OK)
                return ASN_NTRU_KE->may;
            word16     _E;


      lif d        word32      remaining = cert->maxIdx - cert->s_INT08UNTRYcert- CYASSL_SMALL_STACK
         reak;TTrad, DYNAMIC_TYPE_T= NULL;
#else
   modi&key-ITLL, DYNAMIC_TYPE_Tob[MAX_NTRU_KEY_Sreak;UR         return A  rc = ntru_cryptrn tiRG         return AtPublicKeyInfo2Pu     XFUNI &lengru_encrypt_subjectPublicKeyIn_INT08MMO   decULL, &next, &remainingULL)d32     sfndef NO_RCid
    #E_SHA1_RC4 hours sin                             &keyLen, keyBlote* kength, inSz) < 0size(mpi)f (Get;
    if (len < (int)sizeof(, inalue excee       GetInt(AMIC_TYPE_TMex>srcIdx    z    Des    dec;
    reDateLeSL isn   = 0;
    cert->afterDate       = NULcert->srcIdx, int2* inOutIdx,nOutIdx += length; licKey L_SMALL_ength, sz) < = key + 8;

       #elseINTS
   ert->permittedNlicKey xtAuthKeyIinSz) < 0 )  return h;
    *inpIdx];inSz) < 0)t GetKey(Dord32z FOR A PARTISMALL_STACK
    sz    *iert->subjC_UTF8;
    cert->seySizectaocry       = 0Len;

#ifdef CYASSL_SMALLL_SMALL_ b = inpu>issuerNSL is serialTmLL, DullName, NU

#ifdef CYASSL_SMALLcert-licKe;
     c uses slightly di/* HAVlicKeGetLength(cert-ength,certen, cerCA!= ASN_INTEGER)
  retu                                         DYNAMCaBLIC_KEY);
     word326      keyLeSE_E;

 tKey{i;
  ,;
  c     6     3    55    1dert->ength04dSz, salt, saltSz, iterations,
  0x0cert-       ,&cert1 return ASff }NULL, DYNAM          if (    
     of    (GetLength(cert if (                   byte   bd32    rn ret;
                                             DYNAM   wo
        if ( (ret      rc;
Idx, inSz, h)      wor    B
    me_t i,    = Sz = 0;
    cert->deviceType =_PARSE_E;
 e = DEof(unicodeak;
      _PARSE_E;
   if (b[_get(ENTRIEif (0;
    cert->pubKeySize      = 0;
    if (b !=(
           t) sec;

    ret_PARSE_E;
 ) *
     ASN_BITNAL_SER}

#endif /* MICROCHIP_TCPIP */


#ifdef FREESCALE_MQ        derivedL;
    cert->pathLengthf (b !     = 0;
    cert->subjectCN       = 0;
    EE(key, NULL, DY           rC_TYPE_TMP_BUFFER keyLen;
   XTIMESz, h         worc;
   ->extSubjKeyIdS     leCE using GetVersPKCS5ttom upBUFFER);
#endef CYASS(tl) LREE(keyBlob, NULL, RsaKey* key,
INIT_Econd                           DYNAMIC_TYPESMALL_STACK
            er(CPU_INT08Usetteratiof /* CY RSA_PUBLIC;

#if rt->s=dx) = (           r - {
 ? 1z, h) 4SetKey(&dec, ke    re  if if (saltSz >Key = (b length);
        
   /* coul>tm_h length);
        (tl)  retur_PUB return returt    oidSz0x00;
          cer maxI {;
     us  int actual
    the hheap,
         t->source[i].cs *rn ASN_PARSE_E;

 ing 0 *tinuK
     et(&time_s);
    *timerdx += le if (cert->per>tm_hcIdx += ndif
    
         eySize HAVE_ += leCC toolchain only hd32 ersion  = input[idx+ype)
{
    EMAIL_JOdif LEconst time_t* timerype)
{
  +rd32* inOutIdx, DsaKey* ke

int DhPa (int)(next - keyhar* fullert->sr  if (cert->peint    length; ,                   cert-ast */
        if (GetSequence(input,ype)
{
ished names */
    int    dummy;
 kCurvetrt    ret;
    char* full       DecodedName* dName =
                  (ngthType == ISSUER) ? &cert->issuer     length;  r* passwo char* full = (nameT;

    while length; ert->e: cert->subject;
    word32 idx;
    ype)
{
    ert->sr length);
          DecodedName* dName =
               /* oARSE_E    ifsuer or subjectOutIdx += length; ype)
{
eturn MEMORY_G("Trying optional prefullName, NUor subjecturce[certSet_PARSE_E;

 t->extSubjKedx += length;
           return 0;
    ype)
{
 CYASSL_    return ASN_Ute* key     _EXTRA */
#if defined(OPENSSL_EXTRA) |NSSL_EXTRA      ies->next;

        XFREE(names->name, heap, DYNAMIC/
#ifdef CYASSL_SEP
    cet(&time_s);
    *timer  (nayte i, serialT   #define X {
#ifdef CYASSL_ssuerngth, cert->maxId        be
     * calcul
                     cert->rn sec;
.");

        if ssuerName.full

    ret = InitSha(&sha);
    i        XFR    return 0;
       return ret;
        CYASSL_MSG("    sngth, cert->maxageCount = 0;e
     * calcul  cert->subjec         sha, cert->issuer(tl)    XFREE(keyBlob, N, length + cert->srcIdx - idx);
             raw is0)
        return ret;
 ix...");

        if T have SHA-1 hash for cert naAMIC_TYPE_ int   OID_ID_E;

 2a    8 (Get48wLen = lenf7     dASN_PARSE_E;
            b = cert->source[cereturn ASN9 return AS16E;

    OutSz) {
       rt->sjlic Lelse
        ShaFi, length + cert->srcIdx - idx);
          cer               cer    clude <cyassl/ctaocrypthash should t->srcIdx;ubject;
    word32 idx;
    #ifdef OPENSSL_EXTRA
  /*ctRaw = &cert->source[cert->smaxIdxTH) {  rc != NTRU_
    }
#endif

    nal(&sha, cert->subjectHasth(c
        if (GetSet(cert->source, &cert->srcId04    }
#endif

       int    ret;
    char* full nal(&sha, cert->subjectHas     ;a copy of the GNU   (nameType == ISSUER) ? &cert-nal(&sha, cert->subjectHas
                     cert->pu  word32 idx;
    ssuer_PUB  idx = 0;

#ifdef HAVE_PKCS7
    /* store pointer to rPE_PUBLICcIdx += le ISSUER)
        ShaFinaa    sha;     /* MUS  (name    ifsource[idx], length + cert->srcIdx - idx);
         leet->tm_h ISSUER)
        ShaFin lengthert->srcIdx +=ader */
  +Microchip libracert->maxIdx)         Microchip libra return ASN_UNKNOWN_nput, word32*, oid;
    int    versionurn ASN_UNKNOWN_OID_E;
NULL, DYNAMIC_TYPE_TMP_Bsage     = 0;
    x], sizeoft->extExtKeyUsax], sizeof(joint));

  es thader */
  >      decrMAXTACK
    salt = (byte*)XMALLOC(MAX_SALT_SIZEincluding
     * the tag and length. */
    idx = certfdef CYASSL_SEP
    cert->detual key, use length - 1 since ate preceding blicKey ASN_UNKNOCE using GetVersTYPE_X509);
    if (cerha(&sha);
    if  v1 name types */ ISSUER)
        ShaFi v1 name types */if (ret != 0) {
#iC_TYPE_X509);
#endif /* OPENSSL_EXTRA ncluding
     * the tag and length. */
    id
#else
    msource[cer= 0;
   byte    minigned_bin_rn retsigned_bin(&dif

    if (GetS_OK)OutIdxblock */
#endifValiear(&       SE_E;
  rE_E;
t(&key->g, ect, in       /* odd HC08 compRNG* rng          if (Sz)      YEARSIrcIdxSz     return reey,
              ce    }
      cIdx];
                    oidSzetAlgength, certurn BADMALL_0         nameTyp     certkey->p);
  e
     dicod
        turn ASN_PARSE_E)
        ret    b           TRU_PUBLIC;
ey->g, g, gSz) !=e
     nt(&keRNG_GenerateB   G(->sourFUNC_ARG;

  ey->type = RSA_PUBion */
    struct tm* gmtiCaviumInt(&key->c   #ifdef OP int l
     key,
  sleng
             XMEMCPY

    i Names(cer      FUNC_ARG;

       #endif06-2014 woly->p);
                    #      reTS
    if (cex, inSz) < 0      }
 r(&key
          ert->srcMALL_ST
            Name->cnIdx = cert->
    st == 1) {
rt->suES;
    WITHOUT ANY NULL || key =nSz)
{e(inpal to beginning  &inOukey->c_uSz,   input, inOutIdce(input, &pe = DES3_TSN=", /* NO_DH *e[cert>subjectOU    {
           ,{
     ->extSubjKeyIdS {
              rt->m                  if (nameType == SUBJader too 4 1];   /* ver                }
   d la         #ifdef CYA    ceRT_GEN
                    if (nameType == SUBJECT) {
                   nSz) < 0 ||
 bjectSN = (char*    ce->source[cert->srcIdx];
                        cert->subjectSNLen = strLen;
   cert->subjectOLen   nput, inOutINTRURUE;
                }
       b;
             DES_TYPrc  = cal.hour;
16yte* key       returnrc  ifSz) _crypto_     en XMEM_tSz, iter2te((ect) < 0 ||
XVALI       ASN_PARSE_E;
            b = cert->source[cert->srcIdcIdx];
  &(!tooBig)ding
 eclaration */
  cUM
  id =OK            cert->subjectSNLen = strLen  time_t ltooBig) >extExce(input, &i,            cert->subjectSNLen = st
                    XMEMCPY(&full[idx], "/C=", 3);
                    idx += 3;
                    copy = TRUE;
      }
                #if {
           CYASSL_CERT_GEN
                    if (nameType == SUBJECT) {
 SUBJECT) {
                (!tooBig) {lt = NULL;
 t->subjec    ey input      ith;
    }eRaw(const byte* n, word32 nSz, coutIdength;
    woc = m?= TRUE;
                       (key->magve later, Ds
        /*;
                serialTmp)) {;
           tIdx = >source[cert->srcId            ruct tm* gmtime(const tiord32 cert->source          =     }
       WITHOUT ANY         idx += 3;
  f (!tooBig) {
               ce(cert->sou&full[idx], "/L=",  input, inO3);
                    idx += 3;
                    copy = TRUE;
      else iPARSE_Eif /* NO_RSASN=", z) {
   == SUB   wo            f PKCS ver
                                Name->cnIdx = cert->   GetCait under thSequencn = strLen;
     z) < 0)
          cert->   }       #ifde)
       ?   }
#endif

 nc = b;
       :           }                }
L_EXTRA
  Name->cnIdx = cert->ISSU_SEP
 pt/logginne XTIME(            re              if , wo */
   a    }
t->soource[cert->srcId
     ruct tm* gmtime(const ti   *RU= TRUE;
   d;
    int    verME) {
              SAk:
        , oid !CAx += length;lse if (id == ASN_STATE_NAME) {ength(input, PENSSLalue exceedef CYASSL_CERTASN_PARSE_E;
            b = cert->source[ce       ndif /*, wo4;
      ource[cert->srcIdYASSL_CERT_GENruct tm* gmtime(const tingth(input,, 4);
                    idx +YASSL_CERT_GEN
    onst byte* n, word32 nSz, coe[cert->srcIdx];
         E) {
      e* e, wor         #ifdef CYASSL_CERT_GEN
                    if (nameTy CYASSL_CERT_GEASN_PARSE_E;
            b = cert->source[censt byte* e, worhar*)&cert->source[cert->srcIdx];
                        cert->subjectSTLen = strLe skipping");SN=",f (Get=MEMCPY(&full[idxfdef   #endif /*{
               + SUBJECT) {
              {
                {
               {
     L_EXTRA
 ll[idx], "/O=",
             E_TMP_BUFFER);
    if < 0) {signed_bin(&  }

if
#     
      alCYASythe honit(&kime((c))
  etIntIdx+Body (!tooBi       DATE_D     iLL_STACK
           else if (Publar->g,  inp       int    strLen;

            ,ar*)&cer    cert-PE_TMP_BUFFER);                if (ce     idx += 4;EMCPY(&full[id->issuerName.fEMCPY(&full[idert->issuer     t->subjectOEnc = b;
                         }
         #endif /* CYASSL_C

    i +   else if ;
#ifdef HAVE_PKCS7
 L_EXTRA
                   XSN=", 4);
    = cert->srcIdx;
          ret*/
            t->subjectOEnc = b;
                  dNam      copy =  #endif /* CYASSL_Cz) < 0)
                    #ifdeectOEnc = b;
               idx], "/L           idx  #endif /* CYASSL_CEth;
    }
cert->subjectLLe  #ifdef OPENSSL_EXTRA
            ubjectLE3;
           = cert->srcIdx;
    z) {
    2014 wol     copy = TRUE;
rLen;
                #endiSN = (char* {
              #endif /* CYASSL_C /* NO_DH */            }
ength(input,)
    #include c uses slightly differrLen;
                #endi       copy inOu          cert->sASN_PARSE_E;
            b = cert->source[cert->srcId    retif /* CYASSL_CE);
    }
#end /* CYASSL_C
                 t(&key->n,  in   = 0;
 /#endifubjec   decrypti, in       (sz)) < 0) {
#idNamYNAM>sub {
           ndif

  nd, intMIC_TYPE_TM     if f, t) VaYPE_TMPig) {
    == ASN_PARSE_E;
            b BJECT) {
                    cer)&cert->so}

#endif /* MICROCHIP_TCP  XMEMC

/*ime(to_unsigned_encSMCPY( dige->srcIreRsHUSER_TIME)
    FALSE;
  #ifdef[SHA256<windows.h>
mpIdx]maxeturn ASNen    = 0;
    cert->subjectOUEnc         t->subjectEmailLe      GetLenNCODED<win
     >g);
      n ToTradition CYASSL_SMALL_S      #ifdef            #ifdef O                    &cert->source[cex], &cert->souNSSL_(cbcIv, unico     irt->srcIdx],           }

 cert->srcIdx],EMCPY          ceSSL_CErt->srcIdx], Len;
            rnncrypt_sZE(year)                   

    switcMD5 word32* i }

 TCyte tIntm_year = ynt first, iMd5
          ret;  #ifdef))                 x += SSL_Eurce MD5aocrypt/integer#ifdef Od hdr <windows.h>
eturn ret;
    }

  stm32f2xx.h, &inOutIdx, &   switchHays since SLSE;
    GetIntm_year = y             IdSet  int  adv;

        Sha if (joint[0] == 0x2a && joint[1] == 0x86)  /* email id hSHA*/
                email =ff;	E;

        {
            if (joint[0] == 0x9  && joint[1] == 0x92)  /* uid i256id = TRUE;

         256    uid = TRUE;

         _MSG  cert->srcIdx += oidSz + 1;
256
            if (GetLength(cert->source, &cert->srcIdx, &adv256, cert->maxIdx) < 0)
        nIdx = cert->sr     if (joint[0] == 0x9  && joint[1] == 0ey->heap;

    if (GetSeqfine FALSE 0R) {
    ut    IVATdtCaviu        ret* ema;
            breakd* h4;
         word32 i             dName->cnIdx = cert->srcId    XSz = 0;
    cert->deviceType =        cert->extensionsSz   */
            }

            if (copy &ASN_PARSE_E;
            b = cert->source[cert->src  cert->hwType = NULL;
    cert->hwSerial            = 0;
    cert->subjectCN       = 0;    XMEMCBig) {
              
        ;
#end          &cert-
    #include   int length, int ver          re     
         rt->so  #ifdef  #ifdef OPENSSL_reeAltNames(ce    sa  cerignPENSSL_EX               EMCPY({
       rng   #definULL || e ==EXTRA */
               c!SSL_CER&&dName->sN_COUNTRY_NAME) {
t encrSMALL");

       ->subjectCy->p_ut, (TRA
                   SE_Eame->>souName->snI to beginning of inp             cert- get encsalt = NULL;
   LL, DYNAMIC_TYPE_TMP_BUFFER);
      ENSSL_EXL_SERIAL_SIZE];
#if defined(CYASSL_SMALL_STACK) && put, inOutId PKCy->p);
   t  red#end     if (nameailName = assum    UBJECT if (Che   }
#w  idx = 0;
ime((c))
  Add
          if (!tooBig) {
  icKeyD          if (       XMEMCPY(&full[idx], "/serialNumbeE;
                }
  reDateLen   = 0;
    cert-put, inO if rn MEMObin(mpi, ser 0;
#ifdef HAVE ret;
 extSubjKey                        retuEMCPY(&full[idx]->hwType, cert->heap,     i  cert->subjectSNEnc    = CTC_UTF8;
    cert->st->heap, Dert->per     >c_dQ;
          _ID_E; 
) {
           ert->extKeyUsageSet  = #endif /* CYASSL_CERT_GrLen;
                      dNam->issuerName.fuRAINTSlength, inSz)room,
   overgth,             c         return ASN_     XFRATH)
    XFMOVE           if (b !ooBig) { return MrLen;
          XFREE(cert->iL_STACK) && def = 0;

 dif /* OPENSSLan&key->p, p, pSz) !v3  #detIdx, 0;
       }

  ec;

  0) {
#i       N_SERIAL_NUMBER) {Any             if (E:
      Bame->ne{
                  /* odd HC08 compi=", 14);
                   idx += 14;
                   copy = Trce[cert->srcIdx];
                    cert->subjecSz = 0;
    cert->deviceType =nameType == _BIT_STRING)clear(&kif

1 CYASSL_SMALL_S            }
 Name =  ?c = b;
  :YASSL_CER?LL)
     : (id == ASMIC_TYPE_X509);
#endif /* OPENSSL, move nameTypet) sec;

    ret(!tooBigl to beginning
   of input */
int ToTraditalEnc(byte* input, word32 sz,const cha skipping");
             Get  if (MALL_
          ailLen =,}
               cbcIv) < 0)         axIdx) < 0)
               ToTraditionce[ter hash ef CYA        b = input[(f (GetSequence(cer   int    version, l       inicKeyDe=              cMALL_STA         #defineLL, DYNAMIC_TYPE_TMP_BUFFER);
      eturn MEMORY_E;
    }
#endif

    if (version == ALTNAME);
              cert->altEmailNames = e  ifor GetI                 }
                #UMBER) {ME_CONSTRAINTS */
                if (!tooBig) MEMCPY(&full[idx   }
#endif

             idx += 14;
  LL;
#else
    mNORE_NAME_CO                 STACK
 EMCPY(&full[idx], &ceto begert-,  input, inOutI     otalL     NtruME_CONSTRAINTS */
                if (!tooBig) {
                 rce[cert->srcIdx];
         kDH *ame->snLen != 0)
            totalLen += dName->snLen + 4;
  to begto beg, &cert->sourctLen               dName->cLen = sttIdx, inSz) < 0 ||
      TF8;
    cert->eqA ( (bBLIC_KEY);
          Gwt->publicKe           return ASN_OBJECpOid_ID_NG
    #insh);

    lengif (nameTyRawLen = length - cert->srcIdx;
 
    i}

#endif /* MICROCHIP_TCP (nameTyp7E;

       return ASN_OBJEer      totalLen += dName->emailLen + 14;
        if (dName->uidLen != 0)
            totalLen += dName->uidLen + 5;
eE;

DYNAMIC_TYPEecodeRaw(lengtource[cturn ASN_PAR_OK)cpyDecod      ifCeturn MPOutIs.h>
gth(s par>fullName != NULL)        (t))
    #e0) {mail =           dNatRA
   (t))
    #epw {
       FER);
#endi {
                     Rf (ns);
#  if (dName->cnLen != er {
                 XMEe->entryCount
      SLen   = 0;
    cert->aftedNameY_E;
                     t  
   PRSTR /* CYASSL_CERT_XMEMterations, id,
        Name[Y_E;
            XM    }

     0xa>fullNaze   =t->signatuw    pINIT inOutIdx, inY(&d->pubKeyStored pw65)

    sta                 GetInt    ,
     ryCount++;
   ot optional pr        +     me->f  }

    /* F0) {
      += length;             dCri "/SN=",
             idx += 4   email        int*) {
   CODE_EName[idx],
                         
    #define TRUE if (d
        /*Name[idx],onal prlicKey Name[cert->sourc XMEMCPY(&             ame[idxsnIdx], dn != dCrin;
              &cert-TRA
   licKe dNa= 0) {
   XMEMCPY               
    cert->devicPId(ihe pieef CtogeABLEcIv;
    /* HAV");
      >sourame->zARSE_E;

 szA)
 RUE;
     p             i

#ifdef CYASSL_SMALL[dNamme->cId_E;

        /* HAV[dName- = keyLen;

#ifdef CYASSL_SMALLe[idx          [idx]->cLen);
        x += dName->c dName->cIdx = idx;
             Sret  "/SN="->cLen);
            .");

         &cert->source[dName->c   re      ->cLen);
                        XMEMCPY(&dName->fullNa
       ->cLen);
         dName->snIdx = idx;
  CYASSL       XMEMCPY(&dName->fullNadNamee->lIdxe->fullName[idx],
  XMEMCP         XMEMCPY(&dName->fullNan !=                Len;
            }
      "/C=", 3);
     &cert->source[dName->lId    ame[id>lLen);
             .");

       , or
 *x++];
 ths since Januawersibe taJECT)o ret  iderial, sub icIv;
    t(&key->n,  in           byte               }

            if (id == ASN_COMMON_NAME) {
       Req         if (nameType == S&full[idx], "/serialNumber=", 14);
                   idxNULL, DYn = strLen;
  */
                  }

                if (!tooBig) {
                    XMEMCPY(&full[idx], "/CN=", 4);
                    idx += 4;  
     cert->subjectLLen = strLen;
                        cert->subjectLEnc = b;
                    }
                #endif /* CYASSL_CERT_GEN */
          copy = TRUE;
                }
                #ifdef CYASSL_CERT_GEN
                    if (nameType == SUBJECT) {
                        cert->subjectSN = (char*)&cert->source[cert->srcIdx];
                        cert->subjectSNLen = strLen;
                        cert->subjectSNEnc = b;
                    }
                #endif /* CYASSL_CERT_GEN */
                #ifdef OPENSSL_EXTRA
                    dName->snIdx = cert->srcIdx;
                    dName->snLen = strLen;
                #endif /* OPENSSL_E  }
            else if (id == ASN_STATE_NAME) {
                if (!tooBig) {
                    XMEMCPY(&full[idx], "/ST=", 4);
                    idx += 4;
                    copy = TRUE;
                }
                #ifdef CYASSL_CERT_GEN
                    if (nameType == SUBJECT) {
                        cert->subjectST = (cha  
        *      }
                #endif               cert->subjectSTLen = strLen;
                        cert->subjectS {
       GetInt(       totalLen idx += 5;
 ASN_PARSE_E;
            b = cert->      return MP_Indif /* CYASSL_CEjectCNEnc    idx += 5;
     Name->cnIdx = cert->_E;
put[i+U = TRU) {
                if (!tooBig) {
                       3);
                           cert->su{
      GetInt(&k          #ifdef CYASSL_CERT_GEN
            leng        if (nameType == SUBJECT) {
                    Req    cert->subjectO = (char*)&cert->source[cert->srcIdx];
                        cert->subjectOLen = strLen;
                        cert->subjectOEnc = b;
                    }
                #endif /* CYASSL_CERT_GEN */
        fdef CYASSL_CERT_GEN
                    if (nameType == SUBJECT) {
                        cert->subjectOU = (char*)&cert->source[cert->srcIdx];
                        cert->subjectOULen = strLen;
              h--;
    ehar*)&cert->source[cert->srcIdx];
&dName-            dN #endif /* CYASSL_C GetInt(&kEnc = b;
                              cert->subjectOUEnc }
                #endif /* CYASSL_CERT_GEN */
                #ifdef OPENSSL_EXTRA
                    dName->ouIdx = cert->srcIdx;
                    dName->ouLen = strLen;
                #endif /*talLen = 0;
me->stIdx], dNam
                if (!tooBig) {
                = idx;
                idx += dName->s       }

            if (uid) {
                if ( (5 + adv) > (int)(ASN_NAME_MAX - idx)) {
                    CYASSL_MSG(L)
                          tooBig = TRUE;
                }
                if (!tooBig) {
                    XMEMCPY(&full[idx], "/UID=", 5);
                    idx += 5;

          me->         XMEMCPY(&full[id->srcIdx], adv);
                    idx += adv;
                }
                #ifdef OPENSSL_EXTRA
                    dName->uidIdx = cert->srcIdx;
       dx += 14        dName->uidLen = adv;
                #endif /* OPENSSL_EXTRA */
            }

            cert->srcIdx += adv;
    


int DsaPrivateKeyDecode(cons  DYNign  Getcert->     Key == NsTNAME);if (!tooBig) gth, inSuffg) {
            =", 14);
                   idx += 14;
  to_unsigned_bRAINTSen    = 0;
    cert->subjectOUEnc   rt->st(DecodedCert* sL_EXTRA */
     (fi && !tooBig) {
  ], adv
    st||
        GetCaviumInt
    st  return 1;

    if (a->tm_year =dNam         }

                #rtTimel to beginning
   of input */
int ToTraditmat =[idx], "/UID=", 5);
                    idx +      =ER) {
                 e;
    stru     ME */
        certTi += dName->cnLen + 4;e->cnLen + 4;
  [idx], &cem* lo&dec, input,      >t->maxI ASN_OCTET_STR    else;
               CODEcertT(cert- 0;

        #ifdef    }

  L_EXTRA
                    dName->   }

                year, tm_mon */
    Get dName-    GetT          XLL, DYNAMIC_TYPE_TMP_BUFFER);
           TRA */
            }

            cert->srcIdx += a   if (_mon &&
    SelfME_CONSTRAINTS */
     
    int    i = 0;

  cert->subjec sizeof(certTime));

        n = 0;

 == b->ame->ney Zulu tortedoLen != 0->srcIdx], adv);|
        GetCaviumInt(&key->c* CYASSL tm  cer = cert->src     typeH TNAME);
        localTime = XGMTME(&lteturn ASN_PARSE_E;
    }

    int    Altt, &r  }

#i inpbin_size(mpi)0x = suR_CFG_            DYNAMnsigned_From             if (C4_TYPE:
        cIdx,      >tm_year && a->tm_mon == b->tm_mon &&
        adateDate((dddate[M ( (5 + adv) >dateDate(TE_SIZE]N_NAME_MAX - idx)x], dNalse
            certTimteTyp  return 1;

    if (a->tm_year == _bin(&     dateDate((     }
           dateDate(if (!tooSN_PARSE_E;
            b = cert->source[cert->srcIdx++];
            if (b != 0x00)
     >srcIdx];ce[cert->srcIdx];
                        cert->s/* fate = &certf (b != ,asicConsMALL_STACK
 ert->srcnt(&key->c_q,  &key->c_qE;

    i   *ver,    VERIFY->sourime);

    if (daLSE
    #define FALSE 0etInt(&key->dQ, i NULL)
             {31, 28, >srcIdx->srcIdx;
   ndler(CPU_INT08U XVALIDATDecryptKey(sl/ctaocrypt/intinput, iax                        idASN_DATength);

n ASN_DATE_SZ_E;

 ->tm_min   = c= BEFORE)
  x++;  / if (dateType =d, f, t) ValiMDK5)
        #= length;
    *inO 
        b = input[(*inOIP)

/*
 * time() indif /* OPENSCULAR PURPOSE. cert->srcIdx -, & if (dateType =re; you caSN_PARSE_E;
            b = cert->source[cert->srcIdx++]   if (date < 0 on WinCE using GetVers   if (!XVALIDATE_DATE(date, b, dateType)) {
    ectOLen = sateType == BEFORE)
            return ASN_BEFORE_DATE_E;
        else
            return ASN_AFTER_DATE_E;
    }

    return 0;
}


static int GetValidity(DecodedCert* cert, int] == 0x86)  /*ert->srcIdx += ln = cert->src     r(cert   unsigneGO_ID_E;
    }
 if (dateType ==<badDate = ASN_BEFersion  = input[idx+   word32 idx   y)
        return Aturn BEFORE_DATE_E;           }
#endif

    DES_TYPtmp= length;

   IME(t1) pic32_time((t1))nt length;
    int badDate = 0;

    if (GetSequence(cert->source, &certDATE_E;
    }

    return 0;
}


sta
}


static int GetValidity(Decoded->tm_mon  = 0;

    while(daynotime_s);
    *timer  word3ate != 0)
        return badDate;

     if (dateType == B(badDatet current time */
#CULAR P

/* Chnt length;
    int badDate = 0;

   CALE}

#endif /* MICROCHIP_TCPIP */tHeader(cert)) < 0)
        return ret;

    CYASSL_MSG("Got Cert Header");

    if ( (ret = GetAlgoId(cert->source, &cert->s, but#endif
, &length, m        return ret;

   nst byte* e, wordassl/cta +icKeyBEFO->maxIdx)) timer)
{
    tisecond) {
        te* e, word<rveOID += cert;

    CYASSL if (btoi(date[t[i++];
            lengthIdx = cerORE)
       ++;  /(badDate]N_BEFORE_DATE_E;
        else
    CYASSL_CERT_GEN * (GetLength(input, &i, if (GetSequence(input,SSL_MSG("Got Subject Name")OID_E;
    }
}


/*is return 0
   < 0 onsigned_nput, inOutIdxore *e = DES_TYPE;
      if (!tooBig) {
  &lengt Cert Header");

    if  if ( (ret = GetAlgoId(cer  word32 idx;
       b = cert->source[ce if (dateType == B( (ret    /* cont         return ASN_PARSE_E;  cert-E_E;rn ASN_TIME_E;

   s->ndv;
                #endif /* OPENSSL

    iTRA */
            }

            cert->srcIdx += adv;f (d ?atic , h) < 0 int    lengtTime))
            return 0;

    return 1;
}

#endifword3IME_H */


static int GetDate(DecodedCert* cert, int dateType)
{
    int    length;
    byte   date[MAX_DATE_SIZE];
    byte   b;
    word32 startIdx = 0;

    if}

            DeRING;
    oute = DES_ (dateType == BEFORE)
        cert->b      #endife = &cert->source[cert->srcIdx];
    else
        cert->afterDate = &cert->source[cert->srcIdx];
    startIdx = cert->srcIdx;

    b = cert->source[cert->srcIdx++];
    if (b != ASN_UTC_TIME && b != ASN_GENERALIZED_TIME)     return ASN_TIME_E;

    if (GetLength(cert->source, &cert->srcIdx, &length, cert->maxIdx) < 0)
        return ASN_PARSE_E;

    if (length > MAX_DATE_SIZE || length < MIN_DATE_SIZE)
        return ASN_DAT           &idx, &lengnt length)
{
    ithInfo     = NULL;
 or v1.5 */
          exord32 nt   e = DES_TYPEuidIdx-         ++;
        }
    }

    return  inputd32* gInOutSzifde &length, cert->maxIdx) <->srcIdx++];
    if (b !=)
{
    iput + 1) + 1;
}

CY   if (length > MAX_DATEBarcId       SN_SEQUENCE | ASN_CONSTRUCTED;
    reset from CUT in seconds L_STACK) && 
    }

    return ord32 SetSet(word32 lndif
    
    iate;

    retu
    retu, byte* output)
{
  TED;
    return SetLePKCS v2int    length;               , byte* output)
{
    , word32* inOutI)
{
    if (n =byte* output)
{
    o return ASN_P
    cert->signature = &ceert->source[cert->srcIdx];
    cert->srcIdx += cert->sigLength;

    return 0;
}


static word32 SetDigest(const byte* d  NULL, DYNAMIC_TGreaterTha
        if (b !int    c>srcIdTime))
     GetTime( return 0;

    return 1;
}

#endifl,
 IME_H */


st      cnnt GetDate(DecodedCert* cert, int dateType)ret;
{
    int    length;
    byte   date[MAX_DATE_SIZE];
    byte   b;
    word32 startIdx = 0;

    if (dateType == BEFORE)
        cert->beforeDate = &cert->source[cert->srcIdx];
    else
        cert->afterDate = &cert->source[cert->srcIdx];
    startIdx = cert->srcIdx;

    b = cert->source[cert->srcIdx++];
    if (b != ASN_UTC_TIME && b != ASN_GENERALIZED_TIME)     return ASN_TIME_E;

    if (GetLength(cert->source, &cert->srcIdx, &length, cert->maxIdx) < 0)
        return ASN_PARSE_E;

    if (length > MAX_DATE_SIZE || length < MIN_DATE_SIZE)
        r               iert->srcc_dP_Sz,x - startIdx;

 , int byte ECC_224r1_Alg */
<;
   ert->sour>src0x04, 0x00,
         _LOCAL word32 SetOctetString(word32 len, [] = { 0x2b, 0x81:              ert-P_BUFFER);
#endtrncpy(cn  &keyLen, Nord32 SetSeASN_RSA_KEY                 #define RNG                      return ASN_BIT = { 0x2b, 0x8INIT_Ebyte ECC_224r1_AlgMALLOxx.h" */
    #definturn ASN_DAT224r1_AloID[] = { 0x2b, 0x81, 0x04, 0x00,
                                            021};
    static const byte ECC_384r1_AlgoID[] = { 0x2b, 0x81 0x04, 0x00,
                                  t(&ke   0x22};
    stati const byte ECC_521r1_AlgoID[] = { 0t(&key, 0x04, 0x00,
             th, inSz) <byte ECC_224r1_Al0x23};

    int    oidSz = 0;
    int    idSToID[] = { 0x2b, 0x81, 0x04, 0x00,
    ST                                        case;
    static const byte ECC_384r1_AlgoID[] = { 0x2b, 0x81, 0x04, 0x00,
                                &key-   0x22};
    statST const byte ECC_521r1_AlgoID[] = {&key->, 0x04, 0x00,
           utIdx, inSz= sizeof(ECC_256v10x23};

    int    oidSz = 0;
    int    id    TIME_STRUCT t0x81, 0x04, 0x00,
    L                                       lgoIID;
    idx++;

    switch (key->dp->size) {
        case 20:
            oidSz = sizeof(ECC_160r1_AlgETINT_E;   0x22};
    statL const byte ECC_521r1_AlgoID[] = {ETINT_E;
, 0x04, 0x00,
           turn ASN_DH_KE       default:
 0x23};

    int    oidSz = 0;
    int    idO            oid   =        ECC_384r1_AO                                       ndifID;
    idx++;

    switch (key->dp->size) {
        case 20:
            oidSz = sizeof(ECC_160r1_Algor_EXTL_CERT_GEN */


 const byte ECC_521r1_AlgoID[] = {ey->, 0x04, 0x00,
            NULL ||  to end */
    
 Sz;

    XMEMCPY(output+idx, oid, oidSz);
  U  idx += oidSz;

    return idx;
}

#enUdif /* HAVE_ECC && CYASSL_CERT_GEN */


Algo;
    static const byte ECC_384r1_AlgoID[] = { 0x2b, 0x81, 0x04, 0x00,
                                key- 0 to end */
    
 U const byte ECC_521r1_AlgoID[] = {key->, 0x04, 0x00,
           ;

    /* ID[] = { 0x60, 0x81_AlgoID);
            oid   =        ECC_19goID[] = { 0x2b, 0x81, 0x04, 0x00,
    S                                        ,
   _AlgoID);
            oid   =        ECC_224r1_AlgoID;
            break;

        case 32:
            uen +                 _AlgoID);
            oid   =      urC_256v1_AlgoID;
            word32                   0x23};

    int    oidSz = 0;
    int    idEe SHA-1 hash for cer0x81, 0x04, 0x00,
                                }
#endif

   ?   if (b != , 0x02, 0x05, 0 0x04, 0x00,
                                subje 0 to end */
    
      const byte ECC_521r1_AlgoID[] = {rd32 i, 0x04, 0x00,
   >sigLength--;
    cert->signature = &ce ? ASN_CONSTRUCTED : 0)
                    | ASN_CONTEXT_SPECIFIC | number;
    return SetLength(len, output + 1) + 1;
}92)  /* uiFILESYSTEMumber, wor }

               }  Fut, in PEMt totalLSet
     


static int GetDan + 4;          
            /* key rn ASN_RSA_KEY_E   cert-              te shawRSt->pubKeyStored    IGHTKrn A+= cert->sigLength;

t   urn ASN_PARSalEnc(byte* word32 len, byte* outpu          OOF   rblemSN_SEQUENCE | A     cert->extCertPo shawRSA_    ycert-Pe_H */NAMIC_               XMf7,
      _521r1_< 0 )  return ASN_R>fullNadSz + 1ASN_CONTEXT_SPE->lLen = strL     XM cert,    = 0;
   int    iterations = 0;
#            ALTNAME);
         6, 0x48,               IV is                       ;
               0x0d, 0x01, 0x0  0x0d, 0x0x05, 0x00};
        static const byte shawRSA_AlgoID[] = { 0x2a, 0x86, 0x48, 0x86, 0xf7,
                                            0x0d, 0x01, 0x01, 0x05, 0x05, 0x00};
;
       static const byte sha256wRSA_AlgoID[] = { 0x2a, 0x86, 0x48, 0x86, 0xf7,
       0x0d, 0x0                        b, 0x05, 0x00};
        statiif (nameTypee sha384wRSA_AlgoID[] = {0x2a, 0x86, 0x48, 0x86, 0xf7,
                 n ASN_PARSE_E;
    }

    letatiatlsource,                           nsigned_b         0x0d, 0x01, 0x0    x05, 0x00};
        static const byte shawRSA_AlgoID[] = { 0x2a, 0x86, 0x48, 0x86, 0xf7,
                                            0x0d, 0x01, 0x01, 0x05, 0x05, 0x00};
h(cert->s static const byte sha256wRSA_AlgoID[] = { 0x2a, 0x86, 0x48, 0x86, 0xf7,
         xCE, 0x3d,
                       /* NO_TIME_H */
         XMsha384wRSA_AlgoID[] = {0x2a, 0x86, 0x48, 0x86, 0xf7,
                }

CYASSL_LOCAL word32 SetESL_EXorted, set [] = { 0x2ate RS            0x86, 0xf7,
leng    int totalL                0x04, 0x03, 0x02, te(DecodedCert* cert, int da     0x0d, 0x01, 0x01, 0x0b, key->ty0x00};
        static const byte sha384wRe* digest,                                        ;
                     0x01, 0x01, 0x01, 0x05, 0x00};
    #edef HAVE_ECC 
        /* ECC k       0x04, 0x01, 0x0= { 0x2a, 0x86, 0x48, 0xCE,0x3d,
   x48, alLen =                             h(cert->st byte ECC_AlgoID[] = { 0x2a, 0x86, 0x48, 0xCE, 0x3d,
        0x04, 0x03, 0x04, 0x05, 0x00};
    #oBig =
    int nt    = 0;
    int    tagSz  = 2word3st byte ECC_AlgoID[] = { 0x2a, 0x86, 0x48, 0xCE, 0x3d,
        RING;
    outp
    byte ID_Length[MASA
        static const byte RSA_AlgoID[]FER);
            XFREE(             d_unser        r & s/
    n ret;
 word, paDes3(in/oXFREturn ASN     x, &d laDSA->sr     returnt    i    GeN_OBJ    returha256AlgoIsdateDate((d), (f), (t))
#eliAME) {
 word32* inOutIdx, DsaKey* keA

int DsatSNLturn ASN_PAR    if (  dName-DES_TYPE];
#e, 0x44e->cnLe2*modiTAG    *Sz >ENUMASN_S;

    i_ENABL     althwTyp = *inOey, desOutIdx == PKCS5= sizeofrsionName != NULrL   altZsiontNameCrit = 0;
  Len;
    t tm       break;

        case Mx;
 ID;
       BUFFER);
#endif

    XMEMr;
  emailN*/
  (dName->cnLen != Size   ER);
#endif

    XMEM);
         e));
    cz = *256h:
 < (lgo */
        break+5h:
      b;
         ngth = length;

             + /*      ions   casSHA512h:
    x) < 0)
        return ASN_PARSE_E;age     = 0;
       a+        brea+   De;

        d+        UBLIC            x, &lN_ORGUNITo    cert->subjecey, desIv, DERA
      ence(inpmd5AlgoID;
       S_entrANTY;->issuerName.f= recvd;

, ad

        dlkTypes, n            a>fullNa defined(OPENSSL_EXTRA) |r desCbcAlgoID;
    IdSrc =!ut[*inOutIdeturn ASN_PARSE_                if (C    castruct tm            algoSz = sizeof(deT_GEN
   ert->per break;

        d desCbcAlgoID;
          = sha384A;
              break;
        case DES3b:
            algoSz = sizeof(;
}
CbcAlgoID);
            algoName = des3CbcAlgoID;
        Unkn;
}

CY algoNamMicrochE_TMP_BUFFER);
    if     ate = c = -DSADateL= TRU,eak;

     cdE;
 e */
    4
       rd32 256AlgoID);RY_E;
           PARSE_E;
    ha256AlgoID;
            break;

        case SHA3[cert->src

/* Remove PKCify)
{
    i DNS_etware; yoime.tcert->etribute it and/or modi = b;
 length;
}


Cm.h>


#lgoN>t*)&c  al-         case CTC_SHA256wRSA:
                Get_PARif (n         ;

            case CTC_SHA256wRSA:
                wRSA_Als   DNS_e             break;

            case CTC_SHA384wRSA:TIME(c) my_gmtAME) ccPrivat     break    case CTC_       } algoNainOuDatet(&key->g,  in = GetName(cert, ISSUER)) FREE(cbcI (dName->eE_DATE(d, rn 0;
}

#endif /E:
      urn ASN_EXPEendif /privh (a   = 0;PY(date, &cert->so)  return eRaw(const byte* n,  cert->subjectOUEnc       */


void InitDtoi(date[0]) >= 5    licKeMAXreturn ASN_PARSEpublicKeeof(sha-= 1;
    G);
           ny lawo     s |
  cert->srcIdULL;
    byte*  nput, &idx, &lenge CTC_SH &idx, &leng32_WTC_SHA256wECDen);
                dNa return ASN_PARSE_E;

 ET | ASN_CONSTRUCTEe CTC_SHA5; you can2wRSAdistribute it and/or modify
 * it underCULAR P     case DSA_AlgoID;
      PE_TMP_eak;

            case CTC_SHA384wECDSA: *date, CP*e CTC_SHe->cnIdSA_AlgoID ECC_e->oLen);
 rivPENSSL_EXTRA rDateLen 4ExpleLen 6A:
      7
#endif
   dx;

    return length;
}


CYASSL_LOCAL int GoID;
                break;

            case CTC_SHA384wECDSA:
   input[i++             b = input[(*inOuSSL_SEP
 cert->pubKeySize      = 0;
    c    ->pubKeyStored    = 0eof(shaert->version         = 0;
    cert->signatu;
   (byte* input, word32 sz,const char* passwocert->pubKeyStored    = 0            algert->version         = 0;
    cert->signature       = S */
    cert->issrivr[0]       = '\0';
    cert->subject[0]      = '\0';
    cert->source          = /* kpy = TRUE;
      yassl/ctaocrypt         RSA_A FREESCSA_AlgoID;,  case ;
                br /* continue VE_ECefix    maSA_A          sha384wECDSA_AlgoID;
     ear = 0u;d lastEFIX_    if (lengt           break;

  ID);
                algoName = sha512wECDSA_AlgoID;
          ;

    if (!XVALIDATE_DATE(date       typeH = SHA;
  );
    else
        ShaFisha384wECDSA_AlgoID;
     C */
        default:
           TC_SHA512wECD                   word32 max = input[(*inO         mall count integer, 32 bits orype)) {
        if    algoName = sha512wECDSA_AlgoID;
 (GetSequence(input, inOutreturn GetMyVersion(inputast */
        if (GetSequence(input,defin/* HAVE--follows for ecc */
  = idx;
join   }

    idSz  = SetLength(aC */
        default:
  [] = { 0x2b, 0x8 = cert->source[ce    ng.h>  cert;
     */
    #include "dc_rtc_ap  returCUR {
 z + 1 + curveSz, seqArray); CT_ID) 
            r
               oID;
     1  #define XVALIDATE_DA
    idSz  = SetLeng     default:
            CYAeLen endif /* HA1x - startIdx;

    if (!XVSA:
       ATE(date, b, dateType)) {
        if  for object id, curveID of curveSz follows for ecc    seqArray[seqSz++] = ASN_128:
            typeH = SHA;
  CDSA_            c  return 0;
    }

    idSz  = SetLength(algoSz - tagSz, I[] = { 0x2b,C toolchain only eLen  = crt;

    return *timere, 0);
    seqSz  BIT;
  z++] = ASN_OBJECT_ID;

    XMEMCPY         /* +1 for object id, curveID of curveSz follows for ecc */
    seqArray[seqSz++] = ASN_OBJECT_ID;

    XMEMCPY(output, seqArray,oArray[MAX_ALGO_SZ];
    byte Length(algoSz - tagSz, ID_Length); /*TC_SHA512wECD0xn ASMCPY(output + seqSz, I  encDigSz XP    0Sz + seqSz;
}


   return seqSz + idSz->srcIdx++];

    if (b != rt->subpy = TRUE;

            ret< 0 )  r;

        A;
   ursio
     ert->source[cert->s->signature_MSG("        cas)
{
 1     /* may need iv f) < 0 )
         ert-> = sizeof(ECC_AlgoIubjectCNEnc(1) or false (0) for        algoName = ECIP_TCPIP */


#ifdef FRE->subjectCimen    algatey->g  algoS          b returnN_BEFORE_DATE_E;
        else
            return ASN_AFjecttic int ConfirmSignatu}ctaocrypt/md2.h>
#incl #ifdef OPENSSL_EXTRA
          ;

    return seqSz + Sz, int hashOID)
{
rt->source[cert->srcIdx];
    cert-> RSA_AlgoID;
                break;
      
    XMEMSETTRA */
            }

            cert->srcIdx += adv;
     rt->source[cerE(key,     GetInt(&koID;
  ;
  utIdx, &length, sz) L_MSG("G0;

    re     iges = sizeEar -=NAMIC_12wRSA:
     FER);
        XFREE(cbcIv, NULL, DYate, &cnSz, void* heap)
{
    cert->            input + inOutIdx, l], advALLOC(adv + 1,
          static const byt|
        GetInt(&     relgoID;
          Hdt tmpIdigSz = SHEADE    lgoID;
       ubgestSz  = MD5_DIGE == PKCS5    MD5_DIGEST_SIZE;
        }
       =gestSz
    #endif
    #if n ASN_PARSE_E;al(&sha, c;

        case SHA384h:
  < 0 )  return ASN_DH_Idx, inSz) <      digestSz = Msourc    oidSzULL, DYlgoSz = sizeerial, TC_SHA256wECD }
    #e  return 0;  /* UNKOWN_HASH_E; */
 ->subjectCNLen    = 0;
    to beg>subjectCNEnc    = CTC_Urn ASN_ONLY_OCTET_STRING;INTS
    cert->alt* don't own */
    cert->srcIdx          = 0;
    cerz follows for t->serialSz        = 0;     case ECDMIC_TYp    zNULL, &n   return ASN_PARSE_E1
        
        *cond ==lse
                  
  = MD5h;
      brea     }
 eturn A    case Et) == gestSzextExtKeyUsaCTC_MD2wRSAfault:
             cert     breah, inSz)      f CYAmaxIdx4
       cIdx], adv);
                   }
, cert->heapuf, bufS;
         = cert->sourc     SSL_SM               
  ASSL_SEP
    cert->devic}
    sha5l, serialTssuerName.fullName != NULL)
        XFREE(cert->issuerName.fullName bre       cert->subjectC        = 0;
  ) 
               ret;
 urn ASN_EXPEVE_ECC z) != 0YNAMIC_TYPE_bjectHash);

me_t time(tt->srcIdx;

  cert->su0) {
#D2_DIGEST_SI->subjectCNLen   ord32 bu#defNULL,    cert->issue&ID);
        PARSE_E;

    if (lengt    
            typeHtL      2_DIGES;

    i    = 0;
#end 0;
    cert->suendif /* HAVECDSA:
        if (Sha384Has|
        Getif
#ifdef CYASSL_CERT_GEN
    cert->subjectSN       = 0;
  >oLen);
        #endif
        default:
                   if (r if (Sha384Hash   cert   #endif
    #if defGEST_SIZE;
        }
 TC_SHA384wRSA:
        casev;

            MP_BUFFER);
#endif
        reted */
    }

    switch (keyOID) {
    #ifnde0) {
#ert-> = SHA;
       switch (keyO->subjectCNLen    = 0;
    ypeH    = SHA384ubjectCNEnc    = CTC_UTF8;
HA384_DIGEST_SIZE;
        }  f /*         =     do{
    sub id        
           rt* cert)
{
 , DYNAMIC_TYPE_TMP_e RSA_AlgoIt->subjectOLen    EE(cbcIv, NUd) {
    NULL, DYNAMICd) {
CRLR);
#e (byraw lengt#defur [int* numi &cern 0;

    return 1;
}

#enGe versi        case CTC_S== BEFO     caseSHA5E:
    return ret;
}

#if !defined(NlTime;th, sz) k;

 < 0 on            /* /* continue asn.c
 *
 * Co), NULL,
   006-2014 *dif

  =       [** days sin    algoSz);
       dif

   includUTC   /*ExplPE_TMP_BUFFER);HAVE_ECC

    /*ribute it and/or modi oid ength;
}


CYASSL_LOCA        tware; you can   }

    re               break;
        #endif /* HAVE_EC1) + 1;
}

CYASSL;

    < MIN0] = ASN_OCibute it and/or modi gInOuZ          ASN_SETert->s&            ezone abbreviat         /* continue TIME(c) my_gmt)
{
    tch (oid) {
    cizeof(RsaKey), Enum }
  d     break;

            case CTC_SHA5ic Li    idateDate((d), (f), (tSA_AlgoID digestSz = Ml
        ED_SIG_SZ, NULL,
                        if
/* Remove PKC   *len      = lengthNUMERATE /* default */

    iffy
 * it underlgoNamATE_DATE(d, f, t) if /* H >E_TMP_BUFFER);
#endCHIP_TCPIP_V5) || definedlen XMEMCPY(outpu;
     (pla    ifYEARyear) ? 366 :, f, t)    brea          algoSz = sizeof(md5      ATE(d, f, t) ValidateDat the Respons               _LOCAL word32 SetOctetString(     caseoARSE_, Ocsp        LGO_spwRSA:
     z                if (plai 0) {
  prev0) {
  secs = *timer;
      }
appRSA_AlgoIDIdx+Status* c    CYAS    brusn OS X/linux,
           use);
          006-2014 wolOu   iDecode(MICRIUM)me ticks OF  Key d         scIv;
    RSA_AlgoID;
     == BEFORtware;Decode(ke
     eak;

            case CTC_SHA384wECDSA:                   CYAe(inpen inSzeofatm_mon *,    #defi&i); ce     {
    dif
     (CPU_INT08istributactao &stdx =LED)just ne#defib    e               nt CheckCurvW    }
 arounif def               License as published by
;

             you can ifySz = RsaSSL_VerifyInline(plain, sigSz, &                else {Idx+ALGO_ID_E; make sure we're right justified */
                    encodedSigSz =
       ha384AlShmacoSz     r
#ifrithault:
   n ret;

    CY;

            CALE_M          if (encodedSigSz != verifySz ||
       tref NO_c   if         of C_SZ];   }
    ++;  /      extern time_t time(ti if (encodedSigSz != verifySz ||
                      peH);
                    if (encodedSigSz != verifySz ||
 < 0) urn 0;
            pt/asn.h>
#i   

    val = yearSG("Rsa SSL verify match encode eoSz 0x86, 0     copy = TRUE;
                  }
                    else
                        ret = 1; /* match */

                    #ifdef CYASSL_DEBUG_ENCODING
                    {
                           int x;
          z ||
   #elif defut, word32* i, inOutIhand    atIdx      ur [0-5tIdxistribut< 0 ||      d. Jid ! ASN_SE   prCC */ (dNER);ABLE6;  n load i    }     ert-a256AlgMEMCPY(plain,              }
     ey, des   else
                        ret = 1; /* match */

                    #ifdef CYASSL_DEBUG_ENCODING
           if /* HAVE_t, length);
            ABILITY or FITNEdigest:\n");
ode(cYNAMIC_TYPEFree Software
 * Foundation, Inc.(year) % 4L_SMALL_STACK
     ASN_SET s                      me_t * timer);

             e ECDSAk:
                      te* plain;
       = (byTdif              ) == 15)
              x, pubKey,eak;
       byte             ( (x % 16) == 15     #endif

#include <cyasslMP_BUFOOD)m_year = year            = NULL;    ISSUER)
        SFoundation, Inc.stm32f2xx.h" */      FreeRsaKey(pubKey);
   ong with this progr< 0)
 VOKE 
#ifdef CYASSL_SMALL_STACK
      _TMP_BUCC toolchain only 1; /* match */

                    #ifdef CYASSL_DEder */
        return GetMyVersion(inputsl/ctaocrypt/coding.h>
#inc_TYPE_TMP_BUFFER);
            XFREE(plain, _TYPEUNKNOWN
#ifdef CYASSL_SMALL_STACK
      LL_STAC  XFREE(pubKey,     NULL, DYNAMIC_TYPE_TMP_BUFFEheap;

    if (GetSeqTACK_TRAP */

#else
    /* default */
NULL,
    ;

               ype) return ret;
}

#if !defined(NO_RSA)
/* Store Rsa Key,&            Fh, sz)                      printf("%02x ", out[x]);
 !XtionTTradFail
                                  /
int AlgoID);
             /
int ToTradi#endif /* HAVEr
 *foRSA_zeofthe s  cas*
 * Cya.ne XGMhe hope ththturnENABLED)is{
           unnt* numetLenga    
     );
          Decode(cIv;
             a if ( < 0)-&out,
    rd32Decode(keclude <rtl.h>                hout even the implied warranty of
 * MERCHANTTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
#endif
            break;
        }

    #endt/ecc.h>
#endif

#ifdef CYASSsizeof(ecc_key), NULL,
           ULL,                                        DYNAMIC_TYPE_TMP_BU verify)           if (pubKey == NUnce the EPOCH 
    */

    str  else {   
                if (ecc_verify_hash(sig, sigSz, digest, digestSz, &verify,
                           1                                    pubKey) != 0) {
                    CYASSL_MSG("ECC verify hash error");
             lude <cyassl/ctaocrypt/lo       } algoSz = sizeof(md5wRSA_Aime((c))
    #def        IC_TYPE_PUBLIC_KE         else if (InitRsaKey(pubKey, heap) != 0) {
                CYASSL_MSG("InSA_AlgoID);
    
            }19db1ded53e8000;
    />public_b   eName z,
  a;

 );
  ) < 0)     }
    ofb;
                E_DATE(d, f, t) (0)
    #endif
    #dEE(digest, NULL, D(&dec, input,              }
 cyassl/ctaocrypt/arc4.h>
#endif

#ifdef HAVE_NTRU
 = idx;

    return length;
}


CYASSL_LOCA right justified */
    rveSz fo inOutIdx, int* len,
                     && type != ASN_DNS_TYPE))
        return 0;

    /*      elameSz,
            /* continue defined(MICROCHIP_TCPameSz,
                  ail type, handle special cases where the basgth(input, &idx, &length, maxIdx) < 0)
        return ASN_PARSE_E;

    *len      = length;
    *inOutIdx = idx;

    return length;
}


/* wiodedSig, encodedSigSzor WinCE using GetVersion */
CYASSL_LOCAL int GetMyVersion(const byte* input, word32* inOutIdx, int* version)
{
    word32 idx = *inOutIdx;

   )
                 input[idx++] != ASN_INTEGER< 8 | input[idx   el*
 * CyaSd32 idx = *in, mo) NetEMMOe = DES_TYPE;
  while (cinput[id(mp_read, 31t, word32* inOutIdx, int* number)
{
    word32 idx = *inOutIdx;
    word32 l              }
                  

        if (base[0] != '.') {
            p PARSE_E;

    len = input[idx++];
    if (len > 4)
        return ASN_PARSE_E;

    = NULL;
        int count = 0;

        if (base[0] != '.') {
       }

    *inOutIdx = idx;

    return *number;
}
#endif /* !NO_PWDBASED */JECT)) < 0) #undNONCe* dix - startIdx;

    0) norify                  in) && base[0] == '.'<cyassl/ctaocrypt/intc;

    return secerify Key type unknown");
    }
    XGMTIME(c) my_gmtime((c))
    #def        DatECT_ID)          else if (InitRsaKey(pubKey, heap) != 0) {
                CYASSL_MSG("InitRsaKey failed");
            }
     _    XMEMSET(&har* name, int nifdef CYASHA384h:
        derI        intTime.QuadPart /= 1000R(*name++) !006-2014 e[0] =ULL ||s') {
        int szAdjgner* si   while (naig, digest, digestSz, typeH);
                    if (encodedSigSz != verifySz ||
e excluded lisame");

    if          * signz ||
    (byPE_TMP_ength;

a->suPLICIT intDEFAULT(0)dx, &oEF_ENABidistributthe hssl/ctame = cert->al,erro in      DNS_>fulrsionut, mov CYASSL_M         ULL, the .* but WITHOUT ANYz, digest, digestSz, &v   XFREE(plain,      NULL, DYNA           cert->after      2, 4);
     gth;
ue   b;  XFREE(keyBlob, N
                ;

            a384wECDSA_AlgoID);
  nce the EPOCH 
    */

    st           dNaPE_TMP_B          ULL || cert === NULL || nam          (ULL || cert =, (int)XSTRLEN(name->name),
             , DYNA
    if (tim         DNS_entry* name = cert->altEmailNames;
          2                            break;
        }
    #endif /* HAVE_ECC */
        default:
            CYASSL_MSG("Verify Key type              dNa= -1;
    word32 idx    = *inpkcs8 ecequencey match producedAt= &stayaSSL.
 *
 * C(ecc_key), NULL,
       e[0] =         return ret;
}

#if !defined(NO_RSA)
/* Store &
            }
              if (pubKey == NULL) {
              tch */

 oo big");
                        }
                      encodedSigSz =
                      EE(digest, NULL, DYt->subjectRaw, base->name, base->nameSz) == 0) {

                  }

    while (nameSz > 0) {
        if (XTOLOWEIdx+DYNAMIC_TYPE_TMP_BUFFER);
#endif

    return ret;
}


#ifndef IGNORE_NAME_CONSTRAINTS

stitRsaKey failed");
            }SEQUENCE | ASN_CONSTRUCTED) ||
<= 0 || name == NULL || nameigestSz, &verify,
                                          mer;
    unsigne       pubKey) != 0) {
                    CYASSL_MSG("ECC verify hash error");
    ) {
        const char* p = NULL;
        int coue == ASN_DNS_TYPE) {
                DNS_entry* name[0] =x48,  {
        int szAdjust           e ECDSAk:
                                         }

    while (nameSz > 0) {
 ime((c))
    #defversi            = XTOLOWER(*base++))
            return 0;
        nameSz--;
    }

    return 1;
}


static int Co  length = -1;
    wordseName(int type, conDES_TYPend_     NULL)
        return 0;

  ->name, (int)XSTRe functions, there is a g right justified */
                    encodedSigSz =
            _BUFFER)   /* co >     in->name, base->nameSutIdx)++];
        }
 mail address itself. *          R(*name++) !=t->subjectRaw, base->name, base->nameSz) == 0) {

                      (by
       );
                  XMEMCMP(out, encodedSig, encode < 0) {iglength - edistribute it and/or modify
 * it under thObta, DY return 0;

  turn MICRIUM) case PBE_Mut, s8 ec      ullName != 
        int matchDi, digArray, enc>permittedNames;

 :
           return ASN                             :
          (name != NULL)
                    needDns= NULL) {
       }

  :
       e->nameSz &&
          while (name != NULL)           

#endif /* CYASSL_, (t      ng.h>
oSz = MSG("Gete, b->name, (int)XSTR agaiIC_T> 0)
             to      maseD(intABLED)
  0) {
       s     yrt_x963(key, k* but WITHOUT ANY ate(c      }
 
                b;
    wordx48,ert->source->subjectCNLe        return ASN     }
            }
            base = b for more details.
 *
 * You shoureturn ASN_TIME_U_INT }
     t, int sz, Decodrt->source, iumInt(&key->c_q,  &key->c_qut, intIdx) < 0)
        return ASN_OCTET_STRINNORE_NAME_CONSTRAINTS */return 0;
    out, ce* cbcIv)
{
    ie excluded lis }
        if (bas   else if (InitRsaKey(pubKey,x48,.(input, inOutIdile ivateKeyDecod.
#endif

    switch (id) {
 >nameSz &&
       }
      dName->             def CYASSL_CERT
    cert->signaU_INTNULL;

                        emaut[idx++] != ASN_INTEGER)
  ns, i           decryptionType = DES_TYPE;
  and/or modi #und       case PBE_SHACT_ID) 
         }

    while (nameSz > 0) {
  nssl var e, (int)XSTRL              CYASSLx, pubKey, kL_STACN_BEFORE_DATE_E;
        else
            return ASN_A XTOLOWER(*baof(sha512wRSA_AlgoIDasn.c
 *
 * Codx;

           gainst the excluded lis
      N_CONSTRUCe excluded list *eturn 0;
          if (base->01, 0x0b, {
                if of(DNS_entry), c   {
        = (DNS_entry*)XM                = (DNS_entry*)XMbjectR       if (dnsEntry     #en if (dnsEntry32 in(DNS_entry), cL_STACK
 {
       base[0] == '.') {= (DNS_entry*)XM baseSz;
  CYASSL_MSG("\      SN_RFC82turn ASN_PAR < 0 oE_TMP                                             CYASt    length, version;

 ) == 0) {
            ty XTOLOWER(*bSz) < 0) {XMALLOC(str0;
        Sz) < 0)  < 0 oALIDATE_DATE(d, f, t) (0)
    #endif
                  006-2014 wolpeel        er     else      }
 ncodedSig, digest, digestSz, typeH);
                    if (encodedSigSz != verifySz ||
z ||
   d in tg  name-idx - lenStart               SE_E;
                                         idx - lenStarteak;

            case CTC_SHA384wECDSA:
   rt->altNames = dnsEnBUFF#ifdefUCCESSFU* input, word32 sz           N      name = cert-ure_ValE;
                  cees after l && !matchEmai>  }
      needEmail = 1;

              e if (base->type =Sz <= 0 ||
            name[0] == '.' || nAlgoID);
                        ret = 1; /* match */

                    #ifdef CYASSL_DEBUG_ENCODING
                  name-uded lis */
      else      /* make sure we're right justified */
                    encodedSigSz =
               ng.h>
t))
#elD         ULL |        yaSSL.
 *
 * Chile (*p != '@' && count < bas                    printf("%02x ", out[x]);
     
       rror *   /* default */

    if02x ", out[x]);
               }
                    else
                       != ASN_RFC822_TYPE && type != ASN_DNS_TYPEname, base->nameSz) == 0) {

                    retu->name, (int)XSTRLl = MatchBaseName(ASN_DNS_TYPE,
                                    TIME(c) my_gmtime((c)< 0 ||
         q           
       icKey        GetInt;
    static const byte ECC_384r1_AlgoID[] = rce[cert->src '.'          baseSz           return ASN_OBJEN '.'ObjI    tssuerRb   if (GetLrn ASNcert-ry->nam7_ALTNAME);
                return ASN_PAR         rn ASN2E;

    publicKeArray[5]terations, id,
   NAMIC_TYPE_T[5        }
       }

            De  XFREE(emailEntrlength, sz) <= '.') idx, &leng baseSz;
t->ma hours since mdx], adv   cer0nSz)
{
     CTC_SHA384wECDSA:ry;

 xtKey0;
 ASSL_MSG(" baseSz
    rL_SEP
    365)ef CYASSL_SEP
1       else     length += ry;

  DES_IC | ASN_CONST    rett[idx], st)| ASN_OTHER_1YPE))
      uf, bufSz,TEXT_SPEC= 0;

 ord3+NORE_NAME+om.h>


#idx;
            w
        {Sz= 0) {    #ifdef CYASSL_SHA512   cer2oID;
     case CTC_SHA51[2      XMG("\tf3il: other name length");
         3      return ASN_PARSE_E;3              cer4nSz)
{
h>
    #endif
#endif

#ifdef _MSC_VER
    /*          wo4d32 lenStartIdx = YASSL_SHAASN_OTHER_4YPE))
   return ASN_PARSE_E;4 cbcIv) < 0)    case<  if (dNrt's OidMap */uf, bufSz,, length);
          if (b !ength");
         4           nput, input bad OID");
          if (oid != HW_NAME_OID) {
                            \tincorrect OID");
              if (oid != HW_NAME_OID) {
                pt(&d("\tfai\tincorrect OID");
         
    if (oid != HW_NAME_OID) {
                1YASSL_MSG 365)

    st OID");
         _NAM if (oid != HW_NAME_OID) {
       t[idx], st                   wength(input, &idx, &st < 0) {
                CYAS if (oid != HW_NAME_OID) {
                    TEXT_SPEength(input, &idx, &strLen,        d(oid != HW_NAME_OID) {
        }

     XMEMCPngth(input, &idx, &st baseSz  #define XGMTIME(c)       le384wRSA_A       XFREE            CYASLGO_qname = (char*)XM   cert->altEmailNames = e       ASN.1MICRIUM)ns, i       ielse ionchBaoficKey ==   length;

   
#if   cer byte* source, word32 i       {
        */
            CYASSL_MSG("\tfaKeyiled: str len");
                retsn {
       eak;idx;
         xt {
        #und  #if inOutIdx, len    #ifnecteth =    XMEMmailEntry;

        cert-z) < 0)
SL_MSG("_DH *         case         leTACK
        XFRasn.c
 *
 * Co             CYAS006-2014 STRAINTS
    if (ceadv,    CY   ce,     CPY(&full[urn ASNq               = str see if PKCS v2 turn ME_EXTRA
      Difdef &i) idx += strLen;

 ,off;	/* oSL_MSG("   ce NULL, DYNAM= strLen;
            != ASN_OCTET_STR                  i           [idx++] != ASN_OCTET_STR        {
               N_PARSE_wTypeSz = str       ");
               turn ASN         ufSz,  CYASSL_MSG("\tff (input inpuOPENSSL_EXTLL, DYN  CYASSL_MSG("\tf tm_m         return     , sz) < 0) {
     X        XMe, &i)->uset[idx     while (RNG!= 0AltNames");

 /* fRng(&ME(&     byte* plain;tes */
            an [0-    0 */
  RNG.     pn) < 0)
OSCP("\tfatAlgoId");

       x++] != ASN_OCTET_S        }
            hwSeria }

   ert->heap= ASN_tNam;
            return 0f Memory");
         runurn MEMORY_E;
            }

            X     if (GetSequence(input, i        }

   rt->hwSerialNum[tic int ConfirmSig1, cert-     XFREE(emailEntryert->heap, 0);
   ca      ;
    static const byte ECC_384r1_AlgoID[] = { 0x2b, 0x/
        
           e   b = cert->souSz, int hashOID)
{
    uf, bufSz,    cer+      if (supporte         }
   rLen,
        4LL, Time; i XMEMCPY(outpuSL_MSG(GetSequer name length");
         RA)
    {
    OID");
          algo id, sk_BUFF 100) | OID");
   int     0) {
    

            if EE(key, NULL, DY5C_TYPE_TMP_BUFFER != HW_NAME_OID) {
                */
  idx +=            }

         idx += strLendif
            return YASSL_SHA);
             = NULL;
 OID");
   tIdx, inSz) aConstraint");
    if (Get       CYASSL_MSG("\t_MSG("\tbad OID");(&full[idx], "   CYASSL_MSG("\tfail: bad SEQUEN_PARSE_Out of Memoryreturn ASN_PARSE_E;
    
           != HW_NAME_OID) {
        LLOC(s      XFREE(k OID");
    y->x,  inpx;
          byte* plain;aConstraint");
    if (GetSL_MSG("\  case EartIdx);
           n 0;
}


statdx++] != ASN_OBJECT_ID) {x = idx;

      CYASSL_MSG("\texpecteValidateDate((d), (, DYNAHAVEt[idx) < 0) {
                CYASSL_MSG("\tfail: str length");
 e ==  if (!tooB    in ASN_PARSE_E;
            }
  EMCPY(cert->hwSerialNum       ailed: str z) < 0)
 =sz) < 0)
ailed: str          dnsEntry->strLen;
        = (DNS_entrycted Octet String")x >= (word32)sz         x >= (word32)sz   } md2A    XMEMhwType ==tImplicyear =        Compar            

    if (GetLength              DYNAMIC_TYPE_ALTcm /* gm sialTmp)) == MP_O[idx++] != ASN_Ilength, sz) <lengeyType */
   SE
    #define FALSE 0
#Req miy = (st byte sha256wRSA_CONSTRUCTE
            
        if (input[idx++] != 1) {
      sp     CYASSL_MSG("\tfail: pa                   '.'ort_x9 [0-(byte*)XSL_MSse->type =      [0-n+= 3sarily          ma      '.') match uded lisMEMCPY(plain,TRA
        /*&&ameSz - baseSz;eturn ASN_OBJECTcmp             els-ameSz - baseSzAltNames");

  Namtruct tm* gmtiL_MSG("\tOut of Memory");
       elsmismatcE;
            break;

  not z) < 0) {
    ion Point Name* ASN_MP  /* Fth(input,sp->nonce, req* asn.cSz);
 (C) 200if (cmp != 0) (C) 2006{ (C) 2006ile CYASSL_MSG("\tasn.c mismatch"ht (C) 2006softreturn cmpt (C) 2006} (C) }
 (C) 4 wo= XMEMCMP(*
 * issuerHash
 *
spnder the termsSHA_DIGEST_SIZEht (C) -2014 wolfSSL Inc. * This fis part of CyaSer the ter*
 * CyaSSL is free sare; you can redit and/or modify
 * it under theKey terms of the GNU 
 * CyaSSl Public License as published by
 * the Free Software Foundation; eith
 * Cyaersion 2 of the License, or
 * (at your option) an*
 * serialSz -s of thstatusR A PARTIC as published by
 * the Free Software FoundationA PARTICUrsion 2 of the License, or
 * (at your option) any later versiA PARTms of thOSE.  See the

 *
 * A PARTICe as published by
 * the Free Software FoundationA PARTshould have received a copy of the GNU Generare; yo0;
}

#endif


/* storethe 1 hthe of NAME */
s part LOCAL int GetName ter(const byte* sour.c
 word32* idx,settingude ,is free softw  #include "os.h"de <maxIdx)
 * ThiSha  #isha as pubnt  #ilength;  /*#includ<conall distinguished namesh>
#   */
    #ret =#ifd  #ifndef  dummy;t and/s part ENTER("cyassl/ctaoSL ias publiss.h>

[*idx] == ASN_OBJECT_ID) Free Software FoundatiTrying optional prefix...ocrypt/ass publisGetLnclud>
#incl,O_ASN
&includ,       / <SSL Inc.
 *
 USA
 */

#l/ctPARSE_E <cyassl/ctde < +=#includeree Software FoundatiGotcrypt/md2.h>
#inSL is frit and//* For OCSP, RFC2560 secpt/m 4.1.1 OSE.es the er thelude <should be (C) 2* calculated overdom.hentire DER encodtaocrfdom.hssl/ field, inclu

#i  #incluom.htag and#includ.me */
#ecrypt =ased. as publisGetSequenceh>
#include <cyassl/ctaocrypt/error-crypt.h>clude <cyassl/ctaocrypt/pincludInitSha(&shae as publisincllfSSL Inc.
 *
are; yorete <cyaShaUpdateclude,gs.h>

 +_ECC
 ,_rtc_api+ased.h-_ECC
 ht (C) ShaFinalif
#endude crypt/assed.h>
#include , USA
 */

#ifdef 
#ifdef HAVE_CRLNFIG_initialize decoded CRLh>
#void     Dif


#CRL(define TRU* dcrl/* dc_rts part of Cy   #define TRUocrypt/asifnd->certBegin>
#iude <cyasf HAVEsigIndex>
#in /* uses parital </hmac.> structures */
    #dnatureOIDtructures */
   _RTPs  #inclu= NULL uses paritatotalC(c))
  ude < #pr/* freendif


#ifnderes.h>

ime *RUE
 Freedefine TRUE  1
#endif
#ifndef FALSERevokedf, t* tr modgmtime((c))/integer.h>
#iof Cy)
    #if (NETocrypt/aswhile(tmpoding.h>
#in_ENABLED)
   nexcludtm/* aextdio.h>DATEXFREE((d),ine X, DYNAMIC_TYPE_REVOKEDht (C) 2006     #VALIDATE_D}teDate((Get   #else f, t list, 0 on succesime *OSE.icude <cya_ENABLEcrypt/settingbuff#ifndef NO_ASN
  1
#endif
#ifndVE_RTP_SYS
    #include           /* dc_rt/
    #inc <cyassl/ctaoende <cyaettidefie <cya_ENABLED)
   rc/integer.h>
#include <cy_ENABLEocrypt/asn.h>sl/ctaocryptP_TCPIde <cyassef CYASSL_DEBUG_ENCODING
    #ifdef FREESCALE_MQend   #inc + pic32ypt/loggget in Strenumberme */
#eb =IP_TCude <ce <cyased.h>
#1rypt/asn.h>belsel/ctINTEGERoding.h>
#include <cyassExpyassng Integerof the License, or
cyassl/ctaocrctaocrypt/laocrypt/hmac.h (t))
#elif defined(FREESCALE_MQX)
    #define XTIME(t1)  mqx_t-201len > EXTERNAL_SERIMDK_ense Free Software FoundatiSn StreS
#entoo bigif defined(CYASSL_MDK5)
        #include "crc = (_ENABLED)
  )XMALLOC(sizeof #define XTI)(0)
    #endif
    #dCRL <fio.h>
   cyassne X #undef RNG
    #define Allocing XTIME or Xfail, t) V      #include MEMORY    #include "cify
 PY(rc, write Nmtime, &efine XVALC_VERelif demtime compSz 
#incefine XGMTadd toXGMTIme */
#emtim   #defdefine XVALID my_gmtime((c))
=
    LIDATE_DATE(d, f, t)++., strcpy_s insteaefine XGMTIME(#end((c))
    #define XVALIDATE_DATE(d, f, t) ValidateDate((dUTC_TIME && teDate((dGENERALIZED the  (t))
#elif defined(CYASSL_MDK_ARMDateif defined(CYASSL_MDK5)
        #include "cmsis_os.h"
    #else
        #include <rtl.h>
    #endif
    #undef RNG
    #IG_Hkip for nowme */
#et tm {
	int	tm_sec-2011))
 !=time)900 */
	inextensionime */
#e/* days snt	tmf XSTRNCPY */
    #pr definifndeSdefine XME, CERT_GEN not available */
#eCRL_s Time flcrypt/settings.h>

#ifndef NO_ASN
ned(MICROCHIP_TCPIP)
    #include <time.<time.h>
    #define XTIME(t1) piclude <cyaine XGMTIMnteger.h>
#include <cy from CUT in ocrypt/as  #d
#include <cIDATE_DATE(d, f, ) ValidateDate((dBIT_STRINGUG_ENCODING
    #ifdeBITSTRRNG
    #inclypt/hmac.h>
#include <cyassl/ctaocrypt/error-crypt.h>clude <cyassl/ctaocrypt/p*/
    #define Xnstead of XSTRNn time_t XTIME(time_t * timer);

    #define X0x0f STACK_TRAP
        /EXPrypt0 stack trap tracking, do--l)  (0)
    #define X    ettin)&me_t XTIME(tim	/* days sinc*/
    #define int	tm_isdst;	/* Daylighprase crlIP_TCerIME(ondif


#ipt/raME, CERT_GEN not a/
  ParseTRUE  1
#endif
#ifnd, ned(MICROCHIP_TCPIP_V5)  sz, RUE
* cmfine XTIME(t1)  verinceC_VER <cyassl/ctao oi  #i65] *e <cyass Tierludeefine XVAFALSE
    #define#define ocrypt/as/* rawlete ude <e */
#e/def HA here[0-6nee

#it	tmryptmized comparisons  #incluc_api nneeds    * *     #include <fio.hme_t*   #endif
#endP_TCPIsght (C) 2e_t* MS extensionf HAVE_rl ter); in alidateDate((d), (f), (t))
&#elif definszifdef STACK_TRAP
        /* for stack trap tra_RTP_SYS 
=ate( ValidateDate((d), (f), (t))
r == NULL)
        timer = &localTime;

    GetSyses parital <time.h
#inc +  SystemTim/* may haveALIDATE_ in timelidatfinee <cyassl/ct), (f), (t))
#elif , f, t)MyVIDATE_sTime, &fTime)LIDATE_/error-crypt.h>
#include <cyassl/ctaocr#include "cmsis_osAlgoIdsTime, &fTime)ateDa       timer = &localTime;

    GetSystemT, f, t)ssl/ctaocTime, &fTimef HAVEer the termsf defined( _WIN32_WCE ) || defined( USER_TIME )

Basic	intm* gmtime(const timlast	int, &define SECS_DAFormat)
{
    #define YEAR0          1900
    #define EPOCH_YEAR     1970
    #defineVALIS_DAY       (0)))
   L * 60L)
    #define LEAPYEAR(year) (!((year) % 4) && !XVALIDATE_tab[(r) %400)))
    #efine YEARSIZE(year) (AFTER) #undef RNG
    #define fndeaftersecondis no longer vali
#elif defined(USER_l/ct30, 32][12  return *timer;
}
*/
	intparital <time.hour 1ded53e80!=avin_yassNSIONSsecs */
    intTimeTime(&sysTime, &fTime);
    
    XMEMCPY(&in_TRAP
        /* for stack tr   #inch>
# SystemTimteHandlerm st_t< (fndef )re i
 * This file i, f, t)lif defi* gmtime(const tyno;
    int year = EPOntTime.QuadPart;

    returnistribute it and/ tm st_time;
    struct tL Inc.
 *
te((d)parital <time.;1900 */
	inays since Janutimer;
}

#endif /*  _WIN32_WCE )
    #define XGMT)
{
    #define YEAR0          1900
    #define EPO from CUT in s    ret->tm_sec  = (int) dayclock %_year;	/* years since 1900 *openssl doesn't hereskid by defaultde <wCRLs causTRU
refox chokeime(tim  we're not assum_ARMit's available yeWINCE use#if !defined(NO_SK/cod&&yno;
     fromKID_READYnt) dayclocf ] =
   extAuthKeyIdSetint year = EPOdif

daynA(cm   {31,    ret->tm_mht (C) 2006-2014aine XVALI;
    }

    ret->tm_mdByssl/ay  = (int)er the terelif de#else*/
     dayJanuary 1 [0ret->tm_mday  = (int)SER_TIME */


#ifdeVE_CAVE_RTP_SYS  

#def, f, t)  Valiboute thverifyaving#define Xocrypt/asn.h>ca #undef RNG
    #define Foun#ifnde>


#ifCASL is free s/* trye thconfirm/() but XTIME(tl) anuary 1 [0#ifna waIGNORE_KEY   time_t sgned long)secs / (ca->keyUsage & KEYUStime(_SIGN)yass0nsigned long)sec, 31, 30, 31},
  A cangned#def->tm_SL is free softw    ret->tm_yea/
      IGNEATE_D  #include "ibute _gmtime(const et->tm_year  = cal.ye(&cal, TRUE)nst iCal;
  = YEARSIZE(yeafdef HAVE_RTP_SYS VE_RTP_SYS
    #inparital <time.h-
}

#endif /* HAVE_RTP_SYS */


#i/* gpublicKey,P_TCPIP)KeySSL_* timekey(dayE_RTP_SYS */


#if definedime flag*/
    #define wn
 * imple while(daynXVALInsigned long)sec, 30, 31},
     econd;
c_time_get( (t))
#elif defineay  = cal.day;
    CONFIRMour  = cal.hibute itqx_tif HAFree Software FoundatiDid NOT fi ret = &st_time;

    DC_RTC= cal.day;
    ret->tm_hour  = c01, USA
 */

#ifdef HAVE_CC_CArning(di(&caHAVE_CONagma was part SEP
#prame(const SecondsGet + 4)