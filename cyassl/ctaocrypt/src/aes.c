/* aes.c
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

#ifndef NO_AES

#ifdef HAVE_FIPS
    /* set NO_WRAPPERS before headers, use direct internal f()s not wrappers */
    #define FIPS_NO_WRAPPERS
#endif

#include <cyassl/ctaocrypt/aes.h>
#include <cyassl/ctaocrypt/error-crypt.h>
#include <cyassl/ctaocrypt/logging.h>
#ifdef NO_INLINE
    #include <cyassl/ctaocrypt/misc.h>
#else
    #include <ctaocrypt/src/misc.c>
#endif
#ifdef DEBUG_AESNI
    #include <stdio.h>
#endif


#ifdef _MSC_VER
    /* 4127 warning constant while(1)  */
    #pragma warning(disable: 4127)
#endif


#if defined(STM32F2_CRYPTO)
     /* STM32F2 hardware AES support for CBC, CTR modes through the STM32F2
      * Standard Peripheral Library. Documentation located in STM32F2xx
      * Standard Peripheral Library document (See note in README).
      * NOTE: no support for AES-GCM/CCM/Direct */
    #include "stm32f2xx.h"
    #include "stm32f2xx_cryp.h"
#elif defined(HAVE_COLDFIRE_SEC)
    /* Freescale Coldfire SEC support for CBC mode.
     * NOTE: no support for AES-CTR/GCM/CCM/Direct */
    #include <cyassl/ctaocrypt/types.h>
    #include "sec.h"
    #include "mcf5475_sec.h"
    #include "mcf5475_siu.h"
#elif defined(FREESCALE_MMCAU)
    /* Freescale mmCAU hardware AES support for Direct, CBC, CCM, GCM modes
     * through the CAU/mmCAU library. Documentation located in
     * ColdFire/ColdFire+ CAU and Kinetis mmCAU Software Library User
     * Guide (See note in README).
     * NOTE: no support for AES-CTR */
    #include "cau_api.h"
#elif defined(CYASSL_PIC32MZ_CRYPT)
    /* NOTE: no support for AES-CCM/Direct */
    #define DEBUG_CYASSL
    #include "cyassl/ctaocrypt/port/pic32/pic32mz-crypt.h"
#elif defined(HAVE_CAVIUM)
    #include <cyassl/ctaocrypt/logging.h>
    #include "cavium_common.h"

    /* still leave SW crypto available */
    #define NEED_AES_TABLES

    static int  AesCaviumSetKey(Aes* aes, const byte* key, word32 length,
                                const byte* iv);
    static int  AesCaviumCbcEncrypt(Aes* aes, byte* out, const byte* in,
                                    word32 length);
    static int  AesCaviumCbcDecrypt(Aes* aes, byte* out, const byte* in,
                                    word32 length);
#else
    /* using CTaoCrypt software AES implementation */
    #define NEED_AES_TABLES
#endif /* STM32F2_CRYPTO */


#ifdef NEED_AES_TABLES

static const word32 rcon[] = {
    0x01000000, 0x02000000, 0x04000000, 0x08000000,
    0x10000000, 0x20000000, 0x40000000, 0x80000000,
    0x1B000000, 0x36000000,
    /* for 128-bit blocks, Rijndael never uses more than 10 rcon values */
};

static const word32 Te[5][256] = {
{
    0xc66363a5U, 0xf87c7c84U, 0xee777799U, 0xf67b7b8dU,
    0xfff2f20dU, 0xd66b6bbdU, 0xde6f6fb1U, 0x91c5c554U,
    0x60303050U, 0x02010103U, 0xce6767a9U, 0x562b2b7dU,
    0xe7fefe19U, 0xb5d7d762U, 0x4dababe6U, 0xec76769aU,
    0x8fcaca45U, 0x1f82829dU, 0x89c9c940U, 0xfa7d7d87U,
    0xeffafa15U, 0xb25959ebU, 0x8e4747c9U, 0xfbf0f00bU,
    0x41adadecU, 0xb3d4d467U, 0x5fa2a2fdU, 0x45afafeaU,
    0x239c9cbfU, 0x53a4a4f7U, 0xe4727296U, 0x9bc0c05bU,
    0x75b7b7c2U, 0xe1fdfd1cU, 0x3d9393aeU, 0x4c26266aU,
    0x6c36365aU, 0x7e3f3f41U, 0xf5f7f702U, 0x83cccc4fU,
    0x6834345cU, 0x51a5a5f4U, 0xd1e5e534U, 0xf9f1f108U,
    0xe2717193U, 0xabd8d873U, 0x62313153U, 0x2a15153fU,
    0x0804040cU, 0x95c7c752U, 0x46232365U, 0x9dc3c35eU,
    0x30181828U, 0x379696a1U, 0x0a05050fU, 0x2f9a9ab5U,
    0x0e070709U, 0x24121236U, 0x1b80809bU, 0xdfe2e23dU,
    0xcdebeb26U, 0x4e272769U, 0x7fb2b2cdU, 0xea75759fU,
    0x1209091bU, 0x1d83839eU, 0x582c2c74U, 0x341a1a2eU,
    0x361b1b2dU, 0xdc6e6eb2U, 0xb45a5aeeU, 0x5ba0a0fbU,
    0xa45252f6U, 0x763b3b4dU, 0xb7d6d661U, 0x7db3b3ceU,
    0x5229297bU, 0xdde3e33eU, 0x5e2f2f71U, 0x13848497U,
    0xa65353f5U, 0xb9d1d168U, 0x00000000U, 0xc1eded2cU,
    0x40202060U, 0xe3fcfc1fU, 0x79b1b1c8U, 0xb65b5bedU,
    0xd46a6abeU, 0x8dcbcb46U, 0x67bebed9U, 0x7239394bU,
    0x944a4adeU, 0x984c4cd4U, 0xb05858e8U, 0x85cfcf4aU,
    0xbbd0d06bU, 0xc5efef2aU, 0x4faaaae5U, 0xedfbfb16U,
    0x864343c5U, 0x9a4d4dd7U, 0x66333355U, 0x11858594U,
    0x8a4545cfU, 0xe9f9f910U, 0x04020206U, 0xfe7f7f81U,
    0xa05050f0U, 0x783c3c44U, 0x259f9fbaU, 0x4ba8a8e3U,
    0xa25151f3U, 0x5da3a3feU, 0x804040c0U, 0x058f8f8aU,
    0x3f9292adU, 0x219d9dbcU, 0x70383848U, 0xf1f5f504U,
    0x63bcbcdfU, 0x77b6b6c1U, 0xafdada75U, 0x42212163U,
    0x20101030U, 0xe5ffff1aU, 0xfdf3f30eU, 0xbfd2d26dU,
    0x81cdcd4cU, 0x180c0c14U, 0x26131335U, 0xc3ecec2fU,
    0xbe5f5fe1U, 0x359797a2U, 0x884444ccU, 0x2e171739U,
    0x93c4c457U, 0x55a7a7f2U, 0xfc7e7e82U, 0x7a3d3d47U,
    0xc86464acU, 0xba5d5de7U, 0x3219192bU, 0xe6737395U,
    0xc06060a0U, 0x19818198U, 0x9e4f4fd1U, 0xa3dcdc7fU,
    0x44222266U, 0x542a2a7eU, 0x3b9090abU, 0x0b888883U,
    0x8c4646caU, 0xc7eeee29U, 0x6bb8b8d3U, 0x2814143cU,
    0xa7dede79U, 0xbc5e5ee2U, 0x160b0b1dU, 0xaddbdb76U,
    0xdbe0e03bU, 0x64323256U, 0x743a3a4eU, 0x140a0a1eU,
    0x924949dbU, 0x0c06060aU, 0x4824246cU, 0xb85c5ce4U,
    0x9fc2c25dU, 0xbdd3d36eU, 0x43acacefU, 0xc46262a6U,
    0x399191a8U, 0x319595a4U, 0xd3e4e437U, 0xf279798bU,
    0xd5e7e732U, 0x8bc8c843U, 0x6e373759U, 0xda6d6db7U,
    0x018d8d8cU, 0xb1d5d564U, 0x9c4e4ed2U, 0x49a9a9e0U,
    0xd86c6cb4U, 0xac5656faU, 0xf3f4f407U, 0xcfeaea25U,
    0xca6565afU, 0xf47a7a8eU, 0x47aeaee9U, 0x10080818U,
    0x6fbabad5U, 0xf0787888U, 0x4a25256fU, 0x5c2e2e72U,
    0x381c1c24U, 0x57a6a6f1U, 0x73b4b4c7U, 0x97c6c651U,
    0xcbe8e823U, 0xa1dddd7cU, 0xe874749cU, 0x3e1f1f21U,
    0x964b4bddU, 0x61bdbddcU, 0x0d8b8b86U, 0x0f8a8a85U,
    0xe0707090U, 0x7c3e3e42U, 0x71b5b5c4U, 0xcc6666aaU,
    0x904848d8U, 0x06030305U, 0xf7f6f601U, 0x1c0e0e12U,
    0xc26161a3U, 0x6a35355fU, 0xae5757f9U, 0x69b9b9d0U,
    0x17868691U, 0x99c1c158U, 0x3a1d1d27U, 0x279e9eb9U,
    0xd9e1e138U, 0xebf8f813U, 0x2b9898b3U, 0x22111133U,
    0xd26969bbU, 0xa9d9d970U, 0x078e8e89U, 0x339494a7U,
    0x2d9b9bb6U, 0x3c1e1e22U, 0x15878792U, 0xc9e9e920U,
    0x87cece49U, 0xaa5555ffU, 0x50282878U, 0xa5dfdf7aU,
    0x038c8c8fU, 0x59a1a1f8U, 0x09898980U, 0x1a0d0d17U,
    0x65bfbfdaU, 0xd7e6e631U, 0x844242c6U, 0xd06868b8U,
    0x824141c3U, 0x299999b0U, 0x5a2d2d77U, 0x1e0f0f11U,
    0x7bb0b0cbU, 0xa85454fcU, 0x6dbbbbd6U, 0x2c16163aU,
},
{
    0xa5c66363U, 0x84f87c7cU, 0x99ee7777U, 0x8df67b7bU,
    0x0dfff2f2U, 0xbdd66b6bU, 0xb1de6f6fU, 0x5491c5c5U,
    0x50603030U, 0x03020101U, 0xa9ce6767U, 0x7d562b2bU,
    0x19e7fefeU, 0x62b5d7d7U, 0xe64dababU, 0x9aec7676U,
    0x458fcacaU, 0x9d1f8282U, 0x4089c9c9U, 0x87fa7d7dU,
    0x15effafaU, 0xebb25959U, 0xc98e4747U, 0x0bfbf0f0U,
    0xec41adadU, 0x67b3d4d4U, 0xfd5fa2a2U, 0xea45afafU,
    0xbf239c9cU, 0xf753a4a4U, 0x96e47272U, 0x5b9bc0c0U,
    0xc275b7b7U, 0x1ce1fdfdU, 0xae3d9393U, 0x6a4c2626U,
    0x5a6c3636U, 0x417e3f3fU, 0x02f5f7f7U, 0x4f83ccccU,
    0x5c683434U, 0xf451a5a5U, 0x34d1e5e5U, 0x08f9f1f1U,
    0x93e27171U, 0x73abd8d8U, 0x53623131U, 0x3f2a1515U,
    0x0c080404U, 0x5295c7c7U, 0x65462323U, 0x5e9dc3c3U,
    0x28301818U, 0xa1379696U, 0x0f0a0505U, 0xb52f9a9aU,
    0x090e0707U, 0x36241212U, 0x9b1b8080U, 0x3ddfe2e2U,
    0x26cdebebU, 0x694e2727U, 0xcd7fb2b2U, 0x9fea7575U,
    0x1b120909U, 0x9e1d8383U, 0x74582c2cU, 0x2e341a1aU,
    0x2d361b1bU, 0xb2dc6e6eU, 0xeeb45a5aU, 0xfb5ba0a0U,
    0xf6a45252U, 0x4d763b3bU, 0x61b7d6d6U, 0xce7db3b3U,
    0x7b522929U, 0x3edde3e3U, 0x715e2f2fU, 0x97138484U,
    0xf5a65353U, 0x68b9d1d1U, 0x00000000U, 0x2cc1ededU,
    0x60402020U, 0x1fe3fcfcU, 0xc879b1b1U, 0xedb65b5bU,
    0xbed46a6aU, 0x468dcbcbU, 0xd967bebeU, 0x4b723939U,
    0xde944a4aU, 0xd4984c4cU, 0xe8b05858U, 0x4a85cfcfU,
    0x6bbbd0d0U, 0x2ac5efefU, 0xe54faaaaU, 0x16edfbfbU,
    0xc5864343U, 0xd79a4d4dU, 0x55663333U, 0x94118585U,
    0xcf8a4545U, 0x10e9f9f9U, 0x06040202U, 0x81fe7f7fU,
    0xf0a05050U, 0x44783c3cU, 0xba259f9fU, 0xe34ba8a8U,
    0xf3a25151U, 0xfe5da3a3U, 0xc0804040U, 0x8a058f8fU,
    0xad3f9292U, 0xbc219d9dU, 0x48703838U, 0x04f1f5f5U,
    0xdf63bcbcU, 0xc177b6b6U, 0x75afdadaU, 0x63422121U,
    0x30201010U, 0x1ae5ffffU, 0x0efdf3f3U, 0x6dbfd2d2U,
    0x4c81cdcdU, 0x14180c0cU, 0x35261313U, 0x2fc3ececU,
    0xe1be5f5fU, 0xa2359797U, 0xcc884444U, 0x392e1717U,
    0x5793c4c4U, 0xf255a7a7U, 0x82fc7e7eU, 0x477a3d3dU,
    0xacc86464U, 0xe7ba5d5dU, 0x2b321919U, 0x95e67373U,
    0xa0c06060U, 0x98198181U, 0xd19e4f4fU, 0x7fa3dcdcU,
    0x66442222U, 0x7e542a2aU, 0xab3b9090U, 0x830b8888U,
    0xca8c4646U, 0x29c7eeeeU, 0xd36bb8b8U, 0x3c281414U,
    0x79a7dedeU, 0xe2bc5e5eU, 0x1d160b0bU, 0x76addbdbU,
    0x3bdbe0e0U, 0x56643232U, 0x4e743a3aU, 0x1e140a0aU,
    0xdb924949U, 0x0a0c0606U, 0x6c482424U, 0xe4b85c5cU,
    0x5d9fc2c2U, 0x6ebdd3d3U, 0xef43acacU, 0xa6c46262U,
    0xa8399191U, 0xa4319595U, 0x37d3e4e4U, 0x8bf27979U,
    0x32d5e7e7U, 0x438bc8c8U, 0x596e3737U, 0xb7da6d6dU,
    0x8c018d8dU, 0x64b1d5d5U, 0xd29c4e4eU, 0xe049a9a9U,
    0xb4d86c6cU, 0xfaac5656U, 0x07f3f4f4U, 0x25cfeaeaU,
    0xafca6565U, 0x8ef47a7aU, 0xe947aeaeU, 0x18100808U,
    0xd56fbabaU, 0x88f07878U, 0x6f4a2525U, 0x725c2e2eU,
    0x24381c1cU, 0xf157a6a6U, 0xc773b4b4U, 0x5197c6c6U,
    0x23cbe8e8U, 0x7ca1ddddU, 0x9ce87474U, 0x213e1f1fU,
    0xdd964b4bU, 0xdc61bdbdU, 0x860d8b8bU, 0x850f8a8aU,
    0x90e07070U, 0x427c3e3eU, 0xc471b5b5U, 0xaacc6666U,
    0xd8904848U, 0x05060303U, 0x01f7f6f6U, 0x121c0e0eU,
    0xa3c26161U, 0x5f6a3535U, 0xf9ae5757U, 0xd069b9b9U,
    0x91178686U, 0x5899c1c1U, 0x273a1d1dU, 0xb9279e9eU,
    0x38d9e1e1U, 0x13ebf8f8U, 0xb32b9898U, 0x33221111U,
    0xbbd26969U, 0x70a9d9d9U, 0x89078e8eU, 0xa7339494U,
    0xb62d9b9bU, 0x223c1e1eU, 0x92158787U, 0x20c9e9e9U,
    0x4987ceceU, 0xffaa5555U, 0x78502828U, 0x7aa5dfdfU,
    0x8f038c8cU, 0xf859a1a1U, 0x80098989U, 0x171a0d0dU,
    0xda65bfbfU, 0x31d7e6e6U, 0xc6844242U, 0xb8d06868U,
    0xc3824141U, 0xb0299999U, 0x775a2d2dU, 0x111e0f0fU,
    0xcb7bb0b0U, 0xfca85454U, 0xd66dbbbbU, 0x3a2c1616U,
},
{
    0x63a5c663U, 0x7c84f87cU, 0x7799ee77U, 0x7b8df67bU,
    0xf20dfff2U, 0x6bbdd66bU, 0x6fb1de6fU, 0xc55491c5U,
    0x30506030U, 0x01030201U, 0x67a9ce67U, 0x2b7d562bU,
    0xfe19e7feU, 0xd762b5d7U, 0xabe64dabU, 0x769aec76U,
    0xca458fcaU, 0x829d1f82U, 0xc94089c9U, 0x7d87fa7dU,
    0xfa15effaU, 0x59ebb259U, 0x47c98e47U, 0xf00bfbf0U,
    0xadec41adU, 0xd467b3d4U, 0xa2fd5fa2U, 0xafea45afU,
    0x9cbf239cU, 0xa4f753a4U, 0x7296e472U, 0xc05b9bc0U,
    0xb7c275b7U, 0xfd1ce1fdU, 0x93ae3d93U, 0x266a4c26U,
    0x365a6c36U, 0x3f417e3fU, 0xf702f5f7U, 0xcc4f83ccU,
    0x345c6834U, 0xa5f451a5U, 0xe534d1e5U, 0xf108f9f1U,
    0x7193e271U, 0xd873abd8U, 0x31536231U, 0x153f2a15U,
    0x040c0804U, 0xc75295c7U, 0x23654623U, 0xc35e9dc3U,
    0x18283018U, 0x96a13796U, 0x050f0a05U, 0x9ab52f9aU,
    0x07090e07U, 0x12362412U, 0x809b1b80U, 0xe23ddfe2U,
    0xeb26cdebU, 0x27694e27U, 0xb2cd7fb2U, 0x759fea75U,
    0x091b1209U, 0x839e1d83U, 0x2c74582cU, 0x1a2e341aU,
    0x1b2d361bU, 0x6eb2dc6eU, 0x5aeeb45aU, 0xa0fb5ba0U,
    0x52f6a452U, 0x3b4d763bU, 0xd661b7d6U, 0xb3ce7db3U,
    0x297b5229U, 0xe33edde3U, 0x2f715e2fU, 0x84971384U,
    0x53f5a653U, 0xd168b9d1U, 0x00000000U, 0xed2cc1edU,
    0x20604020U, 0xfc1fe3fcU, 0xb1c879b1U, 0x5bedb65bU,
    0x6abed46aU, 0xcb468dcbU, 0xbed967beU, 0x394b7239U,
    0x4ade944aU, 0x4cd4984cU, 0x58e8b058U, 0xcf4a85cfU,
    0xd06bbbd0U, 0xef2ac5efU, 0xaae54faaU, 0xfb16edfbU,
    0x43c58643U, 0x4dd79a4dU, 0x33556633U, 0x85941185U,
    0x45cf8a45U, 0xf910e9f9U, 0x02060402U, 0x7f81fe7fU,
    0x50f0a050U, 0x3c44783cU, 0x9fba259fU, 0xa8e34ba8U,
    0x51f3a251U, 0xa3fe5da3U, 0x40c08040U, 0x8f8a058fU,
    0x92ad3f92U, 0x9dbc219dU, 0x38487038U, 0xf504f1f5U,
    0xbcdf63bcU, 0xb6c177b6U, 0xda75afdaU, 0x21634221U,
    0x10302010U, 0xff1ae5ffU, 0xf30efdf3U, 0xd26dbfd2U,
    0xcd4c81cdU, 0x0c14180cU, 0x13352613U, 0xec2fc3ecU,
    0x5fe1be5fU, 0x97a23597U, 0x44cc8844U, 0x17392e17U,
    0xc45793c4U, 0xa7f255a7U, 0x7e82fc7eU, 0x3d477a3dU,
    0x64acc864U, 0x5de7ba5dU, 0x192b3219U, 0x7395e673U,
    0x60a0c060U, 0x81981981U, 0x4fd19e4fU, 0xdc7fa3dcU,
    0x22664422U, 0x2a7e542aU, 0x90ab3b90U, 0x88830b88U,
    0x46ca8c46U, 0xee29c7eeU, 0xb8d36bb8U, 0x143c2814U,
    0xde79a7deU, 0x5ee2bc5eU, 0x0b1d160bU, 0xdb76addbU,
    0xe03bdbe0U, 0x32566432U, 0x3a4e743aU, 0x0a1e140aU,
    0x49db9249U, 0x060a0c06U, 0x246c4824U, 0x5ce4b85cU,
    0xc25d9fc2U, 0xd36ebdd3U, 0xacef43acU, 0x62a6c462U,
    0x91a83991U, 0x95a43195U, 0xe437d3e4U, 0x798bf279U,
    0xe732d5e7U, 0xc8438bc8U, 0x37596e37U, 0x6db7da6dU,
    0x8d8c018dU, 0xd564b1d5U, 0x4ed29c4eU, 0xa9e049a9U,
    0x6cb4d86cU, 0x56faac56U, 0xf407f3f4U, 0xea25cfeaU,
    0x65afca65U, 0x7a8ef47aU, 0xaee947aeU, 0x08181008U,
    0xbad56fbaU, 0x7888f078U, 0x256f4a25U, 0x2e725c2eU,
    0x1c24381cU, 0xa6f157a6U, 0xb4c773b4U, 0xc65197c6U,
    0xe823cbe8U, 0xdd7ca1ddU, 0x749ce874U, 0x1f213e1fU,
    0x4bdd964bU, 0xbddc61bdU, 0x8b860d8bU, 0x8a850f8aU,
    0x7090e070U, 0x3e427c3eU, 0xb5c471b5U, 0x66aacc66U,
    0x48d89048U, 0x03050603U, 0xf601f7f6U, 0x0e121c0eU,
    0x61a3c261U, 0x355f6a35U, 0x57f9ae57U, 0xb9d069b9U,
    0x86911786U, 0xc15899c1U, 0x1d273a1dU, 0x9eb9279eU,
    0xe138d9e1U, 0xf813ebf8U, 0x98b32b98U, 0x11332211U,
    0x69bbd269U, 0xd970a9d9U, 0x8e89078eU, 0x94a73394U,
    0x9bb62d9bU, 0x1e223c1eU, 0x87921587U, 0xe920c9e9U,
    0xce4987ceU, 0x55ffaa55U, 0x28785028U, 0xdf7aa5dfU,
    0x8c8f038cU, 0xa1f859a1U, 0x89800989U, 0x0d171a0dU,
    0xbfda65bfU, 0xe631d7e6U, 0x42c68442U, 0x68b8d068U,
    0x41c38241U, 0x99b02999U, 0x2d775a2dU, 0x0f111e0fU,
    0xb0cb7bb0U, 0x54fca854U, 0xbbd66dbbU, 0x163a2c16U,
},
{
    0x6363a5c6U, 0x7c7c84f8U, 0x777799eeU, 0x7b7b8df6U,
    0xf2f20dffU, 0x6b6bbdd6U, 0x6f6fb1deU, 0xc5c55491U,
    0x30305060U, 0x01010302U, 0x6767a9ceU, 0x2b2b7d56U,
    0xfefe19e7U, 0xd7d762b5U, 0xababe64dU, 0x76769aecU,
    0xcaca458fU, 0x82829d1fU, 0xc9c94089U, 0x7d7d87faU,
    0xfafa15efU, 0x5959ebb2U, 0x4747c98eU, 0xf0f00bfbU,
    0xadadec41U, 0xd4d467b3U, 0xa2a2fd5fU, 0xafafea45U,
    0x9c9cbf23U, 0xa4a4f753U, 0x727296e4U, 0xc0c05b9bU,
    0xb7b7c275U, 0xfdfd1ce1U, 0x9393ae3dU, 0x26266a4cU,
    0x36365a6cU, 0x3f3f417eU, 0xf7f702f5U, 0xcccc4f83U,
    0x34345c68U, 0xa5a5f451U, 0xe5e534d1U, 0xf1f108f9U,
    0x717193e2U, 0xd8d873abU, 0x31315362U, 0x15153f2aU,
    0x04040c08U, 0xc7c75295U, 0x23236546U, 0xc3c35e9dU,
    0x18182830U, 0x9696a137U, 0x05050f0aU, 0x9a9ab52fU,
    0x0707090eU, 0x12123624U, 0x80809b1bU, 0xe2e23ddfU,
    0xebeb26cdU, 0x2727694eU, 0xb2b2cd7fU, 0x75759feaU,
    0x09091b12U, 0x83839e1dU, 0x2c2c7458U, 0x1a1a2e34U,
    0x1b1b2d36U, 0x6e6eb2dcU, 0x5a5aeeb4U, 0xa0a0fb5bU,
    0x5252f6a4U, 0x3b3b4d76U, 0xd6d661b7U, 0xb3b3ce7dU,
    0x29297b52U, 0xe3e33eddU, 0x2f2f715eU, 0x84849713U,
    0x5353f5a6U, 0xd1d168b9U, 0x00000000U, 0xeded2cc1U,
    0x20206040U, 0xfcfc1fe3U, 0xb1b1c879U, 0x5b5bedb6U,
    0x6a6abed4U, 0xcbcb468dU, 0xbebed967U, 0x39394b72U,
    0x4a4ade94U, 0x4c4cd498U, 0x5858e8b0U, 0xcfcf4a85U,
    0xd0d06bbbU, 0xefef2ac5U, 0xaaaae54fU, 0xfbfb16edU,
    0x4343c586U, 0x4d4dd79aU, 0x33335566U, 0x85859411U,
    0x4545cf8aU, 0xf9f910e9U, 0x02020604U, 0x7f7f81feU,
    0x5050f0a0U, 0x3c3c4478U, 0x9f9fba25U, 0xa8a8e34bU,
    0x5151f3a2U, 0xa3a3fe5dU, 0x4040c080U, 0x8f8f8a05U,
    0x9292ad3fU, 0x9d9dbc21U, 0x38384870U, 0xf5f504f1U,
    0xbcbcdf63U, 0xb6b6c177U, 0xdada75afU, 0x21216342U,
    0x10103020U, 0xffff1ae5U, 0xf3f30efdU, 0xd2d26dbfU,
    0xcdcd4c81U, 0x0c0c1418U, 0x13133526U, 0xecec2fc3U,
    0x5f5fe1beU, 0x9797a235U, 0x4444cc88U, 0x1717392eU,
    0xc4c45793U, 0xa7a7f255U, 0x7e7e82fcU, 0x3d3d477aU,
    0x6464acc8U, 0x5d5de7baU, 0x19192b32U, 0x737395e6U,
    0x6060a0c0U, 0x81819819U, 0x4f4fd19eU, 0xdcdc7fa3U,
    0x22226644U, 0x2a2a7e54U, 0x9090ab3bU, 0x8888830bU,
    0x4646ca8cU, 0xeeee29c7U, 0xb8b8d36bU, 0x14143c28U,
    0xdede79a7U, 0x5e5ee2bcU, 0x0b0b1d16U, 0xdbdb76adU,
    0xe0e03bdbU, 0x32325664U, 0x3a3a4e74U, 0x0a0a1e14U,
    0x4949db92U, 0x06060a0cU, 0x24246c48U, 0x5c5ce4b8U,
    0xc2c25d9fU, 0xd3d36ebdU, 0xacacef43U, 0x6262a6c4U,
    0x9191a839U, 0x9595a431U, 0xe4e437d3U, 0x79798bf2U,
    0xe7e732d5U, 0xc8c8438bU, 0x3737596eU, 0x6d6db7daU,
    0x8d8d8c01U, 0xd5d564b1U, 0x4e4ed29cU, 0xa9a9e049U,
    0x6c6cb4d8U, 0x5656faacU, 0xf4f407f3U, 0xeaea25cfU,
    0x6565afcaU, 0x7a7a8ef4U, 0xaeaee947U, 0x08081810U,
    0xbabad56fU, 0x787888f0U, 0x25256f4aU, 0x2e2e725cU,
    0x1c1c2438U, 0xa6a6f157U, 0xb4b4c773U, 0xc6c65197U,
    0xe8e823cbU, 0xdddd7ca1U, 0x74749ce8U, 0x1f1f213eU,
    0x4b4bdd96U, 0xbdbddc61U, 0x8b8b860dU, 0x8a8a850fU,
    0x707090e0U, 0x3e3e427cU, 0xb5b5c471U, 0x6666aaccU,
    0x4848d890U, 0x03030506U, 0xf6f601f7U, 0x0e0e121cU,
    0x6161a3c2U, 0x35355f6aU, 0x5757f9aeU, 0xb9b9d069U,
    0x86869117U, 0xc1c15899U, 0x1d1d273aU, 0x9e9eb927U,
    0xe1e138d9U, 0xf8f813ebU, 0x9898b32bU, 0x11113322U,
    0x6969bbd2U, 0xd9d970a9U, 0x8e8e8907U, 0x9494a733U,
    0x9b9bb62dU, 0x1e1e223cU, 0x87879215U, 0xe9e920c9U,
    0xcece4987U, 0x5555ffaaU, 0x28287850U, 0xdfdf7aa5U,
    0x8c8c8f03U, 0xa1a1f859U, 0x89898009U, 0x0d0d171aU,
    0xbfbfda65U, 0xe6e631d7U, 0x4242c684U, 0x6868b8d0U,
    0x4141c382U, 0x9999b029U, 0x2d2d775aU, 0x0f0f111eU,
    0xb0b0cb7bU, 0x5454fca8U, 0xbbbbd66dU, 0x16163a2cU,
},
{
    0x63636363U, 0x7c7c7c7cU, 0x77777777U, 0x7b7b7b7bU,
    0xf2f2f2f2U, 0x6b6b6b6bU, 0x6f6f6f6fU, 0xc5c5c5c5U,
    0x30303030U, 0x01010101U, 0x67676767U, 0x2b2b2b2bU,
    0xfefefefeU, 0xd7d7d7d7U, 0xababababU, 0x76767676U,
    0xcacacacaU, 0x82828282U, 0xc9c9c9c9U, 0x7d7d7d7dU,
    0xfafafafaU, 0x59595959U, 0x47474747U, 0xf0f0f0f0U,
    0xadadadadU, 0xd4d4d4d4U, 0xa2a2a2a2U, 0xafafafafU,
    0x9c9c9c9cU, 0xa4a4a4a4U, 0x72727272U, 0xc0c0c0c0U,
    0xb7b7b7b7U, 0xfdfdfdfdU, 0x93939393U, 0x26262626U,
    0x36363636U, 0x3f3f3f3fU, 0xf7f7f7f7U, 0xccccccccU,
    0x34343434U, 0xa5a5a5a5U, 0xe5e5e5e5U, 0xf1f1f1f1U,
    0x71717171U, 0xd8d8d8d8U, 0x31313131U, 0x15151515U,
    0x04040404U, 0xc7c7c7c7U, 0x23232323U, 0xc3c3c3c3U,
    0x18181818U, 0x96969696U, 0x05050505U, 0x9a9a9a9aU,
    0x07070707U, 0x12121212U, 0x80808080U, 0xe2e2e2e2U,
    0xebebebebU, 0x27272727U, 0xb2b2b2b2U, 0x75757575U,
    0x09090909U, 0x83838383U, 0x2c2c2c2cU, 0x1a1a1a1aU,
    0x1b1b1b1bU, 0x6e6e6e6eU, 0x5a5a5a5aU, 0xa0a0a0a0U,
    0x52525252U, 0x3b3b3b3bU, 0xd6d6d6d6U, 0xb3b3b3b3U,
    0x29292929U, 0xe3e3e3e3U, 0x2f2f2f2fU, 0x84848484U,
    0x53535353U, 0xd1d1d1d1U, 0x00000000U, 0xededededU,
    0x20202020U, 0xfcfcfcfcU, 0xb1b1b1b1U, 0x5b5b5b5bU,
    0x6a6a6a6aU, 0xcbcbcbcbU, 0xbebebebeU, 0x39393939U,
    0x4a4a4a4aU, 0x4c4c4c4cU, 0x58585858U, 0xcfcfcfcfU,
    0xd0d0d0d0U, 0xefefefefU, 0xaaaaaaaaU, 0xfbfbfbfbU,
    0x43434343U, 0x4d4d4d4dU, 0x33333333U, 0x85858585U,
    0x45454545U, 0xf9f9f9f9U, 0x02020202U, 0x7f7f7f7fU,
    0x50505050U, 0x3c3c3c3cU, 0x9f9f9f9fU, 0xa8a8a8a8U,
    0x51515151U, 0xa3a3a3a3U, 0x40404040U, 0x8f8f8f8fU,
    0x92929292U, 0x9d9d9d9dU, 0x38383838U, 0xf5f5f5f5U,
    0xbcbcbcbcU, 0xb6b6b6b6U, 0xdadadadaU, 0x21212121U,
    0x10101010U, 0xffffffffU, 0xf3f3f3f3U, 0xd2d2d2d2U,
    0xcdcdcdcdU, 0x0c0c0c0cU, 0x13131313U, 0xececececU,
    0x5f5f5f5fU, 0x97979797U, 0x44444444U, 0x17171717U,
    0xc4c4c4c4U, 0xa7a7a7a7U, 0x7e7e7e7eU, 0x3d3d3d3dU,
    0x64646464U, 0x5d5d5d5dU, 0x19191919U, 0x73737373U,
    0x60606060U, 0x81818181U, 0x4f4f4f4fU, 0xdcdcdcdcU,
    0x22222222U, 0x2a2a2a2aU, 0x90909090U, 0x88888888U,
    0x46464646U, 0xeeeeeeeeU, 0xb8b8b8b8U, 0x14141414U,
    0xdedededeU, 0x5e5e5e5eU, 0x0b0b0b0bU, 0xdbdbdbdbU,
    0xe0e0e0e0U, 0x32323232U, 0x3a3a3a3aU, 0x0a0a0a0aU,
    0x49494949U, 0x06060606U, 0x24242424U, 0x5c5c5c5cU,
    0xc2c2c2c2U, 0xd3d3d3d3U, 0xacacacacU, 0x62626262U,
    0x91919191U, 0x95959595U, 0xe4e4e4e4U, 0x79797979U,
    0xe7e7e7e7U, 0xc8c8c8c8U, 0x37373737U, 0x6d6d6d6dU,
    0x8d8d8d8dU, 0xd5d5d5d5U, 0x4e4e4e4eU, 0xa9a9a9a9U,
    0x6c6c6c6cU, 0x56565656U, 0xf4f4f4f4U, 0xeaeaeaeaU,
    0x65656565U, 0x7a7a7a7aU, 0xaeaeaeaeU, 0x08080808U,
    0xbabababaU, 0x78787878U, 0x25252525U, 0x2e2e2e2eU,
    0x1c1c1c1cU, 0xa6a6a6a6U, 0xb4b4b4b4U, 0xc6c6c6c6U,
    0xe8e8e8e8U, 0xddddddddU, 0x74747474U, 0x1f1f1f1fU,
    0x4b4b4b4bU, 0xbdbdbdbdU, 0x8b8b8b8bU, 0x8a8a8a8aU,
    0x70707070U, 0x3e3e3e3eU, 0xb5b5b5b5U, 0x66666666U,
    0x48484848U, 0x03030303U, 0xf6f6f6f6U, 0x0e0e0e0eU,
    0x61616161U, 0x35353535U, 0x57575757U, 0xb9b9b9b9U,
    0x86868686U, 0xc1c1c1c1U, 0x1d1d1d1dU, 0x9e9e9e9eU,
    0xe1e1e1e1U, 0xf8f8f8f8U, 0x98989898U, 0x11111111U,
    0x69696969U, 0xd9d9d9d9U, 0x8e8e8e8eU, 0x94949494U,
    0x9b9b9b9bU, 0x1e1e1e1eU, 0x87878787U, 0xe9e9e9e9U,
    0xcecececeU, 0x55555555U, 0x28282828U, 0xdfdfdfdfU,
    0x8c8c8c8cU, 0xa1a1a1a1U, 0x89898989U, 0x0d0d0d0dU,
    0xbfbfbfbfU, 0xe6e6e6e6U, 0x42424242U, 0x68686868U,
    0x41414141U, 0x99999999U, 0x2d2d2d2dU, 0x0f0f0f0fU,
    0xb0b0b0b0U, 0x54545454U, 0xbbbbbbbbU, 0x16161616U,
}
};

static const word32 Td[5][256] = {
{
    0x51f4a750U, 0x7e416553U, 0x1a17a4c3U, 0x3a275e96U,
    0x3bab6bcbU, 0x1f9d45f1U, 0xacfa58abU, 0x4be30393U,
    0x2030fa55U, 0xad766df6U, 0x88cc7691U, 0xf5024c25U,
    0x4fe5d7fcU, 0xc52acbd7U, 0x26354480U, 0xb562a38fU,
    0xdeb15a49U, 0x25ba1b67U, 0x45ea0e98U, 0x5dfec0e1U,
    0xc32f7502U, 0x814cf012U, 0x8d4697a3U, 0x6bd3f9c6U,
    0x038f5fe7U, 0x15929c95U, 0xbf6d7aebU, 0x955259daU,
    0xd4be832dU, 0x587421d3U, 0x49e06929U, 0x8ec9c844U,
    0x75c2896aU, 0xf48e7978U, 0x99583e6bU, 0x27b971ddU,
    0xbee14fb6U, 0xf088ad17U, 0xc920ac66U, 0x7dce3ab4U,
    0x63df4a18U, 0xe51a3182U, 0x97513360U, 0x62537f45U,
    0xb16477e0U, 0xbb6bae84U, 0xfe81a01cU, 0xf9082b94U,
    0x70486858U, 0x8f45fd19U, 0x94de6c87U, 0x527bf8b7U,
    0xab73d323U, 0x724b02e2U, 0xe31f8f57U, 0x6655ab2aU,
    0xb2eb2807U, 0x2fb5c203U, 0x86c57b9aU, 0xd33708a5U,
    0x302887f2U, 0x23bfa5b2U, 0x02036abaU, 0xed16825cU,
    0x8acf1c2bU, 0xa779b492U, 0xf307f2f0U, 0x4e69e2a1U,
    0x65daf4cdU, 0x0605bed5U, 0xd134621fU, 0xc4a6fe8aU,
    0x342e539dU, 0xa2f355a0U, 0x058ae132U, 0xa4f6eb75U,
    0x0b83ec39U, 0x4060efaaU, 0x5e719f06U, 0xbd6e1051U,
    0x3e218af9U, 0x96dd063dU, 0xdd3e05aeU, 0x4de6bd46U,
    0x91548db5U, 0x71c45d05U, 0x0406d46fU, 0x605015ffU,
    0x1998fb24U, 0xd6bde997U, 0x894043ccU, 0x67d99e77U,
    0xb0e842bdU, 0x07898b88U, 0xe7195b38U, 0x79c8eedbU,
    0xa17c0a47U, 0x7c420fe9U, 0xf8841ec9U, 0x00000000U,
    0x09808683U, 0x322bed48U, 0x1e1170acU, 0x6c5a724eU,
    0xfd0efffbU, 0x0f853856U, 0x3daed51eU, 0x362d3927U,
    0x0a0fd964U, 0x685ca621U, 0x9b5b54d1U, 0x24362e3aU,
    0x0c0a67b1U, 0x9357e70fU, 0xb4ee96d2U, 0x1b9b919eU,
    0x80c0c54fU, 0x61dc20a2U, 0x5a774b69U, 0x1c121a16U,
    0xe293ba0aU, 0xc0a02ae5U, 0x3c22e043U, 0x121b171dU,
    0x0e090d0bU, 0xf28bc7adU, 0x2db6a8b9U, 0x141ea9c8U,
    0x57f11985U, 0xaf75074cU, 0xee99ddbbU, 0xa37f60fdU,
    0xf701269fU, 0x5c72f5bcU, 0x44663bc5U, 0x5bfb7e34U,
    0x8b432976U, 0xcb23c6dcU, 0xb6edfc68U, 0xb8e4f163U,
    0xd731dccaU, 0x42638510U, 0x13972240U, 0x84c61120U,
    0x854a247dU, 0xd2bb3df8U, 0xaef93211U, 0xc729a16dU,
    0x1d9e2f4bU, 0xdcb230f3U, 0x0d8652ecU, 0x77c1e3d0U,
    0x2bb3166cU, 0xa970b999U, 0x119448faU, 0x47e96422U,
    0xa8fc8cc4U, 0xa0f03f1aU, 0x567d2cd8U, 0x223390efU,
    0x87494ec7U, 0xd938d1c1U, 0x8ccaa2feU, 0x98d40b36U,
    0xa6f581cfU, 0xa57ade28U, 0xdab78e26U, 0x3fadbfa4U,
    0x2c3a9de4U, 0x5078920dU, 0x6a5fcc9bU, 0x547e4662U,
    0xf68d13c2U, 0x90d8b8e8U, 0x2e39f75eU, 0x82c3aff5U,
    0x9f5d80beU, 0x69d0937cU, 0x6fd52da9U, 0xcf2512b3U,
    0xc8ac993bU, 0x10187da7U, 0xe89c636eU, 0xdb3bbb7bU,
    0xcd267809U, 0x6e5918f4U, 0xec9ab701U, 0x834f9aa8U,
    0xe6956e65U, 0xaaffe67eU, 0x21bccf08U, 0xef15e8e6U,
    0xbae79bd9U, 0x4a6f36ceU, 0xea9f09d4U, 0x29b07cd6U,
    0x31a4b2afU, 0x2a3f2331U, 0xc6a59430U, 0x35a266c0U,
    0x744ebc37U, 0xfc82caa6U, 0xe090d0b0U, 0x33a7d815U,
    0xf104984aU, 0x41ecdaf7U, 0x7fcd500eU, 0x1791f62fU,
    0x764dd68dU, 0x43efb04dU, 0xccaa4d54U, 0xe49604dfU,
    0x9ed1b5e3U, 0x4c6a881bU, 0xc12c1fb8U, 0x4665517fU,
    0x9d5eea04U, 0x018c355dU, 0xfa877473U, 0xfb0b412eU,
    0xb3671d5aU, 0x92dbd252U, 0xe9105633U, 0x6dd64713U,
    0x9ad7618cU, 0x37a10c7aU, 0x59f8148eU, 0xeb133c89U,
    0xcea927eeU, 0xb761c935U, 0xe11ce5edU, 0x7a47b13cU,
    0x9cd2df59U, 0x55f2733fU, 0x1814ce79U, 0x73c737bfU,
    0x53f7cdeaU, 0x5ffdaa5bU, 0xdf3d6f14U, 0x7844db86U,
    0xcaaff381U, 0xb968c43eU, 0x3824342cU, 0xc2a3405fU,
    0x161dc372U, 0xbce2250cU, 0x283c498bU, 0xff0d9541U,
    0x39a80171U, 0x080cb3deU, 0xd8b4e49cU, 0x6456c190U,
    0x7bcb8461U, 0xd532b670U, 0x486c5c74U, 0xd0b85742U,
},
{
    0x5051f4a7U, 0x537e4165U, 0xc31a17a4U, 0x963a275eU,
    0xcb3bab6bU, 0xf11f9d45U, 0xabacfa58U, 0x934be303U,
    0x552030faU, 0xf6ad766dU, 0x9188cc76U, 0x25f5024cU,
    0xfc4fe5d7U, 0xd7c52acbU, 0x80263544U, 0x8fb562a3U,
    0x49deb15aU, 0x6725ba1bU, 0x9845ea0eU, 0xe15dfec0U,
    0x02c32f75U, 0x12814cf0U, 0xa38d4697U, 0xc66bd3f9U,
    0xe7038f5fU, 0x9515929cU, 0xebbf6d7aU, 0xda955259U,
    0x2dd4be83U, 0xd3587421U, 0x2949e069U, 0x448ec9c8U,
    0x6a75c289U, 0x78f48e79U, 0x6b99583eU, 0xdd27b971U,
    0xb6bee14fU, 0x17f088adU, 0x66c920acU, 0xb47dce3aU,
    0x1863df4aU, 0x82e51a31U, 0x60975133U, 0x4562537fU,
    0xe0b16477U, 0x84bb6baeU, 0x1cfe81a0U, 0x94f9082bU,
    0x58704868U, 0x198f45fdU, 0x8794de6cU, 0xb7527bf8U,
    0x23ab73d3U, 0xe2724b02U, 0x57e31f8fU, 0x2a6655abU,
    0x07b2eb28U, 0x032fb5c2U, 0x9a86c57bU, 0xa5d33708U,
    0xf2302887U, 0xb223bfa5U, 0xba02036aU, 0x5ced1682U,
    0x2b8acf1cU, 0x92a779b4U, 0xf0f307f2U, 0xa14e69e2U,
    0xcd65daf4U, 0xd50605beU, 0x1fd13462U, 0x8ac4a6feU,
    0x9d342e53U, 0xa0a2f355U, 0x32058ae1U, 0x75a4f6ebU,
    0x390b83ecU, 0xaa4060efU, 0x065e719fU, 0x51bd6e10U,
    0xf93e218aU, 0x3d96dd06U, 0xaedd3e05U, 0x464de6bdU,
    0xb591548dU, 0x0571c45dU, 0x6f0406d4U, 0xff605015U,
    0x241998fbU, 0x97d6bde9U, 0xcc894043U, 0x7767d99eU,
    0xbdb0e842U, 0x8807898bU, 0x38e7195bU, 0xdb79c8eeU,
    0x47a17c0aU, 0xe97c420fU, 0xc9f8841eU, 0x00000000U,
    0x83098086U, 0x48322bedU, 0xac1e1170U, 0x4e6c5a72U,
    0xfbfd0effU, 0x560f8538U, 0x1e3daed5U, 0x27362d39U,
    0x640a0fd9U, 0x21685ca6U, 0xd19b5b54U, 0x3a24362eU,
    0xb10c0a67U, 0x0f9357e7U, 0xd2b4ee96U, 0x9e1b9b91U,
    0x4f80c0c5U, 0xa261dc20U, 0x695a774bU, 0x161c121aU,
    0x0ae293baU, 0xe5c0a02aU, 0x433c22e0U, 0x1d121b17U,
    0x0b0e090dU, 0xadf28bc7U, 0xb92db6a8U, 0xc8141ea9U,
    0x8557f119U, 0x4caf7507U, 0xbbee99ddU, 0xfda37f60U,
    0x9ff70126U, 0xbc5c72f5U, 0xc544663bU, 0x345bfb7eU,
    0x768b4329U, 0xdccb23c6U, 0x68b6edfcU, 0x63b8e4f1U,
    0xcad731dcU, 0x10426385U, 0x40139722U, 0x2084c611U,
    0x7d854a24U, 0xf8d2bb3dU, 0x11aef932U, 0x6dc729a1U,
    0x4b1d9e2fU, 0xf3dcb230U, 0xec0d8652U, 0xd077c1e3U,
    0x6c2bb316U, 0x99a970b9U, 0xfa119448U, 0x2247e964U,
    0xc4a8fc8cU, 0x1aa0f03fU, 0xd8567d2cU, 0xef223390U,
    0xc787494eU, 0xc1d938d1U, 0xfe8ccaa2U, 0x3698d40bU,
    0xcfa6f581U, 0x28a57adeU, 0x26dab78eU, 0xa43fadbfU,
    0xe42c3a9dU, 0x0d507892U, 0x9b6a5fccU, 0x62547e46U,
    0xc2f68d13U, 0xe890d8b8U, 0x5e2e39f7U, 0xf582c3afU,
    0xbe9f5d80U, 0x7c69d093U, 0xa96fd52dU, 0xb3cf2512U,
    0x3bc8ac99U, 0xa710187dU, 0x6ee89c63U, 0x7bdb3bbbU,
    0x09cd2678U, 0xf46e5918U, 0x01ec9ab7U, 0xa8834f9aU,
    0x65e6956eU, 0x7eaaffe6U, 0x0821bccfU, 0xe6ef15e8U,
    0xd9bae79bU, 0xce4a6f36U, 0xd4ea9f09U, 0xd629b07cU,
    0xaf31a4b2U, 0x312a3f23U, 0x30c6a594U, 0xc035a266U,
    0x37744ebcU, 0xa6fc82caU, 0xb0e090d0U, 0x1533a7d8U,
    0x4af10498U, 0xf741ecdaU, 0x0e7fcd50U, 0x2f1791f6U,
    0x8d764dd6U, 0x4d43efb0U, 0x54ccaa4dU, 0xdfe49604U,
    0xe39ed1b5U, 0x1b4c6a88U, 0xb8c12c1fU, 0x7f466551U,
    0x049d5eeaU, 0x5d018c35U, 0x73fa8774U, 0x2efb0b41U,
    0x5ab3671dU, 0x5292dbd2U, 0x33e91056U, 0x136dd647U,
    0x8c9ad761U, 0x7a37a10cU, 0x8e59f814U, 0x89eb133cU,
    0xeecea927U, 0x35b761c9U, 0xede11ce5U, 0x3c7a47b1U,
    0x599cd2dfU, 0x3f55f273U, 0x791814ceU, 0xbf73c737U,
    0xea53f7cdU, 0x5b5ffdaaU, 0x14df3d6fU, 0x867844dbU,
    0x81caaff3U, 0x3eb968c4U, 0x2c382434U, 0x5fc2a340U,
    0x72161dc3U, 0x0cbce225U, 0x8b283c49U, 0x41ff0d95U,
    0x7139a801U, 0xde080cb3U, 0x9cd8b4e4U, 0x906456c1U,
    0x617bcb84U, 0x70d532b6U, 0x74486c5cU, 0x42d0b857U,
},
{
    0xa75051f4U, 0x65537e41U, 0xa4c31a17U, 0x5e963a27U,
    0x6bcb3babU, 0x45f11f9dU, 0x58abacfaU, 0x03934be3U,
    0xfa552030U, 0x6df6ad76U, 0x769188ccU, 0x4c25f502U,
    0xd7fc4fe5U, 0xcbd7c52aU, 0x44802635U, 0xa38fb562U,
    0x5a49deb1U, 0x1b6725baU, 0x0e9845eaU, 0xc0e15dfeU,
    0x7502c32fU, 0xf012814cU, 0x97a38d46U, 0xf9c66bd3U,
    0x5fe7038fU, 0x9c951592U, 0x7aebbf6dU, 0x59da9552U,
    0x832dd4beU, 0x21d35874U, 0x692949e0U, 0xc8448ec9U,
    0x896a75c2U, 0x7978f48eU, 0x3e6b9958U, 0x71dd27b9U,
    0x4fb6bee1U, 0xad17f088U, 0xac66c920U, 0x3ab47dceU,
    0x4a1863dfU, 0x3182e51aU, 0x33609751U, 0x7f456253U,
    0x77e0b164U, 0xae84bb6bU, 0xa01cfe81U, 0x2b94f908U,
    0x68587048U, 0xfd198f45U, 0x6c8794deU, 0xf8b7527bU,
    0xd323ab73U, 0x02e2724bU, 0x8f57e31fU, 0xab2a6655U,
    0x2807b2ebU, 0xc2032fb5U, 0x7b9a86c5U, 0x08a5d337U,
    0x87f23028U, 0xa5b223bfU, 0x6aba0203U, 0x825ced16U,
    0x1c2b8acfU, 0xb492a779U, 0xf2f0f307U, 0xe2a14e69U,
    0xf4cd65daU, 0xbed50605U, 0x621fd134U, 0xfe8ac4a6U,
    0x539d342eU, 0x55a0a2f3U, 0xe132058aU, 0xeb75a4f6U,
    0xec390b83U, 0xefaa4060U, 0x9f065e71U, 0x1051bd6eU,

    0x8af93e21U, 0x063d96ddU, 0x05aedd3eU, 0xbd464de6U,
    0x8db59154U, 0x5d0571c4U, 0xd46f0406U, 0x15ff6050U,
    0xfb241998U, 0xe997d6bdU, 0x43cc8940U, 0x9e7767d9U,
    0x42bdb0e8U, 0x8b880789U, 0x5b38e719U, 0xeedb79c8U,
    0x0a47a17cU, 0x0fe97c42U, 0x1ec9f884U, 0x00000000U,
    0x86830980U, 0xed48322bU, 0x70ac1e11U, 0x724e6c5aU,
    0xfffbfd0eU, 0x38560f85U, 0xd51e3daeU, 0x3927362dU,
    0xd9640a0fU, 0xa621685cU, 0x54d19b5bU, 0x2e3a2436U,
    0x67b10c0aU, 0xe70f9357U, 0x96d2b4eeU, 0x919e1b9bU,
    0xc54f80c0U, 0x20a261dcU, 0x4b695a77U, 0x1a161c12U,
    0xba0ae293U, 0x2ae5c0a0U, 0xe0433c22U, 0x171d121bU,
    0x0d0b0e09U, 0xc7adf28bU, 0xa8b92db6U, 0xa9c8141eU,
    0x198557f1U, 0x074caf75U, 0xddbbee99U, 0x60fda37fU,
    0x269ff701U, 0xf5bc5c72U, 0x3bc54466U, 0x7e345bfbU,
    0x29768b43U, 0xc6dccb23U, 0xfc68b6edU, 0xf163b8e4U,
    0xdccad731U, 0x85104263U, 0x22401397U, 0x112084c6U,
    0x247d854aU, 0x3df8d2bbU, 0x3211aef9U, 0xa16dc729U,
    0x2f4b1d9eU, 0x30f3dcb2U, 0x52ec0d86U, 0xe3d077c1U,
    0x166c2bb3U, 0xb999a970U, 0x48fa1194U, 0x642247e9U,
    0x8cc4a8fcU, 0x3f1aa0f0U, 0x2cd8567dU, 0x90ef2233U,
    0x4ec78749U, 0xd1c1d938U, 0xa2fe8ccaU, 0x0b3698d4U,
    0x81cfa6f5U, 0xde28a57aU, 0x8e26dab7U, 0xbfa43fadU,
    0x9de42c3aU, 0x920d5078U, 0xcc9b6a5fU, 0x4662547eU,
    0x13c2f68dU, 0xb8e890d8U, 0xf75e2e39U, 0xaff582c3U,
    0x80be9f5dU, 0x937c69d0U, 0x2da96fd5U, 0x12b3cf25U,
    0x993bc8acU, 0x7da71018U, 0x636ee89cU, 0xbb7bdb3bU,
    0x7809cd26U, 0x18f46e59U, 0xb701ec9aU, 0x9aa8834fU,
    0x6e65e695U, 0xe67eaaffU, 0xcf0821bcU, 0xe8e6ef15U,
    0x9bd9bae7U, 0x36ce4a6fU, 0x09d4ea9fU, 0x7cd629b0U,
    0xb2af31a4U, 0x23312a3fU, 0x9430c6a5U, 0x66c035a2U,
    0xbc37744eU, 0xcaa6fc82U, 0xd0b0e090U, 0xd81533a7U,
    0x984af104U, 0xdaf741ecU, 0x500e7fcdU, 0xf62f1791U,
    0xd68d764dU, 0xb04d43efU, 0x4d54ccaaU, 0x04dfe496U,
    0xb5e39ed1U, 0x881b4c6aU, 0x1fb8c12cU, 0x517f4665U,
    0xea049d5eU, 0x355d018cU, 0x7473fa87U, 0x412efb0bU,
    0x1d5ab367U, 0xd25292dbU, 0x5633e910U, 0x47136dd6U,
    0x618c9ad7U, 0x0c7a37a1U, 0x148e59f8U, 0x3c89eb13U,
    0x27eecea9U, 0xc935b761U, 0xe5ede11cU, 0xb13c7a47U,
    0xdf599cd2U, 0x733f55f2U, 0xce791814U, 0x37bf73c7U,
    0xcdea53f7U, 0xaa5b5ffdU, 0x6f14df3dU, 0xdb867844U,
    0xf381caafU, 0xc43eb968U, 0x342c3824U, 0x405fc2a3U,
    0xc372161dU, 0x250cbce2U, 0x498b283cU, 0x9541ff0dU,
    0x017139a8U, 0xb3de080cU, 0xe49cd8b4U, 0xc1906456U,
    0x84617bcbU, 0xb670d532U, 0x5c74486cU, 0x5742d0b8U,
},
{
    0xf4a75051U, 0x4165537eU, 0x17a4c31aU, 0x275e963aU,
    0xab6bcb3bU, 0x9d45f11fU, 0xfa58abacU, 0xe303934bU,
    0x30fa5520U, 0x766df6adU, 0xcc769188U, 0x024c25f5U,
    0xe5d7fc4fU, 0x2acbd7c5U, 0x35448026U, 0x62a38fb5U,
    0xb15a49deU, 0xba1b6725U, 0xea0e9845U, 0xfec0e15dU,
    0x2f7502c3U, 0x4cf01281U, 0x4697a38dU, 0xd3f9c66bU,
    0x8f5fe703U, 0x929c9515U, 0x6d7aebbfU, 0x5259da95U,
    0xbe832dd4U, 0x7421d358U, 0xe0692949U, 0xc9c8448eU,
    0xc2896a75U, 0x8e7978f4U, 0x583e6b99U, 0xb971dd27U,
    0xe14fb6beU, 0x88ad17f0U, 0x20ac66c9U, 0xce3ab47dU,
    0xdf4a1863U, 0x1a3182e5U, 0x51336097U, 0x537f4562U,
    0x6477e0b1U, 0x6bae84bbU, 0x81a01cfeU, 0x082b94f9U,
    0x48685870U, 0x45fd198fU, 0xde6c8794U, 0x7bf8b752U,
    0x73d323abU, 0x4b02e272U, 0x1f8f57e3U, 0x55ab2a66U,
    0xeb2807b2U, 0xb5c2032fU, 0xc57b9a86U, 0x3708a5d3U,
    0x2887f230U, 0xbfa5b223U, 0x036aba02U, 0x16825cedU,
    0xcf1c2b8aU, 0x79b492a7U, 0x07f2f0f3U, 0x69e2a14eU,
    0xdaf4cd65U, 0x05bed506U, 0x34621fd1U, 0xa6fe8ac4U,
    0x2e539d34U, 0xf355a0a2U, 0x8ae13205U, 0xf6eb75a4U,
    0x83ec390bU, 0x60efaa40U, 0x719f065eU, 0x6e1051bdU,
    0x218af93eU, 0xdd063d96U, 0x3e05aeddU, 0xe6bd464dU,
    0x548db591U, 0xc45d0571U, 0x06d46f04U, 0x5015ff60U,
    0x98fb2419U, 0xbde997d6U, 0x4043cc89U, 0xd99e7767U,
    0xe842bdb0U, 0x898b8807U, 0x195b38e7U, 0xc8eedb79U,
    0x7c0a47a1U, 0x420fe97cU, 0x841ec9f8U, 0x00000000U,
    0x80868309U, 0x2bed4832U, 0x1170ac1eU, 0x5a724e6cU,
    0x0efffbfdU, 0x8538560fU, 0xaed51e3dU, 0x2d392736U,
    0x0fd9640aU, 0x5ca62168U, 0x5b54d19bU, 0x362e3a24U,
    0x0a67b10cU, 0x57e70f93U, 0xee96d2b4U, 0x9b919e1bU,
    0xc0c54f80U, 0xdc20a261U, 0x774b695aU, 0x121a161cU,
    0x93ba0ae2U, 0xa02ae5c0U, 0x22e0433cU, 0x1b171d12U,
    0x090d0b0eU, 0x8bc7adf2U, 0xb6a8b92dU, 0x1ea9c814U,
    0xf1198557U, 0x75074cafU, 0x99ddbbeeU, 0x7f60fda3U,
    0x01269ff7U, 0x72f5bc5cU, 0x663bc544U, 0xfb7e345bU,
    0x4329768bU, 0x23c6dccbU, 0xedfc68b6U, 0xe4f163b8U,
    0x31dccad7U, 0x63851042U, 0x97224013U, 0xc6112084U,
    0x4a247d85U, 0xbb3df8d2U, 0xf93211aeU, 0x29a16dc7U,
    0x9e2f4b1dU, 0xb230f3dcU, 0x8652ec0dU, 0xc1e3d077U,
    0xb3166c2bU, 0x70b999a9U, 0x9448fa11U, 0xe9642247U,
    0xfc8cc4a8U, 0xf03f1aa0U, 0x7d2cd856U, 0x3390ef22U,
    0x494ec787U, 0x38d1c1d9U, 0xcaa2fe8cU, 0xd40b3698U,
    0xf581cfa6U, 0x7ade28a5U, 0xb78e26daU, 0xadbfa43fU,
    0x3a9de42cU, 0x78920d50U, 0x5fcc9b6aU, 0x7e466254U,
    0x8d13c2f6U, 0xd8b8e890U, 0x39f75e2eU, 0xc3aff582U,
    0x5d80be9fU, 0xd0937c69U, 0xd52da96fU, 0x2512b3cfU,
    0xac993bc8U, 0x187da710U, 0x9c636ee8U, 0x3bbb7bdbU,
    0x267809cdU, 0x5918f46eU, 0x9ab701ecU, 0x4f9aa883U,
    0x956e65e6U, 0xffe67eaaU, 0xbccf0821U, 0x15e8e6efU,
    0xe79bd9baU, 0x6f36ce4aU, 0x9f09d4eaU, 0xb07cd629U,
    0xa4b2af31U, 0x3f23312aU, 0xa59430c6U, 0xa266c035U,
    0x4ebc3774U, 0x82caa6fcU, 0x90d0b0e0U, 0xa7d81533U,
    0x04984af1U, 0xecdaf741U, 0xcd500e7fU, 0x91f62f17U,
    0x4dd68d76U, 0xefb04d43U, 0xaa4d54ccU, 0x9604dfe4U,
    0xd1b5e39eU, 0x6a881b4cU, 0x2c1fb8c1U, 0x65517f46U,
    0x5eea049dU, 0x8c355d01U, 0x877473faU, 0x0b412efbU,
    0x671d5ab3U, 0xdbd25292U, 0x105633e9U, 0xd647136dU,
    0xd7618c9aU, 0xa10c7a37U, 0xf8148e59U, 0x133c89ebU,
    0xa927eeceU, 0x61c935b7U, 0x1ce5ede1U, 0x47b13c7aU,
    0xd2df599cU, 0xf2733f55U, 0x14ce7918U, 0xc737bf73U,
    0xf7cdea53U, 0xfdaa5b5fU, 0x3d6f14dfU, 0x44db8678U,
    0xaff381caU, 0x68c43eb9U, 0x24342c38U, 0xa3405fc2U,
    0x1dc37216U, 0xe2250cbcU, 0x3c498b28U, 0x0d9541ffU,
    0xa8017139U, 0x0cb3de08U, 0xb4e49cd8U, 0x56c19064U,
    0xcb84617bU, 0x32b670d5U, 0x6c5c7448U, 0xb85742d0U,
},
{
    0x52525252U, 0x09090909U, 0x6a6a6a6aU, 0xd5d5d5d5U,
    0x30303030U, 0x36363636U, 0xa5a5a5a5U, 0x38383838U,
    0xbfbfbfbfU, 0x40404040U, 0xa3a3a3a3U, 0x9e9e9e9eU,
    0x81818181U, 0xf3f3f3f3U, 0xd7d7d7d7U, 0xfbfbfbfbU,
    0x7c7c7c7cU, 0xe3e3e3e3U, 0x39393939U, 0x82828282U,
    0x9b9b9b9bU, 0x2f2f2f2fU, 0xffffffffU, 0x87878787U,
    0x34343434U, 0x8e8e8e8eU, 0x43434343U, 0x44444444U,
    0xc4c4c4c4U, 0xdedededeU, 0xe9e9e9e9U, 0xcbcbcbcbU,
    0x54545454U, 0x7b7b7b7bU, 0x94949494U, 0x32323232U,
    0xa6a6a6a6U, 0xc2c2c2c2U, 0x23232323U, 0x3d3d3d3dU,
    0xeeeeeeeeU, 0x4c4c4c4cU, 0x95959595U, 0x0b0b0b0bU,
    0x42424242U, 0xfafafafaU, 0xc3c3c3c3U, 0x4e4e4e4eU,
    0x08080808U, 0x2e2e2e2eU, 0xa1a1a1a1U, 0x66666666U,
    0x28282828U, 0xd9d9d9d9U, 0x24242424U, 0xb2b2b2b2U,
    0x76767676U, 0x5b5b5b5bU, 0xa2a2a2a2U, 0x49494949U,
    0x6d6d6d6dU, 0x8b8b8b8bU, 0xd1d1d1d1U, 0x25252525U,
    0x72727272U, 0xf8f8f8f8U, 0xf6f6f6f6U, 0x64646464U,
    0x86868686U, 0x68686868U, 0x98989898U, 0x16161616U,
    0xd4d4d4d4U, 0xa4a4a4a4U, 0x5c5c5c5cU, 0xccccccccU,
    0x5d5d5d5dU, 0x65656565U, 0xb6b6b6b6U, 0x92929292U,
    0x6c6c6c6cU, 0x70707070U, 0x48484848U, 0x50505050U,
    0xfdfdfdfdU, 0xededededU, 0xb9b9b9b9U, 0xdadadadaU,
    0x5e5e5e5eU, 0x15151515U, 0x46464646U, 0x57575757U,
    0xa7a7a7a7U, 0x8d8d8d8dU, 0x9d9d9d9dU, 0x84848484U,
    0x90909090U, 0xd8d8d8d8U, 0xababababU, 0x00000000U,
    0x8c8c8c8cU, 0xbcbcbcbcU, 0xd3d3d3d3U, 0x0a0a0a0aU,
    0xf7f7f7f7U, 0xe4e4e4e4U, 0x58585858U, 0x05050505U,
    0xb8b8b8b8U, 0xb3b3b3b3U, 0x45454545U, 0x06060606U,
    0xd0d0d0d0U, 0x2c2c2c2cU, 0x1e1e1e1eU, 0x8f8f8f8fU,
    0xcacacacaU, 0x3f3f3f3fU, 0x0f0f0f0fU, 0x02020202U,
    0xc1c1c1c1U, 0xafafafafU, 0xbdbdbdbdU, 0x03030303U,
    0x01010101U, 0x13131313U, 0x8a8a8a8aU, 0x6b6b6b6bU,
    0x3a3a3a3aU, 0x91919191U, 0x11111111U, 0x41414141U,
    0x4f4f4f4fU, 0x67676767U, 0xdcdcdcdcU, 0xeaeaeaeaU,
    0x97979797U, 0xf2f2f2f2U, 0xcfcfcfcfU, 0xcecececeU,
    0xf0f0f0f0U, 0xb4b4b4b4U, 0xe6e6e6e6U, 0x73737373U,
    0x96969696U, 0xacacacacU, 0x74747474U, 0x22222222U,
    0xe7e7e7e7U, 0xadadadadU, 0x35353535U, 0x85858585U,
    0xe2e2e2e2U, 0xf9f9f9f9U, 0x37373737U, 0xe8e8e8e8U,
    0x1c1c1c1cU, 0x75757575U, 0xdfdfdfdfU, 0x6e6e6e6eU,
    0x47474747U, 0xf1f1f1f1U, 0x1a1a1a1aU, 0x71717171U,
    0x1d1d1d1dU, 0x29292929U, 0xc5c5c5c5U, 0x89898989U,
    0x6f6f6f6fU, 0xb7b7b7b7U, 0x62626262U, 0x0e0e0e0eU,
    0xaaaaaaaaU, 0x18181818U, 0xbebebebeU, 0x1b1b1b1bU,
    0xfcfcfcfcU, 0x56565656U, 0x3e3e3e3eU, 0x4b4b4b4bU,
    0xc6c6c6c6U, 0xd2d2d2d2U, 0x79797979U, 0x20202020U,
    0x9a9a9a9aU, 0xdbdbdbdbU, 0xc0c0c0c0U, 0xfefefefeU,
    0x78787878U, 0xcdcdcdcdU, 0x5a5a5a5aU, 0xf4f4f4f4U,
    0x1f1f1f1fU, 0xddddddddU, 0xa8a8a8a8U, 0x33333333U,
    0x88888888U, 0x07070707U, 0xc7c7c7c7U, 0x31313131U,
    0xb1b1b1b1U, 0x12121212U, 0x10101010U, 0x59595959U,
    0x27272727U, 0x80808080U, 0xececececU, 0x5f5f5f5fU,
    0x60606060U, 0x51515151U, 0x7f7f7f7fU, 0xa9a9a9a9U,
    0x19191919U, 0xb5b5b5b5U, 0x4a4a4a4aU, 0x0d0d0d0dU,
    0x2d2d2d2dU, 0xe5e5e5e5U, 0x7a7a7a7aU, 0x9f9f9f9fU,
    0x93939393U, 0xc9c9c9c9U, 0x9c9c9c9cU, 0xefefefefU,
    0xa0a0a0a0U, 0xe0e0e0e0U, 0x3b3b3b3bU, 0x4d4d4d4dU,
    0xaeaeaeaeU, 0x2a2a2a2aU, 0xf5f5f5f5U, 0xb0b0b0b0U,
    0xc8c8c8c8U, 0xebebebebU, 0xbbbbbbbbU, 0x3c3c3c3cU,
    0x83838383U, 0x53535353U, 0x99999999U, 0x61616161U,
    0x17171717U, 0x2b2b2b2bU, 0x04040404U, 0x7e7e7e7eU,
    0xbabababaU, 0x77777777U, 0xd6d6d6d6U, 0x26262626U,
    0xe1e1e1e1U, 0x69696969U, 0x14141414U, 0x63636363U,
    0x55555555U, 0x21212121U, 0x0c0c0c0cU, 0x7d7d7d7dU,
}
};

#define GETBYTE(x, y) (word32)((byte)((x) >> (8 * (y))))

#ifdef CYASSL_AESNI

/* Each platform needs to query info type 1 from cpuid to see if aesni is
 * supported. Also, let's setup a macro for proper linkage w/o ABI conflicts
 */

#ifndef _MSC_VER

    #define cpuid(reg, func)\
        __asm__ __volatile__ ("cpuid":\
             "=a" (reg[0]), "=b" (reg[1]), "=c" (reg[2]), "=d" (reg[3]) :\
             "a" (func));

    #define XASM_LINK(f) asm(f)
#else

    #include <intrin.h>
    #define cpuid(a,b) __cpuid((int*)a,b)

    #define XASM_LINK(f)

#endif /* _MSC_VER */


static int Check_CPU_support_AES(void)
{
    unsigned int reg[4];  /* put a,b,c,d into 0,1,2,3 */
    cpuid(reg, 1);        /* query info 1 */

    if (reg[2] & 0x2000000)
        return 1;

    return 0;
}

static int checkAESNI = 0;
static int haveAESNI  = 0;


/* tell C compiler these are asm functions in case any mix up of ABI underscore
   prefix between clang/gcc/llvm etc */
void AES_CBC_encrypt(const unsigned char* in, unsigned char* out,
                     unsigned char* ivec, unsigned long length,
                     const unsigned char* KS, int nr)
                     XASM_LINK("AES_CBC_encrypt");


void AES_CBC_decrypt(const unsigned char* in, unsigned char* out,
                     unsigned char* ivec, unsigned long length,
                     const unsigned char* KS, int nr)
                     XASM_LINK("AES_CBC_decrypt");

void AES_ECB_encrypt(const unsigned char* in, unsigned char* out,
                     unsigned long length, const unsigned char* KS, int nr)
                     XASM_LINK("AES_ECB_encrypt");


void AES_ECB_decrypt(const unsigned char* in, unsigned char* out,
                     unsigned long length, const unsigned char* KS, int nr)
                     XASM_LINK("AES_ECB_decrypt");

void AES_128_Key_Expansion(const unsigned char* userkey,
                           unsigned char* key_schedule)
                           XASM_LINK("AES_128_Key_Expansion");

void AES_192_Key_Expansion(const unsigned char* userkey,
                           unsigned char* key_schedule)
                           XASM_LINK("AES_192_Key_Expansion");

void AES_256_Key_Expansion(const unsigned char* userkey,
                           unsigned char* key_schedule)
                           XASM_LINK("AES_256_Key_Expansion");


static int AES_set_encrypt_key(const unsigned char *userKey, const int bits,
                               Aes* aes)
{
    if (!userKey || !aes)
        return BAD_FUNC_ARG;

    if (bits == 128) {
       AES_128_Key_Expansion (userKey,(byte*)aes->key); aes->rounds = 10;
       return 0;
    }
    else if (bits == 192) {
       AES_192_Key_Expansion (userKey,(byte*)aes->key); aes->rounds = 12;
       return 0;
    }
    else if (bits == 256) {
       AES_256_Key_Expansion (userKey,(byte*)aes->key); aes->rounds = 14;
       return 0;
    }
    return BAD_FUNC_ARG;
}


static int AES_set_decrypt_key(const unsigned char* userKey, const int bits,
                               Aes* aes)
{
    int nr;
    Aes temp_key;
    __m128i *Key_Schedule = (__m128i*)aes->key;
    __m128i *Temp_Key_Schedule = (__m128i*)temp_key.key;

    if (!userKey || !aes)
        return BAD_FUNC_ARG;

    if (AES_set_encrypt_key(userKey,bits,&temp_key) == BAD_FUNC_ARG)
        return BAD_FUNC_ARG;

    nr = temp_key.rounds;
    aes->rounds = nr;

    Key_Schedule[nr] = Temp_Key_Schedule[0];
    Key_Schedule[nr-1] = _mm_aesimc_si128(Temp_Key_Schedule[1]);
    Key_Schedule[nr-2] = _mm_aesimc_si128(Temp_Key_Schedule[2]);
    Key_Schedule[nr-3] = _mm_aesimc_si128(Temp_Key_Schedule[3]);
    Key_Schedule[nr-4] = _mm_aesimc_si128(Temp_Key_Schedule[4]);
    Key_Schedule[nr-5] = _mm_aesimc_si128(Temp_Key_Schedule[5]);
    Key_Schedule[nr-6] = _mm_aesimc_si128(Temp_Key_Schedule[6]);
    Key_Schedule[nr-7] = _mm_aesimc_si128(Temp_Key_Schedule[7]);
    Key_Schedule[nr-8] = _mm_aesimc_si128(Temp_Key_Schedule[8]);
    Key_Schedule[nr-9] = _mm_aesimc_si128(Temp_Key_Schedule[9]);

    if(nr>10) {
        Key_Schedule[nr-10] = _mm_aesimc_si128(Temp_Key_Schedule[10]);
        Key_Schedule[nr-11] = _mm_aesimc_si128(Temp_Key_Schedule[11]);
    }

    if(nr>12) {
        Key_Schedule[nr-12] = _mm_aesimc_si128(Temp_Key_Schedule[12]);
        Key_Schedule[nr-13] = _mm_aesimc_si128(Temp_Key_Schedule[13]);
    }

    Key_Schedule[0] = Temp_Key_Schedule[nr];

    return 0;
}



#endif /* CYASSL_AESNI */


static void AesEncrypt(Aes* aes, const byte* inBlock, byte* outBlock)
{
    word32 s0, s1, s2, s3;
    word32 t0, t1, t2, t3;
    word32 r = aes->rounds >> 1;

    const word32* rk = aes->key;
    if (r > 7 || r == 0) {
        CYASSL_MSG("AesEncrypt encountered improper key, set it up");
        return;  /* stop instead of segfaulting, set up your keys! */
    }
#ifdef CYASSL_AESNI
    if (haveAESNI && aes->use_aesni) {
        #ifdef DEBUG_AESNI
            printf("about to aes encrypt\n");
            printf("in  = %p\n", inBlock);
            printf("out = %p\n", outBlock);
            printf("aes->key = %p\n", aes->key);
            printf("aes->rounds = %d\n", aes->rounds);
            printf("sz = %d\n", AES_BLOCK_SIZE);
        #endif

        /* check alignment, decrypt doesn't need alignment */
        if ((cyassl_word)inBlock % 16) {
        #ifndef NO_CYASSL_ALLOC_ALIGN
            byte* tmp = (byte*)XMALLOC(AES_BLOCK_SIZE, NULL,
                                                      DYNAMIC_TYPE_TMP_BUFFER);
            if (tmp == NULL) return;

            XMEMCPY(tmp, inBlock, AES_BLOCK_SIZE);
            AES_ECB_encrypt(tmp, tmp, AES_BLOCK_SIZE, (byte*)aes->key,
                            aes->rounds);
            XMEMCPY(outBlock, tmp, AES_BLOCK_SIZE);
            XFREE(tmp, NULL, DYNAMIC_TYPE_TMP_BUFFER);
            return;
        #else
            CYASSL_MSG("AES-ECB encrypt with bad alignment");
            return;
        #endif
        }

        AES_ECB_encrypt(inBlock, outBlock, AES_BLOCK_SIZE, (byte*)aes->key,
                        aes->rounds);

        return;
    }
    else {
        #ifdef DEBUG_AESNI
            printf("Skipping AES-NI\n");
        #endif
    }
#endif

    /*
     * map byte array block to cipher state
     * and add initial round key:
     */
    XMEMCPY(&s0, inBlock,                  sizeof(s0));
    XMEMCPY(&s1, inBlock + sizeof(s0),     sizeof(s1));
    XMEMCPY(&s2, inBlock + 2 * sizeof(s0), sizeof(s2));
    XMEMCPY(&s3, inBlock + 3 * sizeof(s0), sizeof(s3));

    #ifdef LITTLE_ENDIAN_ORDER
        s0 = ByteReverseWord32(s0);
        s1 = ByteReverseWord32(s1);
        s2 = ByteReverseWord32(s2);
        s3 = ByteReverseWord32(s3);
    #endif

    s0 ^= rk[0];
    s1 ^= rk[1];
    s2 ^= rk[2];
    s3 ^= rk[3];

    /*
     * Nr - 1 full rounds:
     */

    for (;;) {
        t0 =
            Te[0][GETBYTE(s0, 3)]  ^
            Te[1][GETBYTE(s1, 2)]  ^
            Te[2][GETBYTE(s2, 1)]  ^
            Te[3][GETBYTE(s3, 0)]  ^
            rk[4];
        t1 =
            Te[0][GETBYTE(s1, 3)]  ^
            Te[1][GETBYTE(s2, 2)]  ^
            Te[2][GETBYTE(s3, 1)]  ^
            Te[3][GETBYTE(s0, 0)]  ^
            rk[5];
        t2 =
            Te[0][GETBYTE(s2, 3)] ^
            Te[1][GETBYTE(s3, 2)]  ^
            Te[2][GETBYTE(s0, 1)]  ^
            Te[3][GETBYTE(s1, 0)]  ^
            rk[6];
        t3 =
            Te[0][GETBYTE(s3, 3)] ^
            Te[1][GETBYTE(s0, 2)]  ^
            Te[2][GETBYTE(s1, 1)]  ^
            Te[3][GETBYTE(s2, 0)]  ^
            rk[7];

        rk += 8;
        if (--r == 0) {
            break;
        }

        s0 =
            Te[0][GETBYTE(t0, 3)] ^
            Te[1][GETBYTE(t1, 2)] ^
            Te[2][GETBYTE(t2, 1)] ^
            Te[3][GETBYTE(t3, 0)] ^
            rk[0];
        s1 =
            Te[0][GETBYTE(t1, 3)] ^
            Te[1][GETBYTE(t2, 2)] ^
            Te[2][GETBYTE(t3, 1)] ^
            Te[3][GETBYTE(t0, 0)] ^
            rk[1];
        s2 =
            Te[0][GETBYTE(t2, 3)] ^
            Te[1][GETBYTE(t3, 2)] ^
            Te[2][GETBYTE(t0, 1)] ^
            Te[3][GETBYTE(t1, 0)] ^
            rk[2];
        s3 =
            Te[0][GETBYTE(t3, 3)] ^
            Te[1][GETBYTE(t0, 2)] ^
            Te[2][GETBYTE(t1, 1)] ^
            Te[3][GETBYTE(t2, 0)] ^
            rk[3];
    }

    /*
     * apply last round and
     * map cipher state to byte array block:
     */

    s0 =
        (Te[4][GETBYTE(t0, 3)] & 0xff000000) ^
        (Te[4][GETBYTE(t1, 2)] & 0x00ff0000) ^
        (Te[4][GETBYTE(t2, 1)] & 0x0000ff00) ^
        (Te[4][GETBYTE(t3, 0)] & 0x000000ff) ^
        rk[0];
    s1 =
        (Te[4][GETBYTE(t1, 3)] & 0xff000000) ^
        (Te[4][GETBYTE(t2, 2)] & 0x00ff0000) ^
        (Te[4][GETBYTE(t3, 1)] & 0x0000ff00) ^
        (Te[4][GETBYTE(t0, 0)] & 0x000000ff) ^
        rk[1];
    s2 =
        (Te[4][GETBYTE(t2, 3)] & 0xff000000) ^
        (Te[4][GETBYTE(t3, 2)] & 0x00ff0000) ^
        (Te[4][GETBYTE(t0, 1)] & 0x0000ff00) ^
        (Te[4][GETBYTE(t1, 0)] & 0x000000ff) ^
        rk[2];
    s3 =
        (Te[4][GETBYTE(t3, 3)] & 0xff000000) ^
        (Te[4][GETBYTE(t0, 2)] & 0x00ff0000) ^
        (Te[4][GETBYTE(t1, 1)] & 0x0000ff00) ^
        (Te[4][GETBYTE(t2, 0)] & 0x000000ff) ^
        rk[3];

    /* write out */
    #ifdef LITTLE_ENDIAN_ORDER
        s0 = ByteReverseWord32(s0);
        s1 = ByteReverseWord32(s1);
        s2 = ByteReverseWord32(s2);
        s3 = ByteReverseWord32(s3);
    #endif

    XMEMCPY(outBlock,                  &s0, sizeof(s0));
    XMEMCPY(outBlock + sizeof(s0),     &s1, sizeof(s1));
    XMEMCPY(outBlock + 2 * sizeof(s0), &s2, sizeof(s2));
    XMEMCPY(outBlock + 3 * sizeof(s0), &s3, sizeof(s3));
}

static void AesDecrypt(Aes* aes, const byte* inBlock, byte* outBlock)
{
    word32 s0, s1, s2, s3;
    word32 t0, t1, t2, t3;
    word32 r = aes->rounds >> 1;

    const word32* rk = aes->key;
    if (r > 7 || r == 0) {
        CYASSL_MSG("AesDecrypt encountered improper key, set it up");
        return;  /* stop instead of segfaulting, set up your keys! */
    }
#ifdef CYASSL_AESNI
    if (haveAESNI && aes->use_aesni) {
        #ifdef DEBUG_AESNI
            printf("about to aes decrypt\n");
            printf("in  = %p\n", inBlock);
            printf("out = %p\n", outBlock);
            printf("aes->key = %p\n", aes->key);
            printf("aes->rounds = %d\n", aes->rounds);
            printf("sz = %d\n", AES_BLOCK_SIZE);
        #endif

        /* if input and output same will overwrite input iv */
        XMEMCPY(aes->tmp, inBlock, AES_BLOCK_SIZE);
        AES_ECB_decrypt(inBlock, outBlock, AES_BLOCK_SIZE, (byte*)aes->key,
                        aes->rounds);
        return;
    }
    else {
        #ifdef DEBUG_AESNI
            printf("Skipping AES-NI\n");
        #endif
    }
#endif

    /*
     * map byte array block to cipher state
     * and add initial round key:
     */
    XMEMCPY(&s0, inBlock,                  sizeof(s0));
    XMEMCPY(&s1, inBlock + sizeof(s0),     sizeof(s1));
    XMEMCPY(&s2, inBlock + 2 * sizeof(s0), sizeof(s2));
    XMEMCPY(&s3, inBlock + 3 * sizeof(s0), sizeof(s3));

    #ifdef LITTLE_ENDIAN_ORDER
        s0 = ByteReverseWord32(s0);
        s1 = ByteReverseWord32(s1);
        s2 = ByteReverseWord32(s2);
        s3 = ByteReverseWord32(s3);
    #endif

    s0 ^= rk[0];
    s1 ^= rk[1];
    s2 ^= rk[2];
    s3 ^= rk[3];

    /*
     * Nr - 1 full rounds:
     */

    for (;;) {
        t0 =
            Td[0][GETBYTE(s0, 3)] ^
            Td[1][GETBYTE(s3, 2)] ^
            Td[2][GETBYTE(s2, 1)] ^
            Td[3][GETBYTE(s1, 0)] ^
            rk[4];
        t1 =
            Td[0][GETBYTE(s1, 3)] ^
            Td[1][GETBYTE(s0, 2)] ^
            Td[2][GETBYTE(s3, 1)] ^
            Td[3][GETBYTE(s2, 0)] ^
            rk[5];
        t2 =
            Td[0][GETBYTE(s2, 3)] ^
            Td[1][GETBYTE(s1, 2)] ^
            Td[2][GETBYTE(s0, 1)] ^
            Td[3][GETBYTE(s3, 0)] ^
            rk[6];
        t3 =
            Td[0][GETBYTE(s3, 3)] ^
            Td[1][GETBYTE(s2, 2)] ^
            Td[2][GETBYTE(s1, 1)] ^
            Td[3][GETBYTE(s0, 0)] ^
            rk[7];

        rk += 8;
        if (--r == 0) {
            break;
        }

        s0 =
            Td[0][GETBYTE(t0, 3)] ^
            Td[1][GETBYTE(t3, 2)] ^
            Td[2][GETBYTE(t2, 1)] ^
            Td[3][GETBYTE(t1, 0)] ^
            rk[0];
        s1 =
            Td[0][GETBYTE(t1, 3)] ^
            Td[1][GETBYTE(t0, 2)] ^
            Td[2][GETBYTE(t3, 1)] ^
            Td[3][GETBYTE(t2, 0)] ^
            rk[1];
        s2 =
            Td[0][GETBYTE(t2, 3)] ^
            Td[1][GETBYTE(t1, 2)] ^
            Td[2][GETBYTE(t0, 1)] ^
            Td[3][GETBYTE(t3, 0)] ^
            rk[2];
        s3 =
            Td[0][GETBYTE(t3, 3)] ^
            Td[1][GETBYTE(t2, 2)] ^
            Td[2][GETBYTE(t1, 1)] ^
            Td[3][GETBYTE(t0, 0)] ^
            rk[3];
    }
    /*
     * apply last round and
     * map cipher state to byte array block:
     */
    s0 =
        (Td[4][GETBYTE(t0, 3)] & 0xff000000) ^
        (Td[4][GETBYTE(t3, 2)] & 0x00ff0000) ^
        (Td[4][GETBYTE(t2, 1)] & 0x0000ff00) ^
        (Td[4][GETBYTE(t1, 0)] & 0x000000ff) ^
        rk[0];
    s1 =
        (Td[4][GETBYTE(t1, 3)] & 0xff000000) ^
        (Td[4][GETBYTE(t0, 2)] & 0x00ff0000) ^
        (Td[4][GETBYTE(t3, 1)] & 0x0000ff00) ^
        (Td[4][GETBYTE(t2, 0)] & 0x000000ff) ^
        rk[1];
    s2 =
        (Td[4][GETBYTE(t2, 3)] & 0xff000000) ^
        (Td[4][GETBYTE(t1, 2)] & 0x00ff0000) ^
        (Td[4][GETBYTE(t0, 1)] & 0x0000ff00) ^
        (Td[4][GETBYTE(t3, 0)] & 0x000000ff) ^
        rk[2];
    s3 =
        (Td[4][GETBYTE(t3, 3)] & 0xff000000) ^
        (Td[4][GETBYTE(t2, 2)] & 0x00ff0000) ^
        (Td[4][GETBYTE(t1, 1)] & 0x0000ff00) ^
        (Td[4][GETBYTE(t0, 0)] & 0x000000ff) ^
        rk[3];

    /* write out */
    #ifdef LITTLE_ENDIAN_ORDER
        s0 = ByteReverseWord32(s0);
        s1 = ByteReverseWord32(s1);
        s2 = ByteReverseWord32(s2);
        s3 = ByteReverseWord32(s3);
    #endif

    XMEMCPY(outBlock,                  &s0, sizeof(s0));
    XMEMCPY(outBlock + sizeof(s0),     &s1, sizeof(s1));
    XMEMCPY(outBlock + 2 * sizeof(s0), &s2, sizeof(s2));
    XMEMCPY(outBlock + 3 * sizeof(s0), &s3, sizeof(s3));
}

#endif /* NEED_AES_TABLES */


/* AesSetKey */
#ifdef STM32F2_CRYPTO
    int AesSetKey(Aes* aes, const byte* userKey, word32 keylen, const byte* iv,
                  int dir)
    {
        word32 *rk = aes->key;

        if (!((keylen == 16) || (keylen == 24) || (keylen == 32)))
            return BAD_FUNC_ARG;

        aes->rounds = keylen/4 + 6;
        XMEMCPY(rk, userKey, keylen);
        ByteReverseWords(rk, rk, keylen);

        return AesSetIV(aes, iv);
    }

    int AesSetKeyDirect(Aes* aes, const byte* userKey, word32 keylen,
                        const byte* iv, int dir)
    {
        return AesSetKey(aes, userKey, keylen, iv, dir);
    }

#elif defined(HAVE_COLDFIRE_SEC)
    #if defined (HAVE_THREADX)
        #include "memory_pools.h"
        extern TX_BYTE_POOL mp_ncached;  /* Non Cached memory pool */
    #endif

    #define AES_BUFFER_SIZE (AES_BLOCK_SIZE * 64)
    static unsigned char *AESBuffIn = NULL;
    static unsigned char *AESBuffOut = NULL;
    static byte *secReg;
    static byte *secKey;
    static volatile SECdescriptorType *secDesc;

    static CyaSSL_Mutex Mutex_AesSEC;

    #define SEC_DESC_AES_CBC_ENCRYPT 0x60300010
    #define SEC_DESC_AES_CBC_DECRYPT 0x60200010

    extern volatile unsigned char __MBAR[];

    int AesSetKey(Aes* aes, const byte* userKey, word32 keylen, const byte* iv,
                  int dir)
    {
        if (AESBuffIn == NULL) {
            #if defined (HAVE_THREADX)
			    int s1, s2, s3, s4, s5 ;
                s5 = tx_byte_allocate(&mp_ncached,(void *)&secDesc,
                                      sizeof(SECdescriptorType), TX_NO_WAIT);
                s1 = tx_byte_allocate(&mp_ncached, (void *)&AESBuffIn,
                                      AES_BUFFER_SIZE, TX_NO_WAIT);
                s2 = tx_byte_allocate(&mp_ncached, (void *)&AESBuffOut,
                                      AES_BUFFER_SIZE, TX_NO_WAIT);
                s3 = tx_byte_allocate(&mp_ncached, (void *)&secKey,
                                      AES_BLOCK_SIZE*2, TX_NO_WAIT);
                s4 = tx_byte_allocate(&mp_ncached, (void *)&secReg,
                                      AES_BLOCK_SIZE, TX_NO_WAIT);

                if(s1 || s2 || s3 || s4 || s5)
                    return BAD_FUNC_ARG;
            #else
                #warning "Allocate non-Cache buffers"
            #endif

            InitMutex(&Mutex_AesSEC);
        }

        if (!((keylen == 16) || (keylen == 24) || (keylen == 32)))
            return BAD_FUNC_ARG;

        if (aes == NULL)
            return BAD_FUNC_ARG;

        aes->rounds = keylen/4 + 6;
        XMEMCPY(aes->key, userKey, keylen);

        if (iv)
            XMEMCPY(aes->reg, iv, AES_BLOCK_SIZE);

        return 0;
    }
#elif defined(FREESCALE_MMCAU)
    int AesSetKey(Aes* aes, const byte* userKey, word32 keylen, const byte* iv,
                  int dir)
    {
        byte *rk = (byte*)aes->key;

        if (!((keylen == 16) || (keylen == 24) || (keylen == 32)))
            return BAD_FUNC_ARG;

        if (rk == NULL)
            return BAD_FUNC_ARG;

        aes->rounds = keylen/4 + 6;
        cau_aes_set_key(userKey, keylen*8, rk);

        return AesSetIV(aes, iv);
    }

    int AesSetKeyDirect(Aes* aes, const byte* userKey, word32 keylen,
                        const byte* iv, int dir)
    {
        return AesSetKey(aes, userKey, keylen, iv, dir);
    }
#else
    static int AesSetKeyLocal(Aes* aes, const byte* userKey, word32 keylen,
                const byte* iv, int dir)
    {
        word32 temp, *rk = aes->key;
        unsigned int i = 0;

        #ifdef CYASSL_AESNI
            aes->use_aesni = 0;
        #endif /* CYASSL_AESNI */
        #ifdef CYASSL_AES_COUNTER
            aes->left = 0;
        #endif /* CYASSL_AES_COUNTER */

        aes->rounds = keylen/4 + 6;

        XMEMCPY(rk, userKey, keylen);
        #ifdef LITTLE_ENDIAN_ORDER
            ByteReverseWords(rk, rk, keylen);
        #endif

        #ifdef CYASSL_PIC32MZ_CRYPT
        {
            word32 *akey1 = aes->key_ce;
            word32 *areg = aes->iv_ce ;
            aes->keylen = keylen ;
            XMEMCPY(akey1, userKey, keylen);
            if (iv)
                XMEMCPY(areg, iv, AES_BLOCK_SIZE);
            else
                XMEMSET(areg,  0, AES_BLOCK_SIZE);
        }
        #endif

        switch(keylen)
        {
        case 16:
            while (1)
            {
                temp  = rk[3];
                rk[4] = rk[0] ^
                    (Te[4][GETBYTE(temp, 2)] & 0xff000000) ^
                    (Te[4][GETBYTE(temp, 1)] & 0x00ff0000) ^
                    (Te[4][GETBYTE(temp, 0)] & 0x0000ff00) ^
                    (Te[4][GETBYTE(temp, 3)] & 0x000000ff) ^
                    rcon[i];
                rk[5] = rk[1] ^ rk[4];
                rk[6] = rk[2] ^ rk[5];
                rk[7] = rk[3] ^ rk[6];
                if (++i == 10)
                    break;
                rk += 4;
            }
            break;

        case 24:
            /* for (;;) here triggers a bug in VC60 SP4 w/ Pro Pack */
            while (1)
            {
                temp = rk[ 5];
                rk[ 6] = rk[ 0] ^
                    (Te[4][GETBYTE(temp, 2)] & 0xff000000) ^
                    (Te[4][GETBYTE(temp, 1)] & 0x00ff0000) ^
                    (Te[4][GETBYTE(temp, 0)] & 0x0000ff00) ^
                    (Te[4][GETBYTE(temp, 3)] & 0x000000ff) ^
                    rcon[i];
                rk[ 7] = rk[ 1] ^ rk[ 6];
                rk[ 8] = rk[ 2] ^ rk[ 7];
                rk[ 9] = rk[ 3] ^ rk[ 8];
                if (++i == 8)
                    break;
                rk[10] = rk[ 4] ^ rk[ 9];
                rk[11] = rk[ 5] ^ rk[10];
                rk += 6;
            }
            break;

        case 32:
            while (1)
            {
                temp = rk[ 7];
                rk[ 8] = rk[ 0] ^
                    (Te[4][GETBYTE(temp, 2)] & 0xff000000) ^
                    (Te[4][GETBYTE(temp, 1)] & 0x00ff0000) ^
                    (Te[4][GETBYTE(temp, 0)] & 0x0000ff00) ^
                    (Te[4][GETBYTE(temp, 3)] & 0x000000ff) ^
                    rcon[i];
                rk[ 9] = rk[ 1] ^ rk[ 8];
                rk[10] = rk[ 2] ^ rk[ 9];
                rk[11] = rk[ 3] ^ rk[10];
                if (++i == 7)
                    break;
                temp = rk[11];
                rk[12] = rk[ 4] ^
                    (Te[4][GETBYTE(temp, 3)] & 0xff000000) ^
                    (Te[4][GETBYTE(temp, 2)] & 0x00ff0000) ^
                    (Te[4][GETBYTE(temp, 1)] & 0x0000ff00) ^
                    (Te[4][GETBYTE(temp, 0)] & 0x000000ff);
                rk[13] = rk[ 5] ^ rk[12];
                rk[14] = rk[ 6] ^ rk[13];
                rk[15] = rk[ 7] ^ rk[14];

                rk += 8;
            }
            break;

        default:
            return BAD_FUNC_ARG;
        }

        if (dir == AES_DECRYPTION)
        {
            unsigned int j;
            rk = aes->key;

            /* invert the order of the round keys: */
            for (i = 0, j = 4* aes->rounds; i < j; i += 4, j -= 4) {
                temp = rk[i    ]; rk[i    ] = rk[j    ]; rk[j    ] = temp;
                temp = rk[i + 1]; rk[i + 1] = rk[j + 1]; rk[j + 1] = temp;
                temp = rk[i + 2]; rk[i + 2] = rk[j + 2]; rk[j + 2] = temp;
                temp = rk[i + 3]; rk[i + 3] = rk[j + 3]; rk[j + 3] = temp;
            }
            /* apply the inverse MixColumn transform to all round keys but the
               first and the last: */
            for (i = 1; i < aes->rounds; i++) {
                rk += 4;
                rk[0] =
                    Td[0][Te[4][GETBYTE(rk[0], 3)] & 0xff] ^
                    Td[1][Te[4][GETBYTE(rk[0], 2)] & 0xff] ^
                    Td[2][Te[4][GETBYTE(rk[0], 1)] & 0xff] ^
                    Td[3][Te[4][GETBYTE(rk[0], 0)] & 0xff];
                rk[1] =
                    Td[0][Te[4][GETBYTE(rk[1], 3)] & 0xff] ^
                    Td[1][Te[4][GETBYTE(rk[1], 2)] & 0xff] ^
                    Td[2][Te[4][GETBYTE(rk[1], 1)] & 0xff] ^
                    Td[3][Te[4][GETBYTE(rk[1], 0)] & 0xff];
                rk[2] =
                    Td[0][Te[4][GETBYTE(rk[2], 3)] & 0xff] ^
                    Td[1][Te[4][GETBYTE(rk[2], 2)] & 0xff] ^
                    Td[2][Te[4][GETBYTE(rk[2], 1)] & 0xff] ^
                    Td[3][Te[4][GETBYTE(rk[2], 0)] & 0xff];
                rk[3] =
                    Td[0][Te[4][GETBYTE(rk[3], 3)] & 0xff] ^
                    Td[1][Te[4][GETBYTE(rk[3], 2)] & 0xff] ^
                    Td[2][Te[4][GETBYTE(rk[3], 1)] & 0xff] ^
                    Td[3][Te[4][GETBYTE(rk[3], 0)] & 0xff];
            }
        }

        return AesSetIV(aes, iv);
    }

    int AesSetKey(Aes* aes, const byte* userKey, word32 keylen, const byte* iv,
                  int dir)
    {

        if (!((keylen == 16) || (keylen == 24) || (keylen == 32)))
            return BAD_FUNC_ARG;

        #ifdef HAVE_CAVIUM
        if (aes->magic == CYASSL_AES_CAVIUM_MAGIC)
            return AesCaviumSetKey(aes, userKey, keylen, iv);
        #endif

        #ifdef CYASSL_AESNI
        if (checkAESNI == 0) {
            haveAESNI  = Check_CPU_support_AES();
            checkAESNI = 1;
        }
        if (haveAESNI) {
            aes->use_aesni = 1;
            if (iv)
                XMEMCPY(aes->reg, iv, AES_BLOCK_SIZE);
            if (dir == AES_ENCRYPTION)
                return AES_set_encrypt_key(userKey, keylen * 8, aes);
            else
                return AES_set_decrypt_key(userKey, keylen * 8, aes);
        }
        #endif /* CYASSL_AESNI */

        return AesSetKeyLocal(aes, userKey, keylen, iv, dir);
    }

    #if defined(CYASSL_AES_DIRECT) || defined(CYASSL_AES_COUNTER)

    /* AES-CTR and AES-DIRECT need to use this for key setup, no aesni yet */
    int AesSetKeyDirect(Aes* aes, const byte* userKey, word32 keylen,
                        const byte* iv, int dir)
    {
        return AesSetKeyLocal(aes, userKey, keylen, iv, dir);
    }

    #endif /* CYASSL_AES_DIRECT || CYASSL_AES_COUNTER */
#endif /* STM32F2_CRYPTO, AesSetKey block */


/* AesSetIV is shared between software and hardware */
int AesSetIV(Aes* aes, const byte* iv)
{
    if (aes == NULL)
        return BAD_FUNC_ARG;

    if (iv)
        XMEMCPY(aes->reg, iv, AES_BLOCK_SIZE);
    else
        XMEMSET(aes->reg,  0, AES_BLOCK_SIZE);

    return 0;
}


int AesCbcDecryptWithKey(byte* out, const byte* in, word32 inSz,
                                  const byte* key, word32 keySz, const byte* iv)
{
    int  ret = 0;
#ifdef CYASSL_SMALL_STACK
    Aes* aes = NULL;
#else
    Aes  aes[1];
#endif

#ifdef CYASSL_SMALL_STACK
    aes = (Aes*)XMALLOC(sizeof(Aes), NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (aes == NULL)
        return MEMORY_E;
#endif

    ret = AesSetKey(aes, key, keySz, iv, AES_DECRYPTION);
    if (ret == 0)
        ret = AesCbcDecrypt(aes, out, in, inSz); 

#ifdef CYASSL_SMALL_STACK
    XFREE(aes, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif

    return ret;
}


/* AES-DIRECT */
#if defined(CYASSL_AES_DIRECT)
    #if defined(FREESCALE_MMCAU)

        /* Allow direct access to one block encrypt */
        void AesEncryptDirect(Aes* aes, byte* out, const byte* in)
        {
            byte* key;
            key = (byte*)aes->key;

            return cau_aes_encrypt(in, key, aes->rounds, out);
        }

        /* Allow direct access to one block decrypt */
        void AesDecryptDirect(Aes* aes, byte* out, const byte* in)
        {
            byte* key;
            key = (byte*)aes->key;

            return cau_aes_decrypt(in, key, aes->rounds, out);
        }

    #elif defined(STM32F2_CRYPTO)
        #error "STM32F2 crypto doesn't yet support AES direct"

    #elif defined(HAVE_COLDFIRE_SEC)
        #error "Coldfire SEC doesn't yet support AES direct"

    #elif defined(CYASSL_PIC32MZ_CRYPT)
        #error "PIC32MZ doesn't yet support AES direct"

    #else
        /* Allow direct access to one block encrypt */
        void AesEncryptDirect(Aes* aes, byte* out, const byte* in)
        {
            return AesEncrypt(aes, in, out);
        }

        /* Allow direct access to one block decrypt */
        void AesDecryptDirect(Aes* aes, byte* out, const byte* in)
        {
            return AesDecrypt(aes, in, out);
        }

    #endif /* FREESCALE_MMCAU, AES direct block */
#endif /* CYASSL_AES_DIRECT */


/* AES-CBC */
#ifdef STM32F2_CRYPTO
    int AesCbcEncrypt(Aes* aes, byte* out, const byte* in, word32 sz)
    {
        word32 *enc_key, *iv;
        CRYP_InitTypeDef AES_CRYP_InitStructure;
        CRYP_KeyInitTypeDef AES_CRYP_KeyInitStructure;
        CRYP_IVInitTypeDef AES_CRYP_IVInitStructure;

        enc_key = aes->key;
        iv = aes->reg;

        /* crypto structure initialization */
        CRYP_KeyStructInit(&AES_CRYP_KeyInitStructure);
        CRYP_StructInit(&AES_CRYP_InitStructure);
        CRYP_IVStructInit(&AES_CRYP_IVInitStructure);

        /* reset registers to their default values */
        CRYP_DeInit();

        /* load key into correct registers */
        switch(aes->rounds)
        {
            case 10: /* 128-bit key */
                AES_CRYP_InitStructure.CRYP_KeySize = CRYP_KeySize_128b;
                AES_CRYP_KeyInitStructure.CRYP_Key2Left  = enc_key[0];
                AES_CRYP_KeyInitStructure.CRYP_Key2Right = enc_key[1];
                AES_CRYP_KeyInitStructure.CRYP_Key3Left  = enc_key[2];
                AES_CRYP_KeyInitStructure.CRYP_Key3Right = enc_key[3];
                break;

            case 12: /* 192-bit key */
                AES_CRYP_InitStructure.CRYP_KeySize = CRYP_KeySize_192b;
                AES_CRYP_KeyInitStructure.CRYP_Key1Left  = enc_key[0];
                AES_CRYP_KeyInitStructure.CRYP_Key1Right = enc_key[1];
                AES_CRYP_KeyInitStructure.CRYP_Key2Left  = enc_key[2];
                AES_CRYP_KeyInitStructure.CRYP_Key2Right = enc_key[3];
                AES_CRYP_KeyInitStructure.CRYP_Key3Left  = enc_key[4];
                AES_CRYP_KeyInitStructure.CRYP_Key3Right = enc_key[5];
                break;

            case 14: /* 256-bit key */
                AES_CRYP_InitStructure.CRYP_KeySize = CRYP_KeySize_256b;
                AES_CRYP_KeyInitStructure.CRYP_Key0Left  = enc_key[0];
                AES_CRYP_KeyInitStructure.CRYP_Key0Right = enc_key[1];
                AES_CRYP_KeyInitStructure.CRYP_Key1Left  = enc_key[2];
                AES_CRYP_KeyInitStructure.CRYP_Key1Right = enc_key[3];
                AES_CRYP_KeyInitStructure.CRYP_Key2Left  = enc_key[4];
                AES_CRYP_KeyInitStructure.CRYP_Key2Right = enc_key[5];
                AES_CRYP_KeyInitStructure.CRYP_Key3Left  = enc_key[6];
                AES_CRYP_KeyInitStructure.CRYP_Key3Right = enc_key[7];
                break;

            default:
                break;
        }
        CRYP_KeyInit(&AES_CRYP_KeyInitStructure);

        /* set iv */
        ByteReverseWords(iv, iv, AES_BLOCK_SIZE);
        AES_CRYP_IVInitStructure.CRYP_IV0Left  = iv[0];
        AES_CRYP_IVInitStructure.CRYP_IV0Right = iv[1];
        AES_CRYP_IVInitStructure.CRYP_IV1Left  = iv[2];
        AES_CRYP_IVInitStructure.CRYP_IV1Right = iv[3];
        CRYP_IVInit(&AES_CRYP_IVInitStructure);

        /* set direction, mode, and datatype */
        AES_CRYP_InitStructure.CRYP_AlgoDir  = CRYP_AlgoDir_Encrypt;
        AES_CRYP_InitStructure.CRYP_AlgoMode = CRYP_AlgoMode_AES_CBC;
        AES_CRYP_InitStructure.CRYP_DataType = CRYP_DataType_8b;
        CRYP_Init(&AES_CRYP_InitStructure);

        /* enable crypto processor */
        CRYP_Cmd(ENABLE);

        while (sz > 0)
        {
            /* flush IN/OUT FIFOs */
            CRYP_FIFOFlush();

            CRYP_DataIn(*(uint32_t*)&in[0]);
            CRYP_DataIn(*(uint32_t*)&in[4]);
            CRYP_DataIn(*(uint32_t*)&in[8]);
            CRYP_DataIn(*(uint32_t*)&in[12]);

            /* wait until the complete message has been processed */
            while(CRYP_GetFlagStatus(CRYP_FLAG_BUSY) != RESET) {}

            *(uint32_t*)&out[0]  = CRYP_DataOut();
            *(uint32_t*)&out[4]  = CRYP_DataOut();
            *(uint32_t*)&out[8]  = CRYP_DataOut();
            *(uint32_t*)&out[12] = CRYP_DataOut();

            /* store iv for next call */
            XMEMCPY(aes->reg, out + sz - AES_BLOCK_SIZE, AES_BLOCK_SIZE);

            sz  -= 16;
            in  += 16;
            out += 16;
        }

        /* disable crypto processor */
        CRYP_Cmd(DISABLE);

        return 0;
    }

    int AesCbcDecrypt(Aes* aes, byte* out, const byte* in, word32 sz)
    {
        word32 *dec_key, *iv;
        CRYP_InitTypeDef AES_CRYP_InitStructure;
        CRYP_KeyInitTypeDef AES_CRYP_KeyInitStructure;
        CRYP_IVInitTypeDef AES_CRYP_IVInitStructure;

        dec_key = aes->key;
        iv = aes->reg;

        /* crypto structure initialization */
        CRYP_KeyStructInit(&AES_CRYP_KeyInitStructure);
        CRYP_StructInit(&AES_CRYP_InitStructure);
        CRYP_IVStructInit(&AES_CRYP_IVInitStructure);

        /* if input and output same will overwrite input iv */
        XMEMCPY(aes->tmp, in + sz - AES_BLOCK_SIZE, AES_BLOCK_SIZE);

        /* reset registers to their default values */
        CRYP_DeInit();

        /* load key into correct registers */
        switch(aes->rounds)
        {
            case 10: /* 128-bit key */
                AES_CRYP_InitStructure.CRYP_KeySize = CRYP_KeySize_128b;
                AES_CRYP_KeyInitStructure.CRYP_Key2Left  = dec_key[0];
                AES_CRYP_KeyInitStructure.CRYP_Key2Right = dec_key[1];
                AES_CRYP_KeyInitStructure.CRYP_Key3Left  = dec_key[2];
                AES_CRYP_KeyInitStructure.CRYP_Key3Right = dec_key[3];
                break;

            case 12: /* 192-bit key */
                AES_CRYP_InitStructure.CRYP_KeySize = CRYP_KeySize_192b;
                AES_CRYP_KeyInitStructure.CRYP_Key1Left  = dec_key[0];
                AES_CRYP_KeyInitStructure.CRYP_Key1Right = dec_key[1];
                AES_CRYP_KeyInitStructure.CRYP_Key2Left  = dec_key[2];
                AES_CRYP_KeyInitStructure.CRYP_Key2Right = dec_key[3];
                AES_CRYP_KeyInitStructure.CRYP_Key3Left  = dec_key[4];
                AES_CRYP_KeyInitStructure.CRYP_Key3Right = dec_key[5];
                break;

            case 14: /* 256-bit key */
                AES_CRYP_InitStructure.CRYP_KeySize = CRYP_KeySize_256b;
                AES_CRYP_KeyInitStructure.CRYP_Key0Left  = dec_key[0];
                AES_CRYP_KeyInitStructure.CRYP_Key0Right = dec_key[1];
                AES_CRYP_KeyInitStructure.CRYP_Key1Left  = dec_key[2];
                AES_CRYP_KeyInitStructure.CRYP_Key1Right = dec_key[3];
                AES_CRYP_KeyInitStructure.CRYP_Key2Left  = dec_key[4];
                AES_CRYP_KeyInitStructure.CRYP_Key2Right = dec_key[5];
                AES_CRYP_KeyInitStructure.CRYP_Key3Left  = dec_key[6];
                AES_CRYP_KeyInitStructure.CRYP_Key3Right = dec_key[7];
                break;

            default:
                break;
        }

        /* set direction, mode, and datatype for key preparation */
        AES_CRYP_InitStructure.CRYP_AlgoDir  = CRYP_AlgoDir_Decrypt;
        AES_CRYP_InitStructure.CRYP_AlgoMode = CRYP_AlgoMode_AES_Key;
        AES_CRYP_InitStructure.CRYP_DataType = CRYP_DataType_32b;
        CRYP_Init(&AES_CRYP_InitStructure);
        CRYP_KeyInit(&AES_CRYP_KeyInitStructure);

        /* enable crypto processor */
        CRYP_Cmd(ENABLE);

        /* wait until key has been prepared */
        while(CRYP_GetFlagStatus(CRYP_FLAG_BUSY) != RESET) {}

        /* set direction, mode, and datatype for decryption */
        AES_CRYP_InitStructure.CRYP_AlgoDir  = CRYP_AlgoDir_Decrypt;
        AES_CRYP_InitStructure.CRYP_AlgoMode = CRYP_AlgoMode_AES_CBC;
        AES_CRYP_InitStructure.CRYP_DataType = CRYP_DataType_8b;
        CRYP_Init(&AES_CRYP_InitStructure);

        /* set iv */
        ByteReverseWords(iv, iv, AES_BLOCK_SIZE);

        AES_CRYP_IVInitStructure.CRYP_IV0Left  = iv[0];
        AES_CRYP_IVInitStructure.CRYP_IV0Right = iv[1];
        AES_CRYP_IVInitStructure.CRYP_IV1Left  = iv[2];
        AES_CRYP_IVInitStructure.CRYP_IV1Right = iv[3];
        CRYP_IVInit(&AES_CRYP_IVInitStructure);

        /* enable crypto processor */
        CRYP_Cmd(ENABLE);

        while (sz > 0)
        {
            /* flush IN/OUT FIFOs */
            CRYP_FIFOFlush();

            CRYP_DataIn(*(uint32_t*)&in[0]);
            CRYP_DataIn(*(uint32_t*)&in[4]);
            CRYP_DataIn(*(uint32_t*)&in[8]);
            CRYP_DataIn(*(uint32_t*)&in[12]);

            /* wait until the complete message has been processed */
            while(CRYP_GetFlagStatus(CRYP_FLAG_BUSY) != RESET) {}

            *(uint32_t*)&out[0]  = CRYP_DataOut();
            *(uint32_t*)&out[4]  = CRYP_DataOut();
            *(uint32_t*)&out[8]  = CRYP_DataOut();
            *(uint32_t*)&out[12] = CRYP_DataOut();

            /* store iv for next call */
            XMEMCPY(aes->reg, aes->tmp, AES_BLOCK_SIZE);

            sz -= 16;
            in += 16;
            out += 16;
        }

        /* disable crypto processor */
        CRYP_Cmd(DISABLE);

        return 0;
    }

#elif defined(HAVE_COLDFIRE_SEC)
    static int AesCbcCrypt(Aes* aes, byte* po, const byte* pi, word32 sz,
                           word32 descHeader)
    {
        #ifdef DEBUG_CYASSL
            int i; int stat1, stat2; int ret;
	    #endif

        int size;
        volatile int v;

        if ((pi == NULL) || (po == NULL))
            return BAD_FUNC_ARG;    /*wrong pointer*/

        LockMutex(&Mutex_AesSEC);

        /* Set descriptor for SEC */
        secDesc->length1 = 0x0;
        secDesc->pointer1 = NULL;

        secDesc->length2 = AES_BLOCK_SIZE;
        secDesc->pointer2 = (byte *)secReg; /* Initial Vector */

        switch(aes->rounds) {
            case 10: secDesc->length3 = 16 ; break ;
            case 12: secDesc->length3 = 24 ; break ;
            case 14: secDesc->length3 = 32 ; break ;
        }
        XMEMCPY(secKey, aes->key, secDesc->length3);

        secDesc->pointer3 = (byte *)secKey;
        secDesc->pointer4 = AESBuffIn;
        secDesc->pointer5 = AESBuffOut;
        secDesc->length6 = 0x0;
        secDesc->pointer6 = NULL;
        secDesc->length7 = 0x0;
        secDesc->pointer7 = NULL;
        secDesc->nextDescriptorPtr = NULL;

        while (sz) {
            secDesc->header = descHeader;
            XMEMCPY(secReg, aes->reg, AES_BLOCK_SIZE);
            if ((sz % AES_BUFFER_SIZE) == sz) {
                size = sz;
                sz = 0;
            } else {
                size = AES_BUFFER_SIZE;
                sz -= AES_BUFFER_SIZE;
            }
            secDesc->length4 = size;
            secDesc->length5 = size;

            XMEMCPY(AESBuffIn, pi, size);
            if(descHeader == SEC_DESC_AES_CBC_DECRYPT) {
                XMEMCPY((void*)aes->tmp, (void*)&(pi[size-AES_BLOCK_SIZE]),
                        AES_BLOCK_SIZE);
            }

            /* Point SEC to the location of the descriptor */
            MCF_SEC_FR0 = (uint32)secDesc;
            /* Initialize SEC and wait for encryption to complete */
            MCF_SEC_CCCR0 = 0x0000001a;
            /* poll SISR to determine when channel is complete */
            v=0;

            while ((secDesc->header>> 24) != 0xff) v++;

            #ifdef DEBUG_CYASSL
                ret = MCF_SEC_SISRH;
                stat1 = MCF_SEC_AESSR;
                stat2 = MCF_SEC_AESISR;
                if (ret & 0xe0000000) {
                    db_printf("Aes_Cbc(i=%d):ISRH=%08x, AESSR=%08x, "
                              "AESISR=%08x\n", i, ret, stat1, stat2);
                }
            #endif

            XMEMCPY(po, AESBuffOut, size);

            if (descHeader == SEC_DESC_AES_CBC_ENCRYPT) {
                XMEMCPY((void*)aes->reg, (void*)&(po[size-AES_BLOCK_SIZE]),
                        AES_BLOCK_SIZE);
            } else {
                XMEMCPY((void*)aes->reg, (void*)aes->tmp, AES_BLOCK_SIZE);
            }

            pi += size;
            po += size;
        }

        UnLockMutex(&Mutex_AesSEC);
        return 0;
    }

    int AesCbcEncrypt(Aes* aes, byte* po, const byte* pi, word32 sz)
    {
        return (AesCbcCrypt(aes, po, pi, sz, SEC_DESC_AES_CBC_ENCRYPT));
    }

    int AesCbcDecrypt(Aes* aes, byte* po, const byte* pi, word32 sz)
    {
        return (AesCbcCrypt(aes, po, pi, sz, SEC_DESC_AES_CBC_DECRYPT));
    }

#elif defined(FREESCALE_MMCAU)
    int AesCbcEncrypt(Aes* aes, byte* out, const byte* in, word32 sz)
    {
        int i;
        int offset = 0;
        int len = sz;

        byte *iv, *enc_key;
        byte temp_block[AES_BLOCK_SIZE];

        iv      = (byte*)aes->reg;
        enc_key = (byte*)aes->key;

        if ((cyassl_word)out % CYASSL_MMCAU_ALIGNMENT) {
            CYASSL_MSG("Bad cau_aes_encrypt alignment");
            return BAD_ALIGN_E;
        }

        while (len > 0)
        {
            XMEMCPY(temp_block, in + offset, AES_BLOCK_SIZE);

            /* XOR block with IV for CBC */
            for (i = 0; i < AES_BLOCK_SIZE; i++)
                temp_block[i] ^= iv[i];

            cau_aes_encrypt(temp_block, enc_key, aes->rounds, out + offset);

            len    -= AES_BLOCK_SIZE;
            offset += AES_BLOCK_SIZE;

            /* store IV for next block */
            XMEMCPY(iv, out + offset - AES_BLOCK_SIZE, AES_BLOCK_SIZE);
        }

        return 0;
    }

    int AesCbcDecrypt(Aes* aes, byte* out, const byte* in, word32 sz)
    {
        int i;
        int offset = 0;
        int len = sz;

        byte* iv, *dec_key;
        byte temp_block[AES_BLOCK_SIZE];

        iv      = (byte*)aes->reg;
        dec_key = (byte*)aes->key;

        if ((cyassl_word)out % CYASSL_MMCAU_ALIGNMENT) {
            CYASSL_MSG("Bad cau_aes_decrypt alignment");
            return BAD_ALIGN_E;
        }

        while (len > 0)
        {
            XMEMCPY(temp_block, in + offset, AES_BLOCK_SIZE);

            cau_aes_decrypt(in + offset, dec_key, aes->rounds, out + offset);

            /* XOR block with IV for CBC */
            for (i = 0; i < AES_BLOCK_SIZE; i++)
                (out + offset)[i] ^= iv[i];

            /* store IV for next block */
            XMEMCPY(iv, temp_block, AES_BLOCK_SIZE);

            len    -= AES_BLOCK_SIZE;
            offset += AES_BLOCK_SIZE;
        }

        return 0;
    }

#elif defined(CYASSL_PIC32MZ_CRYPT)
    /* core hardware crypt engine driver */
    static void AesCrypt(Aes *aes, byte* out, const byte* in, word32 sz,
                                            int dir, int algo, int cryptoalgo)
    {
        securityAssociation *sa_p ;
        bufferDescriptor *bd_p ;

        volatile securityAssociation sa __attribute__((aligned (8)));
        volatile bufferDescriptor bd __attribute__((aligned (8)));
        volatile int k ;

        /* get uncached address */
        sa_p = KVA0_TO_KVA1(&sa) ;
        bd_p = KVA0_TO_KVA1(&bd) ;

        /* Sync cache and physical memory */
        if(PIC32MZ_IF_RAM(in)) {
            XMEMCPY((void *)KVA0_TO_KVA1(in), (void *)in, sz);
        }
        XMEMSET((void *)KVA0_TO_KVA1(out), 0, sz);
        /* Set up the Security Association */
        XMEMSET((byte *)KVA0_TO_KVA1(&sa), 0, sizeof(sa));
        sa_p->SA_CTRL.ALGO = algo ; /* AES */
        sa_p->SA_CTRL.LNC = 1;
        sa_p->SA_CTRL.LOADIV = 1;
        sa_p->SA_CTRL.FB = 1;
        sa_p->SA_CTRL.ENCTYPE = dir ; /* Encryption/Decryption */
        sa_p->SA_CTRL.CRYPTOALGO = cryptoalgo;

        if(cryptoalgo == PIC32_CRYPTOALGO_AES_GCM){
            switch(aes->keylen) {
            case 32:
                sa_p->SA_CTRL.KEYSIZE = PIC32_AES_KEYSIZE_256 ;
                break ;
            case 24:
                sa_p->SA_CTRL.KEYSIZE = PIC32_AES_KEYSIZE_192 ;
                break ;
            case 16:
                sa_p->SA_CTRL.KEYSIZE = PIC32_AES_KEYSIZE_128 ;
                break ;
            }
        } else
            sa_p->SA_CTRL.KEYSIZE = PIC32_AES_KEYSIZE_128 ;

        ByteReverseWords(
        (word32 *)KVA0_TO_KVA1(sa.SA_ENCKEY + 8 - aes->keylen/sizeof(word32)),
                         (word32 *)aes->key_ce, aes->keylen);
        ByteReverseWords(
        (word32*)KVA0_TO_KVA1(sa.SA_ENCIV), (word32 *)aes->iv_ce, 16);

        XMEMSET((byte *)KVA0_TO_KVA1(&bd), 0, sizeof(bd));
        /* Set up the Buffer Descriptor */
        bd_p->BD_CTRL.BUFLEN = sz;
        if(cryptoalgo == PIC32_CRYPTOALGO_AES_GCM) {
            if(sz % 0x10)
                bd_p->BD_CTRL.BUFLEN = (sz/0x10 + 1) * 0x10 ;
        }
        bd_p->BD_CTRL.LIFM = 1;
        bd_p->BD_CTRL.SA_FETCH_EN = 1;
        bd_p->BD_CTRL.LAST_BD = 1;
        bd_p->BD_CTRL.DESC_EN = 1;

        bd_p->SA_ADDR = (unsigned int)KVA_TO_PA(&sa) ;
        bd_p->SRCADDR = (unsigned int)KVA_TO_PA(in) ;
        bd_p->DSTADDR = (unsigned int)KVA_TO_PA(out);
        bd_p->MSGLEN = sz ;

        CECON = 1 << 6;
        while (CECON);

        /* Run the engine */
        CEBDPADDR = (unsigned int)KVA_TO_PA(&bd) ;
        CEINTEN = 0x07;
        CECON = 0x27;

        WAIT_ENGINE ;

        if((cryptoalgo == PIC32_CRYPTOALGO_CBC) ||
           (cryptoalgo == PIC32_CRYPTOALGO_TCBC)||
           (cryptoalgo == PIC32_CRYPTOALGO_RCBC)) {
            /* set iv for the next call */
            if(dir == PIC32_ENCRYPTION) {
                XMEMCPY((void *)aes->iv_ce,
                        (void*)KVA0_TO_KVA1(out + sz - AES_BLOCK_SIZE),
                        AES_BLOCK_SIZE) ;
            } else {
                ByteReverseWords((word32*)aes->iv_ce,
                        (word32 *)KVA0_TO_KVA1(in + sz - AES_BLOCK_SIZE),
                        AES_BLOCK_SIZE);
            }
        }
        XMEMCPY((byte *)out, (byte *)KVA0_TO_KVA1(out), sz) ;
        ByteReverseWords((word32*)out, (word32 *)out, sz);
    }

    int AesCbcEncrypt(Aes* aes, byte* out, const byte* in, word32 sz)
    {
        AesCrypt(aes, out, in, sz, PIC32_ENCRYPTION, PIC32_ALGO_AES,
                                                      PIC32_CRYPTOALGO_RCBC );
        return 0 ;
    }

    int AesCbcDecrypt(Aes* aes, byte* out, const byte* in, word32 sz)
    {
        AesCrypt(aes, out, in, sz, PIC32_DECRYPTION, PIC32_ALGO_AES,
                                                      PIC32_CRYPTOALGO_RCBC);
        return 0 ;
    }

#else
    int AesCbcEncrypt(Aes* aes, byte* out, const byte* in, word32 sz)
    {
        word32 blocks = sz / AES_BLOCK_SIZE;

    #ifdef HAVE_CAVIUM
        if (aes->magic == CYASSL_AES_CAVIUM_MAGIC)
            return AesCaviumCbcEncrypt(aes, out, in, sz);
    #endif

    #ifdef CYASSL_AESNI
        if (haveAESNI) {
            #ifdef DEBUG_AESNI
                printf("about to aes cbc encrypt\n");
                printf("in  = %p\n", in);
                printf("out = %p\n", out);
                printf("aes->key = %p\n", aes->key);
                printf("aes->reg = %p\n", aes->reg);
                printf("aes->rounds = %d\n", aes->rounds);
                printf("sz = %d\n", sz);
            #endif

            /* check alignment, decrypt doesn't need alignment */
            if ((cyassl_word)in % 16) {
            #ifndef NO_CYASSL_ALLOC_ALIGN
                byte* tmp = (byte*)XMALLOC(sz, NULL, DYNAMIC_TYPE_TMP_BUFFER);
                CYASSL_MSG("AES-CBC encrypt with bad alignment");
                if (tmp == NULL) return MEMORY_E;

                XMEMCPY(tmp, in, sz);
                AES_CBC_encrypt(tmp, tmp, (byte*)aes->reg, sz, (byte*)aes->key,
                            aes->rounds);
                /* store iv for next call */
                XMEMCPY(aes->reg, tmp + sz - AES_BLOCK_SIZE, AES_BLOCK_SIZE);

                XMEMCPY(out, tmp, sz);
                XFREE(tmp, NULL, DYNAMIC_TYPE_TMP_BUFFER);
                return 0;
            #else
                return BAD_ALIGN_E;
            #endif
            }

            AES_CBC_encrypt(in, out, (byte*)aes->reg, sz, (byte*)aes->key,
                            aes->rounds);
            /* store iv for next call */
            XMEMCPY(aes->reg, out + sz - AES_BLOCK_SIZE, AES_BLOCK_SIZE);

            return 0;
        }
    #endif

        while (blocks--) {
            xorbuf((byte*)aes->reg, in, AES_BLOCK_SIZE);
            AesEncrypt(aes, (byte*)aes->reg, (byte*)aes->reg);
            XMEMCPY(out, aes->reg, AES_BLOCK_SIZE);

            out += AES_BLOCK_SIZE;
            in  += AES_BLOCK_SIZE;
        }

        return 0;
    }

    int AesCbcDecrypt(Aes* aes, byte* out, const byte* in, word32 sz)
    {
        word32 blocks = sz / AES_BLOCK_SIZE;

    #ifdef HAVE_CAVIUM
        if (aes->magic == CYASSL_AES_CAVIUM_MAGIC)
            return AesCaviumCbcDecrypt(aes, out, in, sz);
    #endif

    #ifdef CYASSL_AESNI
        if (haveAESNI) {
            #ifdef DEBUG_AESNI
                printf("about to aes cbc decrypt\n");
                printf("in  = %p\n", in);
                printf("out = %p\n", out);
                printf("aes->key = %p\n", aes->key);
                printf("aes->reg = %p\n", aes->reg);
                printf("aes->rounds = %d\n", aes->rounds);
                printf("sz = %d\n", sz);
            #endif

            /* if input and output same will overwrite input iv */
            XMEMCPY(aes->tmp, in + sz - AES_BLOCK_SIZE, AES_BLOCK_SIZE);
            AES_CBC_decrypt(in, out, (byte*)aes->reg, sz, (byte*)aes->key,
                            aes->rounds);
            /* store iv for next call */
            XMEMCPY(aes->reg, aes->tmp, AES_BLOCK_SIZE);
            return 0;
        }
    #endif

        while (blocks--) {
            XMEMCPY(aes->tmp, in, AES_BLOCK_SIZE);
            AesDecrypt(aes, (byte*)aes->tmp, out);
            xorbuf(out, (byte*)aes->reg, AES_BLOCK_SIZE);
            XMEMCPY(aes->reg, aes->tmp, AES_BLOCK_SIZE);

            out += AES_BLOCK_SIZE;
            in  += AES_BLOCK_SIZE;
        }

        return 0;
    }

#endif /* STM32F2_CRYPTO, AES-CBC block */

/* AES-CTR */
#ifdef CYASSL_AES_COUNTER

    #ifdef STM32F2_CRYPTO
        void AesCtrEncrypt(Aes* aes, byte* out, const byte* in, word32 sz)
        {
            word32 *enc_key, *iv;
            CRYP_InitTypeDef AES_CRYP_InitStructure;
            CRYP_KeyInitTypeDef AES_CRYP_KeyInitStructure;
            CRYP_IVInitTypeDef AES_CRYP_IVInitStructure;

            enc_key = aes->key;
            iv = aes->reg;

            /* crypto structure initialization */
            CRYP_KeyStructInit(&AES_CRYP_KeyInitStructure);
            CRYP_StructInit(&AES_CRYP_InitStructure);
            CRYP_IVStructInit(&AES_CRYP_IVInitStructure);

            /* reset registers to their default values */
            CRYP_DeInit();

            /* load key into correct registers */
            switch(aes->rounds)
            {
                case 10: /* 128-bit key */
                    AES_CRYP_InitStructure.CRYP_KeySize = CRYP_KeySize_128b;
                    AES_CRYP_KeyInitStructure.CRYP_Key2Left  = enc_key[0];
                    AES_CRYP_KeyInitStructure.CRYP_Key2Right = enc_key[1];
                    AES_CRYP_KeyInitStructure.CRYP_Key3Left  = enc_key[2];
                    AES_CRYP_KeyInitStructure.CRYP_Key3Right = enc_key[3];
                    break;

                case 12: /* 192-bit key */
                    AES_CRYP_InitStructure.CRYP_KeySize = CRYP_KeySize_192b;
                    AES_CRYP_KeyInitStructure.CRYP_Key1Left  = enc_key[0];
                    AES_CRYP_KeyInitStructure.CRYP_Key1Right = enc_key[1];
                    AES_CRYP_KeyInitStructure.CRYP_Key2Left  = enc_key[2];
                    AES_CRYP_KeyInitStructure.CRYP_Key2Right = enc_key[3];
                    AES_CRYP_KeyInitStructure.CRYP_Key3Left  = enc_key[4];
                    AES_CRYP_KeyInitStructure.CRYP_Key3Right = enc_key[5];
                    break;

                case 14: /* 256-bit key */
                    AES_CRYP_InitStructure.CRYP_KeySize = CRYP_KeySize_256b;
                    AES_CRYP_KeyInitStructure.CRYP_Key0Left  = enc_key[0];
                    AES_CRYP_KeyInitStructure.CRYP_Key0Right = enc_key[1];
                    AES_CRYP_KeyInitStructure.CRYP_Key1Left  = enc_key[2];
                    AES_CRYP_KeyInitStructure.CRYP_Key1Right = enc_key[3];
                    AES_CRYP_KeyInitStructure.CRYP_Key2Left  = enc_key[4];
                    AES_CRYP_KeyInitStructure.CRYP_Key2Right = enc_key[5];
                    AES_CRYP_KeyInitStructure.CRYP_Key3Left  = enc_key[6];
                    AES_CRYP_KeyInitStructure.CRYP_Key3Right = enc_key[7];
                    break;

                default:
                    break;
            }
            CRYP_KeyInit(&AES_CRYP_KeyInitStructure);

            /* set iv */
            ByteReverseWords(iv, iv, AES_BLOCK_SIZE);
            AES_CRYP_IVInitStructure.CRYP_IV0Left  = iv[0];
            AES_CRYP_IVInitStructure.CRYP_IV0Right = iv[1];
            AES_CRYP_IVInitStructure.CRYP_IV1Left  = iv[2];
            AES_CRYP_IVInitStructure.CRYP_IV1Right = iv[3];
            CRYP_IVInit(&AES_CRYP_IVInitStructure);

            /* set direction, mode, and datatype */
            AES_CRYP_InitStructure.CRYP_AlgoDir  = CRYP_AlgoDir_Encrypt;
            AES_CRYP_InitStructure.CRYP_AlgoMode = CRYP_AlgoMode_AES_CTR;
            AES_CRYP_InitStructure.CRYP_DataType = CRYP_DataType_8b;
            CRYP_Init(&AES_CRYP_InitStructure);

            /* enable crypto processor */
            CRYP_Cmd(ENABLE);

            while (sz > 0)
            {
                /* flush IN/OUT FIFOs */
                CRYP_FIFOFlush();

                CRYP_DataIn(*(uint32_t*)&in[0]);
                CRYP_DataIn(*(uint32_t*)&in[4]);
                CRYP_DataIn(*(uint32_t*)&in[8]);
                CRYP_DataIn(*(uint32_t*)&in[12]);

                /* wait until the complete message has been processed */
                while(CRYP_GetFlagStatus(CRYP_FLAG_BUSY) != RESET) {}

                *(uint32_t*)&out[0]  = CRYP_DataOut();
                *(uint32_t*)&out[4]  = CRYP_DataOut();
                *(uint32_t*)&out[8]  = CRYP_DataOut();
                *(uint32_t*)&out[12] = CRYP_DataOut();

                /* store iv for next call */
                XMEMCPY(aes->reg, out + sz - AES_BLOCK_SIZE, AES_BLOCK_SIZE);

                sz  -= 16;
                in  += 16;
                out += 16;
            }

            /* disable crypto processor */
            CRYP_Cmd(DISABLE);
        }

    #elif defined(CYASSL_PIC32MZ_CRYPT)
        void AesCtrEncrypt(Aes* aes, byte* out, const byte* in, word32 sz)
        {
            int i ;
            char out_block[AES_BLOCK_SIZE] ;
            int odd ;
            int even ;
            char *tmp ; /* (char *)aes->tmp, for short */

            tmp = (char *)aes->tmp ;
            if(aes->left) {
                if((aes->left + sz) >= AES_BLOCK_SIZE){
                    odd = AES_BLOCK_SIZE - aes->left ;
                } else {
                    odd = sz ;
                }
                XMEMCPY(tmp+aes->left, in, odd) ;
                if((odd+aes->left) == AES_BLOCK_SIZE){
                    AesCrypt(aes, out_block, tmp, AES_BLOCK_SIZE,
                        PIC32_ENCRYPTION, PIC32_ALGO_AES, PIC32_CRYPTOALGO_RCTR);
                    XMEMCPY(out, out_block+aes->left, odd) ;
                    aes->left = 0 ;
                    XMEMSET(tmp, 0x0, AES_BLOCK_SIZE) ;
                    /* Increment IV */
                    for (i = AES_BLOCK_SIZE - 1; i >= 0; i--) {
                        if (++((byte *)aes->iv_ce)[i])
                            break ;
                    }
                }
                in += odd ;
                out+= odd ;
                sz -= odd ;
            }
            odd = sz % AES_BLOCK_SIZE ;  /* if there is tail flagment */
            if(sz / AES_BLOCK_SIZE) {
                even = (sz/AES_BLOCK_SIZE)*AES_BLOCK_SIZE ;
                AesCrypt(aes, out, in, even, PIC32_ENCRYPTION, PIC32_ALGO_AES,
                                                        PIC32_CRYPTOALGO_RCTR);
                out += even ;
                in  += even ;
                do {  /* Increment IV */
                    for (i = AES_BLOCK_SIZE - 1; i >= 0; i--) {
                        if (++((byte *)aes->iv_ce)[i])
                            break ;
                    }
                    even -= AES_BLOCK_SIZE ;
                } while((int)even > 0) ;
            }
            if(odd) {
                XMEMSET(tmp+aes->left, 0x0, AES_BLOCK_SIZE - aes->left) ;
                XMEMCPY(tmp+aes->left, in, odd) ;
                AesCrypt(aes, out_block, tmp, AES_BLOCK_SIZE,
                        PIC32_ENCRYPTION, PIC32_ALGO_AES, PIC32_CRYPTOALGO_RCTR);
                XMEMCPY(out, out_block+aes->left,odd) ;
                aes->left += odd ;
            }
        }

    #elif defined(HAVE_COLDFIRE_SEC)
        #error "Coldfire SEC doesn't currently support AES-CTR mode"

    #elif defined(FREESCALE_MMCAU)
        #error "Freescale mmCAU doesn't currently support AES-CTR mode"

    #else
        /* Increment AES counter */
        static INLINE void IncrementAesCounter(byte* inOutCtr)
        {
            int i;

            /* in network byte order so start at end and work back */
            for (i = AES_BLOCK_SIZE - 1; i >= 0; i--) {
                if (++inOutCtr[i])  /* we're done unless we overflow */
                    return;
            }
        }

        void AesCtrEncrypt(Aes* aes, byte* out, const byte* in, word32 sz)
        {
            byte* tmp = (byte*)aes->tmp + AES_BLOCK_SIZE - aes->left;

            /* consume any unused bytes left in aes->tmp */
            while (aes->left && sz) {
               *(out++) = *(in++) ^ *(tmp++);
               aes->left--;
               sz--;
            }

            /* do as many block size ops as possible */
            while (sz >= AES_BLOCK_SIZE) {
                AesEncrypt(aes, (byte*)aes->reg, out);
                IncrementAesCounter((byte*)aes->reg);
                xorbuf(out, in, AES_BLOCK_SIZE);

                out += AES_BLOCK_SIZE;
                in  += AES_BLOCK_SIZE;
                sz  -= AES_BLOCK_SIZE;
                aes->left = 0;
            }

            /* handle non block size remaining and sotre unused byte count in left */
            if (sz) {
                AesEncrypt(aes, (byte*)aes->reg, (byte*)aes->tmp);
                IncrementAesCounter((byte*)aes->reg);

                aes->left = AES_BLOCK_SIZE;
                tmp = (byte*)aes->tmp;

                while (sz--) {
                    *(out++) = *(in++) ^ *(tmp++);
                    aes->left--;
                }
            }
        }

    #endif /* STM32F2_CRYPTO, AES-CTR block */

#endif /* CYASSL_AES_COUNTER */

#ifdef HAVE_AESGCM

/*
 * The IV for AES GCM, stored in struct Aes's member reg, is comprised of
 * three parts in order:
 *   1. The implicit IV. This is generated from the PRF using the shared
 *      secrets between endpoints. It is 4 bytes long.
 *   2. The explicit IV. This is set by the user of the AES. It needs to be
 *      unique for each call to encrypt. The explicit IV is shared with the
 *      other end of the transaction in the clear.
 *   3. The counter. Each block of data is encrypted with its own sequence
 *      number counter.
 */

#ifdef STM32F2_CRYPTO
    #error "STM32F2 crypto doesn't currently support AES-GCM mode"

#elif defined(HAVE_COLDFIRE_SEC)
    #error "Coldfire SEC doesn't currently support AES-GCM mode"

#endif

enum {
    CTR_SZ = 4
};


static INLINE void InitGcmCounter(byte* inOutCtr)
{
    inOutCtr[AES_BLOCK_SIZE - 4] = 0;
    inOutCtr[AES_BLOCK_SIZE - 3] = 0;
    inOutCtr[AES_BLOCK_SIZE - 2] = 0;
    inOutCtr[AES_BLOCK_SIZE - 1] = 1;
}


static INLINE void IncrementGcmCounter(byte* inOutCtr)
{
    int i;

    /* in network byte order so start at end and work back */
    for (i = AES_BLOCK_SIZE - 1; i >= AES_BLOCK_SIZE - CTR_SZ; i--) {
        if (++inOutCtr[i])  /* we're done unless we overflow */
            return;
    }
}


#if defined(GCM_SMALL) || defined(GCM_TABLE)

static INLINE void FlattenSzInBits(byte* buf, word32 sz)
{
    /* Multiply the sz by 8 */
    word32 szHi = (sz >> (8*sizeof(sz) - 3));
    sz <<= 3;

    /* copy over the words of the sz into the destination buffer */
    buf[0] = (szHi >> 24) & 0xff;
    buf[1] = (szHi >> 16) & 0xff;
    buf[2] = (szHi >>  8) & 0xff;
    buf[3] = szHi & 0xff;
    buf[4] = (sz >> 24) & 0xff;
    buf[5] = (sz >> 16) & 0xff;
    buf[6] = (sz >>  8) & 0xff;
    buf[7] = sz & 0xff;
}


static INLINE void RIGHTSHIFTX(byte* x)
{
    int i;
    int carryOut = 0;
    int carryIn = 0;
    int borrow = x[15] & 0x01;

    for (i = 0; i < AES_BLOCK_SIZE; i++) {
        carryOut = x[i] & 0x01;
        x[i] = (x[i] >> 1) | (carryIn ? 0x80 : 0);
        carryIn = carryOut;
    }
    if (borrow) x[0] ^= 0xE1;
}

#endif /* defined(GCM_SMALL) || defined(GCM_TABLE) */


#ifdef GCM_TABLE

static void GenerateM0(Aes* aes)
{
    int i, j;
    byte (*m)[AES_BLOCK_SIZE] = aes->M0;

    XMEMCPY(m[128], aes->H, AES_BLOCK_SIZE);

    for (i = 64; i > 0; i /= 2) {
        XMEMCPY(m[i], m[i*2], AES_BLOCK_SIZE);
        RIGHTSHIFTX(m[i]);
    }

    for (i = 2; i < 256; i *= 2) {
        for (j = 1; j < i; j++) {
            XMEMCPY(m[i+j], m[i], AES_BLOCK_SIZE);
            xorbuf(m[i+j], m[j], AES_BLOCK_SIZE);
        }
    }

    XMEMSET(m[0], 0, AES_BLOCK_SIZE);
}

#endif /* GCM_TABLE */


int AesGcmSetKey(Aes* aes, const byte* key, word32 len)
{
    int  ret;
    byte iv[AES_BLOCK_SIZE];

    #ifdef FREESCALE_MMCAU
        byte* rk = (byte*)aes->key;
    #endif

    if (!((len == 16) || (len == 24) || (len == 32)))
        return BAD_FUNC_ARG;

    XMEMSET(iv, 0, AES_BLOCK_SIZE);
    ret = AesSetKey(aes, key, len, iv, AES_ENCRYPTION);

    if (ret == 0) {
    #ifdef FREESCALE_MMCAU
        cau_aes_encrypt(iv, rk, aes->rounds, aes->H);
    #else
        AesEncrypt(aes, iv, aes->H);
    #endif
    #ifdef GCM_TABLE
        GenerateM0(aes);
    #endif /* GCM_TABLE */
    }

    return ret;
}


#if defined(GCM_SMALL)

static void GMULT(byte* X, byte* Y)
{
    byte Z[AES_BLOCK_SIZE];
    byte V[AES_BLOCK_SIZE];
    int i, j;

    XMEMSET(Z, 0, AES_BLOCK_SIZE);
    XMEMCPY(V, X, AES_BLOCK_SIZE);
    for (i = 0; i < AES_BLOCK_SIZE; i++)
    {
        byte y = Y[i];
        for (j = 0; j < 8; j++)
        {
            if (y & 0x80) {
                xorbuf(Z, V, AES_BLOCK_SIZE);
            }

            RIGHTSHIFTX(V);
            y = y << 1;
        }
    }
    XMEMCPY(X, Z, AES_BLOCK_SIZE);
}


static void GHASH(Aes* aes, const byte* a, word32 aSz,
                                const byte* c, word32 cSz, byte* s, word32 sSz)
{
    byte x[AES_BLOCK_SIZE];
    byte scratch[AES_BLOCK_SIZE];
    word32 blocks, partial;
    byte* h = aes->H;

    XMEMSET(x, 0, AES_BLOCK_SIZE);

    /* Hash in A, the Additional Authentication Data */
    if (aSz != 0 && a != NULL) {
        blocks = aSz / AES_BLOCK_SIZE;
        partial = aSz % AES_BLOCK_SIZE;
        while (blocks--) {
            xorbuf(x, a, AES_BLOCK_SIZE);
            GMULT(x, h);
            a += AES_BLOCK_SIZE;
        }
        if (partial != 0) {
            XMEMSET(scratch, 0, AES_BLOCK_SIZE);
            XMEMCPY(scratch, a, partial);
            xorbuf(x, scratch, AES_BLOCK_SIZE);
            GMULT(x, h);
        }
    }

    /* Hash in C, the Ciphertext */
    if (cSz != 0 && c != NULL) {
        blocks = cSz / AES_BLOCK_SIZE;
        partial = cSz % AES_BLOCK_SIZE;
        while (blocks--) {
            xorbuf(x, c, AES_BLOCK_SIZE);
            GMULT(x, h);
            c += AES_BLOCK_SIZE;
        }
        if (partial != 0) {
            XMEMSET(scratch, 0, AES_BLOCK_SIZE);
            XMEMCPY(scratch, c, partial);
            xorbuf(x, scratch, AES_BLOCK_SIZE);
            GMULT(x, h);
        }
    }

    /* Hash in the lengths of A and C in bits */
    FlattenSzInBits(&scratch[0], aSz);
    FlattenSzInBits(&scratch[8], cSz);
    xorbuf(x, scratch, AES_BLOCK_SIZE);
    GMULT(x, h);

    /* Copy the result into s. */
    XMEMCPY(s, x, sSz);
}

/* end GCM_SMALL */
#elif defined(GCM_TABLE)

static const byte R[256][2] = {
    {0x00, 0x00}, {0x01, 0xc2}, {0x03, 0x84}, {0x02, 0x46},
    {0x07, 0x08}, {0x06, 0xca}, {0x04, 0x8c}, {0x05, 0x4e},
    {0x0e, 0x10}, {0x0f, 0xd2}, {0x0d, 0x94}, {0x0c, 0x56},
    {0x09, 0x18}, {0x08, 0xda}, {0x0a, 0x9c}, {0x0b, 0x5e},
    {0x1c, 0x20}, {0x1d* aee2c
 *
 *f* aea4c
 *
 *e* ae66},
    *
 *b* aes8c
 *
 *aCopyrac
 *
 *82006-cc
 *
 *9SSL Iec.
 *
 * Th2* ae3.c
 *
 *3* aefight (C)1* aeb2014 wol0* ae7nc.
 *
 * Th5 can e is par4ute iyaSSL.
 6modifyaSSL is7nder software; y3*
 * 4.c
 *
 3 free8ight (C3is fic2014 wo3t of 0nc.
 *
 * T3 20064e is pa3fSSL 8yaSSL.
3/* aecyaSSL i3 Copy0 * the Free nse a5re Founded by9 either  the dn 2 of tal Pu1ense, or
 *  modi5ur optiounder9 later vu cand.
 *
 * bute 1software; y2al Pu6.c
 *
 2 the aight (C2ed bye2014 wo2nse a2nc.
 *
 * T2bute 6e is pa2u canayaSSL.
2undereyaSSL i2 modi2 MERCHANTABIt of 7r FITNESis fibA PARTIC freefURPOSE. *
 * 3he
 * GNU Ge Copy7Public L/* aeb for morfSSL fils.
 *
 20063software; y7under8.c
 *
 7 modi4ight (C7bute 02014 wo7u cancnc.
 *
 * T7ed by8e is pa7nse a4yaSSL.
7al Pu0yaSSL i7 the ctware
 * FoufSSL 9n, Inc., 20065anklin S Copy1 Fifth F/* aedBoston, MA 0 free9301, USA*
 * 5#ifdef Ht of 1NFIG_H
 is fidsoftware; y6/* aea.c
 *
 6 Copy6ight (C6 200622014 wo6fSSL enc.
 *
 * T6is fiae is pa6t of 6yaSSL.
6*
 * 2yaSSL i6 freee before headu canbse direcbute 7rnal f() modi3wrappersunderf  #define FI the bWRAPPERSal Pu7f

#inclnse a3yassl/cted byfsoftware; y4*
 * c.c
 *
 4 free0ight (C4is fi42014 wo4t of 8nc.
 *
 * T4 2006ce is pa4fSSL 0yaSSL.
4/* ae4yaSSL i4 Copy8cyassl/ctaocnse adisc.h>
#ed by1   #incl the 5taocryptal Pu9isc.c>
#endi modidef DEBUGunder1
    #inu can5<stdio.hbute 9software; y5al Pue.c
 *
 5 the 2ight (C5ed by62014 wo5nse aanc.
 *
 * T5bute ee is pa5u can2yaSSL.
5under6yaSSL i5 modiaTM32F2_CRYPTt of f  /* STMis fi3ardware  free7pport fo*
 * b CTR modes t Copyf the STM/* ae3     * SfSSL 7d Periph 2006bsoftware; ye modi0.c
 *
 eundercight (Ceu can82014 woebute 4nc.
 *
 * Tense a0e is paeed bycyaSSL.
e the 8yaSSL ieal Pu4TE: no suppo 20061 AES-GCMfSSL direct *//* ae9include  Copy5f2xx.h"
    *
 * 1de "stm3 freedcryp.h"
is fi9defined(t of 5software; yf Copys.c
 *
 f/* aeright (CffSSL -2014 wof 2006Inc.
 *
 * Tft of le is pafis fiCyaSSL.
f freeCyaSSL if*
 *  software; yfbute  redistrfu canit and/ofunderfy
 * itf modi the terms ofal PuGNU Genef the blic Licfed bys publisfnse a
 * the Freed freeare Found*
 * ; eitherdt of on 2 of dis ficense, or
 *dfSSL our optid 2006y later d Copyn.
 *
 *d/* aeL is distribded byn the hodnse at it wildal Puseful,
 d the WITHOUT ANY dunderTY; withd modien the idbute  warrantdu can* MERCHANTABc the or FITNEcal Pu A PARTIcnse aPURPOSE.ced bythe
 * GNU Gcu can Public cbute e for moc modiails.
 *cunderu should havcis fiived a cct of  the GNUc*
 * al Public freense
 * alongc/* aethis proc Copyif not, c 2006to the FcfSSL ftware
 * Fo9 modion, Inc.9underranklin 9u can, Fifth 9bute  Boston, MA 9nse a1301, US9ed by
#ifdef 9 the ONFIG_H
9al Punclude <conf9 2006#endif

9fSSL de <cyas9/* aeocrypt/s9 Copys.h>

#ifnde9*
 * ES

#ifd9 freeE_FIPS
 9is fiset NO_W9t of S before hea8 Copyuse dire8/* aeernal f(8fSSL  wrapper8 2006   #define F8t of _WRAPPER8is fiif

#inc8 freecyassl/c8*
 * pt/aes.h>
#i8bute  <cyassl8u canrypt/err8underpt.h>
#i8 modi <cyassl/cta8al Pu/logging8 the fdef NO_8ed by
    #in8nse a<cyassl/ctaoa freemisc.h>
a*
 *     #incat of ctaocrypais fimisc.c>
#endafSSL def DEBUa 2006I
    #ia Copy <stdio.a/* aedif


#ifdefaed byVER
    anse a7 warninaal Putant whia the  */
    #praaunderrning(dia modi 4127)
#abute 

#if deau canSTM32F2_CRYPb the    /* STbal Puhardwarebnse aupport fbed by, CTR modes bu canh the STbbute       * b modird PeripbunderLibrary. Docbis fition locbt of n STM32Fb*
 *     * Stb free Peripheral b/* aey documeb Copye note ib 2006ME).
   bfSSL be} };


static void GMULT(byte *x, x6030m[256][AES_BLOCK_SIZE])
{
 *
 int i, j;
 *
 x6030Z03U, 0xce6767a9U   0xe7fefea;

 *
 XMEMSET(Z, 0, sizeof(Z)), 0xec7for (i = 15; i > 0; i--) 0x562bU,
 xorbuf
   m[x[i]], 3U, 0xce6767a9)   0xe, 0xa = Z[15], 0xec71f82829dUj 0x89c9j940U, jxfa7d7d87U,
  x45aZ[j]f0f00j-1, 0x4dacbfU}    0x41adZ[0aU,
R[a][0x239c9cbfU,Z[1] ^e4727290x239c9c}
 *
   0xeffafa15U,00xb25959ebU, 0x8e47470xec76769CPY(x, Zb25959ebU, 0x8e4747}U, 0x91c5c554U,
HASH(Aes* aes, conste7fef* a, word32 aSz.
 *
 xf9f1f108U,
    0xe2717193U,U, 0x51a5a5fcU, 0xd1e5cSz50U, 0* sU, 0xd1e5sSz, 0x562bx6030x9U, 0xb5d7d762U, 0x4dababe6scratch9U, 0xb5d7d762U, 0x4da 0xd1e5blocks, partial, 0xec76769aU,
x   0x, 0x4c26266aU,
    0x6/* Hash in A, the Additional AuthenticadU,
 Data */x562b2f (aSz != 0 && a2cdUNULLa7d7d87U,
  , 0x0a =5e53 /e070709U, 0x241239c9cbfU,050fU, 0x1d838%9eU, 0x582c2c74U, 0x341a1while (, 0x0ax5fa2a2fdU, 0x45af  0xeffx,f4U,5959ebU, 0x8e4747c9U, 0xfdb3b
    0 0x7es->M0d661U, 0x7db3b3a +=9eU, 0x582c2c74U, 0x341a1 0xe1f9U, 0x7fa2eU,
  cdU,fa2a2fdU, 0x45af6769aU,
3c35eU, 0x0e070709U, 0x241212 0x00000000U, 0x65aUed2cU,
  a05050fU, e3fcfc1fU, 0x79252f6U, 0xed2cU,
  b3b4dU, 0xb7d6d661U, 0x7db3b3ceU,
    0x5229297bU, 0xdde 0xe1f 0x53a40x1b80809bUC 0xdfeCiphertext72769U, 0x7fc2b2cdU, 0xec75759fU,
    0x1209091bU, 0x1aae539eU, 0x582c2c74U, 0x341a1a2eU,
    aae51b1b2dU, 0xdc6e6eb2U, 0xb45a5aeeU, 0x5ba0a0fbU,
    0xa45252f6U, 0xc63b3b4dU, 0xb7d6d661U, 0x7db3b3ceU,
    0x5229297bU, 0xdde3e33cU, 0x5e2f2f71U, 0x13848497U,
    0xa65353f5U, 0xb9d1d168U, 0x00000000U, 0xc1eded2cU,
    0x40202060U, 0xe3fcfc1fU, 0x79b1b1c8U, 0xb65b5bcdU,
    0xd46a6abeU, 0x8dcbcb46U, 0x67bebed9U, 0x7239394bU,
    0x944a4adeU, 0x984c4cd4U, 0xb05858e8U, 0x85cfcf4aU,
    0xbxdfelengths of A and C09bUbits72769U, FlattenSzInBits(&3c35eU,
0],5e53e3fcfc1171739U,
    0x93c4c457U,8],x8a4e3fcfc1dcbcb46U, 0x67bebed9U, 0x7239394bU,
    ceU,
    0x5229297bcfcf4aU,Copy5f5feresultb2b7o s.72769U, b1b1c8U, , U, 00xc86}

/* end GCM_TABLE7276#elif defined(WORD64_AVAIL9090) 0xe!88883U,
 0x3    32), 0x91c5c554U,
    0 0xd64* XU, 0xdede7Y, 0x562b 0xbc5 Z[2aU,
{0,0}, 0x37969664 V, 0x; x562b2b7dU,
    0xeV, 0xe4X, 0x;43a314eU, 01]  0x1f82829dU, 0xU, 0 < 2; i++)
 *
 *b2U, 0xb45 0xdbey = Y[ix239c9cbfU,adecU, 0xU, 0 < 64; j824246cU46cU, 0xb85c5c9U, 0x7fy &ll le595a4U, 0xd3e4fa2a2fdU, 0x45afa4f7U, 0x^=3a3a43fcfc1fU, 0x79c0c05bU,
   a1eU3fcfc1fU, 0x79 0x53a4a4f79U, 0x7fa1eU,0x31595a4U, 0xd3e4e1437U, 0xf279798bU,
 a1eU,>>= 12U, 0x8bc8c843U, 0a1eU,|= ((a3a4e64U, 0x9c4e4ed2U, 0x49?x319595a4U, 0xd3e4e : 297bU, 0xdde3e33x743a3a4eU, 0xac5656faU, 0xf3f4f40 0xd5e0xE1595a4U, 0xd3e40xda6d6db7U,
   xf9f1f108U,
else9a9a9e0U,
    0xd86c6cb4U, 0xac5656faU, 0xf3f4f407U, 0xcfeaea25U,
    0xca6565afU, 0xf47a7a8eU, 0x47aeaee9U, 0x10080818U,
    0x6fbabad5U, 0xf0787888U,0x57a6a6f1U, 0y << 0xac5656faU,8U, 0x857fU,
, 0xe4U, 03fcfc1   0x0f00b]f702U, 0x83cccc4fU,
    0x6834345cU, 0x51a5a5f4U, 0xd1e5e534U, 0xf9f1f108U,
    0xe2717193U, 0xabd8d873U, 0x62313153U, 0x2a15153fU,
    0x0804040cUe4U,
  x, 0xaddbdb76U,
    0xa1U, 0x0a05050fU, 0xe1e138U, 0xbigH[2,
    0xb1b1c8U, 0xa  0x522Hed9U, 0x7239394bU,
    #ifdef LITTLE_ENDIAN_ORDERx57a6a6f1ByteReverseWords64e89U, 089U, 05959ebU, 0x8e474, 0x64#endif236U, 0x1b80809bU, 0xdfe2e23dU,
    0xcdebeb26U, 0x4e272769U, 0x7fb2b2cdU, 0xea75759fU,
    0x12090969bbU, 0xA9d9d9 0x1209091bU, 0x1d83839eU, 0x582c2c74U, 0x341a1a2eU,
    0x361b1b2dU, 0xdc6e6eb2U, 0xb45a5aeeU, 0x5ba0a0fbU,
    0xa450x078e8e89UA0x763b3b4dU, 0xb7d6d661U, 0x7db3b30x3c1e1e22U, 0x15878792U, 0xc9e9e92xc9e9e920U,
    0x87cece49U, 0Aaa555Ax84f87c7cU, 0x99ee7777U, 0x8df67f7aU,
6a6abeU, 0x8d25256fU68b8U732U, 0x8bc8c843xbU,
   68b8U, 0xda6d6db7U,
 ceU,
     0xa97bU, 0xdde3e33eU, 0x5e2f2f71U, 0x13848497U,
    0xa65353f5U, 0xb9d1d168U, 0x00000000U, 0xc1edx50603  0x40202060U, 0xe3fcfc1fU, 0x79b1b1c8U,363U, 0x8,
    0xd46a6abeU, 0x87b7bU,
    0x0dfff2f2U, 0xbdd66b6bU, 0xb1de6f6fU, 0x5491c5c5U,
    0x50603030U, 0x03020101U, 0xa9ce6767U, 0x7d562b2bU,
    0x19e7fefeU, 0x62b5d7d7U, 0xe64dababU, 0x9aec7676U,
    0x458fcacaU, 0x9d1f8282U,8U, 0x85cfcf4aU,
    0xbbd0d06bU, 0xc5efef2aU, 0x4faaaae5U, 0xedfbfb16U,
    0x864343c969bbU, 0xCU,
    0x824141c3U, 0xd4dd7U, 0x66333355U, 0x11858594U,
    0x8a4545cfU, 0xe9f9f910U, 0x04020206U, 0xfe7f7f81U,
    0xa0505a2U, 0xea45C783c3c44U, 0x259f9fbaU, 0x4ba8a8e37b7bU,
    0x0dfff2f2U, 0xbdd66b6bU, 0xb1de6f6fU, 0x5491c5c5U,
  CcaU, C03030U, 0x03020101U, 0xa9ce6767U, 0x7d562b2bU,
    0x19e7fefeC, 0x62b5d7d7U, 0xe64dababU, Cx9aec7676U,
    0x458fcacaU, 0x9d1f8282U, 0x4, 0x804040c0U, 0x058f8f8aU,
    0x3f9292adU, 0x219d9dbcU, 0x70383848U, 0xf1f5f5
    0ec41adadU, 0x67b3d4d4U, 0xfd5fa2a2U, 0xea45cdebeb
    0xbf239c9cU, 0xf753a4a4U, 0x96e47272U, 0x5b9bc0c0U,
    0xc275b7b7U, 0x1ce1fdfdU, aU,
    0x2d361b1bU, 0xb2dc6e6eU, 0xeeb45a5aU, 0xfb5ba0a0U,
    0xf6a45252U, 0x4d763b3bU, 0x61b7d6d6U, 0xce7db3b3U,
    0x7b522929U, 0x3edd, 0xc3ecec2fU,
    0xbe5f5fe1U, 0x35884444cc9797a2U, 0x2769U, , 0xb85c5ce4U,
  lene03bU, 0x64xba2x447 0xe4d838;59f9f305U,cSz
    0x41ad/* LU, 0x35are0x060ytes. Convert to4444c3dcdc7fU,ba259f9fU, *= 8    0x8241a8U,
  19d9dU7d87U,
   25256fU9f9fU,    0x8241e64dababa8U,
     0x8241x458fcacaU, 0x9d1f82
    00x3c1e1e22U, 0x15878792U, 0xc9e9e920U,
    0x87cece49Ux222267U,
    0x2d9b9bb6U, 0, 0x7d562b
    0x44222266U, 0x542a2a7eU,88883U,
    0x8c4646caU, 0xc7eeee29U, 0x6bb8b8d3UabU, 0xse0xfe0x6bb8b8d37f7f 0x2814143cU,
    0xa7d32e79U, 0xb0xe7ee2U, 0x160b032 Z[40xaddbdb   00x2b9898b3U, 0V7373    0x2b7dU,
   0x743a3a4eU, 0x10a0a1eU,
    0;e0e03b=60302, 0x73542a2aU3,
    0xbU, 0x0c06060aU,40x4824246cU, 0xb85c5ce4U,32   0x9fc2c25dU, 0xbdd3d36eU, 0x43ac32efU, 0xc46262a6U,
    0x399191a8U, 0x319595a4U,437U, 0xf279798bU,
    0xd5e7e732U, 0x8bc8c843U, 0x6e373759U, 0xda6d6db7U,
 c0c05b20xd5e7e,
    0x82410x9bc0c05b30xd5e7e 0x8da6d6db7U,
    0x018d8d8cU, 0xb1d3a25U,
    0xcx49a9a9e0U,
    0xd86c63babad5U, 0xf0787888U, 0x4a23U, 0xcfea2   0xa8399191U, xf47a7a8eU, e9U, 0x10080818U,
    0x62babad5U, 0xf0787888U, 0x4a22U, 0xcfea5d564U, 0x9c4e96e3737U, 0xb7da6d6dU,
    0x8c018d8dU, cb4U, 0xac5656faU, 0xf3f4f407U, 0xcfeaea25U,
    0xc96e3737U, 0xb7da6d6dU,
    0x8c018d8dU, fbabad5U, 0xf0787888U, 0x4a25256fU, 0x5c2e2ebdd3d3U, 0xef430x73b4b4c7U, 0x97c6c651U,
4e4U, 0x8bf27979U,
    0x32d5e7e7U, 0x438bc8c8U, 0x596e3737U, 0xb7da6d6dU,
    0x8c018d8dU, 0x64b1d5d5U, 0xd29c4e4eU, 0xe049a9a9U,
    0xb4d86c6cU, 0xfaac5656U, 0x07f3f4f4U, 0x25cfeaeaU,
    0xafca6565U, 0x8ef47a7aU, 0xe947aeaeU, 0x18100808U,
    0xd56fbabaU, 0x88f07878U, 0x6f4a2525U, 0x725c2e2eU,x7c3e3e42U, 0x71b5b5c4U, 0xcc6666aaU,
    0x904848d8U, 0x06030305U, 0xf7fx06030e542a82428U, 0x333b909fc2c7f6f601U, 0x1c0e0e12U,
    0xc26161a3U, 0x6a35355fU, 0xae5757f9U, 0x69b9b9d0U,
    0x17868691U, 0x99c1c158U, 0x3a1d1d27U, 0x279e9eb9U,
    0xd9e1e138U,32 x7373U,
    0xa0c06060U, 0x98x22111133U,
    0xd26969b 0x80xa949d970U, 0x078e8e89U, 0x339494a7U,
    0x2d9b9bb6U, 0x3c1e1e22U, 0x15878792U, 0xc9e9e920U,
    0x87ceceU, 0xaa5555ffU, 0x50282878U, 0xa5dfdf7aU,
    0x038c8c8fU, 0x59a1a1f8U, 0x09898980U, 0x1a0d0d17U,
    0x65bfbfdaU, 0xd7e6e631U, 0x844242c6U, 0xd   0xdA65bfb  0x824141c3U, 0x299999b0U, 0x5a2d2d77U, 0x1e0f0f11U,
    0x7bb0b0cbU, 0xa85454fcU, 0x6dbbbbd6U, 0x2c16163aU,
},
{
    0xa5c66363U, 0x84f87c7cU, 0x99ee7777U, 0x8df67b7bU,
    0x0dfff2f2U, 0xbdd66b6bU, 0xb1de6f6fU, 0x5491c5c,
    0x50603030U, 0x03020101U, 0xa9ce6767U, 0x7d562b2bU,
    0x19e7fefeU, 0x62b5d7d7U, 0xe64dababU, 0x9aec7676U,
    0ebf8fbabU, 0x,
    0x472U, 0xc02c2U, 0x6fb6ebdd3d3U, 0xef4x458fcacaU, 0x9d1f8282U, 0x4089c9c9U, 0x87fa7d7dU,
    0x15effafaU, 0xebb25959U, 0xc98e4747U, 0x0bfbf0f0U,
    0xec41adadU, 0x67b3d4d4U, 0xfd5fa2a2U, 0xea45afafU,
    0xbf239c9cU, 0xf753a4a4U, 0x96e47272U, 0x5b9bc0c0U,
    0xc275b7b7U, 0x1ce1f47U, 0xf00bfbf0U,
    0xadec41adU, 0xd467b3d4U, 0xa2fd5fa2U, 0xafea45afU,
    0x9cbf239cU, 0xa4f753a4U, 0x7296e472U, 0xc05b9bc0U,
    0xb7c275b7U, 0xfd1ce1fdU, 0x93ae3d93U, 0x266a4c26U,
    0x365a6c36U   0x93e27171U, 0x73abd8d8U, 0x53623131U, 0x3f2a1515U,
    0x0c080404U, 0x5295c7c7U, 0x654   0xdCb1de6fU, 0xc55491c5U,
301818U, 0xa1379696U, 0x0f0a0505U, 0xb52f9a9aU,
    0x090e0707U, 0x36241212U, 0x9b1b8080U, 0x3ddfe2e2U,
    0x26cdebebU, 0x694e2727U, 0xcd7fb2b2U, 0x9fea7575U,
    0x1b120909U, 0x9e1d8383U, 0x74582c2cU, 0x241a1aU,
    0x2d361b1bU, 0xb2dc6e6eU, 0xeeb45a5aU, 0xfb5ba0a0U,
    0xf6a45252U, 0x4d763b3bU, 0x61b7d6d6U, 0xce7db3b3U,c05b9bc0U,
, 0x5e9dc3c3U,U, 0xfd1ce1fdU,C0x93ae3d93U, 0x266a4c26U,
    0x365a6c36U, 0xU, 0x715e2f2fU, 0x97138484U,
    0xf5a65353U, 0x68b9d1d1U, 0x00000000U, 0x2cc1ededU,
    0x60402020U, 0x1fe3fcfcU, 0xc879b1b1U, 0xedb65b5bU,
    0xbed46a6aU, 0x468dcbcbU, 0xd967bebeU, 0x4b723939U,
    0xde944a4aU, 0bed967beU, 0x394b7239U,
    0x4ade944aU, 0x4cd4984cU, 0x58e8b058U, 0xcf4a85cfU,
    0xd06bbbd0U, 0xef2ac5efU, 0xaae54faaU, 0xfb16edfbU,
    0x43c58643U, 0x4dd79a4dU, 0x33556633U, 0x85941185U,
    0x45c85U,
    0xcf8a4545U, 0x10e9f9f9U, 0x06040202U, 0x81fe7f7fU,
    0xf0a05050U325afda5bfbfU, 0U, 0xfe5da3a3U, 0xc0804040U, 0x8a058f8fU,
    0xad3f9292U, 0xbc2=7fb2b2>> (8*8fcaca45a7a - 3U, 0, 0x48703838U, 0xe34b<< 3
    0x2266442e542aaaae54fd19e4fU, 0x 0xca3dcU,
    0x22664423b909aae5e542aUf5f5U,
    0xdf63bcbcU, 0xc177b6b6U, 0x75afdadaU, 0x63422c05b9bc0x4478360bU, 0xdb762c2U, U, 0xbU, 0x63422121U,
    0x30201010U, 0x1ae5ffffU, 0x0efdf3f3U, 0x6dbfd2d2U,
    0x4c81cdcdU0x14180c0cU, 0x35261313U, 0x2fc3ececU,
    0xe1be5f5fU, 0xa2352fc3ec0xfe7eU, 0x3U, 0x477a3d
2b7dAesGcmEncrypt 0x6834345cx2a151out5cU, 0x51a5a5fin3fU,
    034U, 0xf9f1f108U,
    8bc8U, 0x3759vU, 0xd1e5iv534U, 0xf9f1f108U,
    1a5a5f4uthTagU, 0xd1e5e6cU, 0534U, 0xf9f1f108U,
    U, 0x51a5a5f4uthI6e37U, 0x65U, 0x 0x7aa5dfdfU,
   91bU, 0x1sdd7U, 0x66333355U, 0x118 0xd1e5a2eU,
    s4545cfU, 0xe9f9f910U, 0xU, 0x51a5a5fp = in   0xe7fef* c =0xc8   0xe7fefecounter9U, 0xb5d7d762U, 0x4dababe6*ctr81U, 0x0x9dc3c35eU,
    0x30181828U, 
0x3c1e1FREESCALE_MMCAUc773b4U, 0xke  0x0x603*)0x522key;83991U,143c28CYASSL_ENTER("x798bf279U,
 "0U, 0x3c1e15U, 0x6PIC32MZ_CRYPT381cU,tr 0x88har , 0x3e4iv_ce 3eU,lse 0x0e121c0e823cbe8, 0x37aU,
    06769aU,
ctr,
    0x60402020U, 0x1fe3fb1b1c8U,91178d5U,9c4e,
    0InitGcmC23cbe8x9eb048U, 0x03050603U, 0xf601f7f6U, 0x0eifU, 0x5b0xc46262a6AesCU,
  4345cxc84396e3, 0x0a*3U, 0xce6767a94U, 0xf9f1f108U 0xf6_EN7f6U,ION,, 0x879ALGO_AESe920c9e97f6U,OU,
    0_GCM )3eU, 0xb50xb45a5aeeU, 0x5ba0a0fbU,
    0Incremene1U, 0xf813ebf8U, fb2b2U, 0x9nx03050603U, 0xf601f7f6U, 0x0efb2b2U, 0x9fea7860d8bU, 0x8a850f8aUea25cfeaU,
  au_aes_e79U,
  91178key  0x522rounds, 0x67beb01U, 0xa9ce6767U,55f6a35Ubd66dbbU, 0xAes279U,
  4345cU1178  0xb0cb7bb0U, 0x54fca85 0x7d562b2bU,  0xeffed2cU,
  ped9U, 0x7239394bU,
    0x94a1dU, 0x9, 0x67bebed9U, 0x7239394bU,
    0x94, 0x777799eeU, pU, 0x5e2f2f71U, 0x13848497U,, 0x804040c0U, 0x058f8f8a 0x53a4353f5U, 0xb9d1d168U, 0x000000xa1f859a1U, 0x89800989U, 0x0d171a0dU2U, 0x68b8d068U,
    0x41c38241U99b02999U, 0x2d775a2dU, 0x0f111e0fU,
    0xb0cb7bb0U, 0x5854U, 0xbbd66dbbU,63a2c16U,
},
{
    0x6363a5c6U, 0x7c7c8, 0x777799eeU, 0x7b7b8df6U,
    0x,
    0xd46a6abeU,x6f6fb1deU, 0xc5c554,
    0xd4, 0xababe64d,
    4345c5U, 0x7a, 0xaee98eU, 0xszeU, 0x, 0x5U, 0xf407  0xe138d9e1U, 0xf813ebf8U, 42c68442U, 0x68b8d068U,
    0x41c3899b02999U, 0x2d775a2dU, 0x0f111e0fU,
    0xb0cb7bb0U,854U, 0xbbd66d63a2c16U,
},
{
    0x6363a5c6U, 0x7, 0x777799e  0xeff86cU, 0x5 0xb65b5be   0x34345c34d1Ureturn 0f702U,2b7d0x798bfDe9U,
    0xe732d5e7U, 0xc8438bc8U, 0x37596e37U, 0x6db7da6dU,
    0x8d8c018dU, 0xd564b1d5U, 0x4ed29c4eU, 0xa9e049a9U,
    0   0x65afca65U, , 0x56faac56U, 0xf407f3f4U, 0xea25cfeaU,
    0x65afca65U, 0x7a8ef47aU, 0xaee947aeU, 0x08181008U,
    0xbad56fbaU, 0x7888f078U, 0x256f4a25U, 0x2e725c2eU,
    0x1c24381cU, 0xa6f157a6c651xb4c773b4U, 0xU, 097c6U,
    0xe823cbe8U, 0xdd7ca1ddU, 0x749ce874U, 0x1f213e1fU,
    0x4bdd964bU, 0xbddc61bdU, 0x8b860d8bU, 0x8a850f8aU,
    0x7090e070U, 0x3e427c3eU, 0xb5c471b5U, 0x66aacc66U,
   , 0x8089048U, 0x03050603U, 0xf601f7f6U, 0x0e121c0eU,
    0x61a3c261U, 0x355f6a35U, 0x57f9ae57U, 0xb9d069b9U,
    0x86911786U, 0xc15899c1U, 0x1d273a1dU, 0x9eb9279eU,
    0xe138d9e1U, 0xf813ebf8U, 00x198181alculate5f5fe 0x9a9a again using, 0x9e4ceivedfba25 d4e272U, th, 0xbbd* c, 0xc 5efe3dcdc7fU,   0x1209096030Tprime9U, 0xb5d7d762U, 0x4da13e1fU,
 EKY0dd964bU, 0xbddc61bd3U, 0x2665a6cU, 0x3f3f417eU, 0xf7f70296e30xcc0x9d9d0x8fcaca40x9d9dU,
    0x226d7d87faU,
    0xfafa15efU, 0x5959ebb2U, 0x4747c98eU, 0xf0f00bfbU,
    0xad,
  , 0xd4d467b3U, 0xa2a2fd5fU, 0xafafea45U,
    0x9c9x5f5fe1beU, 0x9790x777799eeU, 0x7b7b83020U, 0,
   0xffff1ae5U, 0xf3f6b6c177U,0x7fb1b1cMPa137U, 0x03020U, 0 0x9a9ab529d1d168U, 0x00000000U 0x0707a55U, 0_AUTH_x13848497U,
    0}
 0x98b32b98U, 0x11332211U,
    0x69bbd269U, 0xd970a9d9U, 0x8e89078eU, 0x94a73394U,
    0x9bb62d9bU, 0x1e223c1eU, 0x879DE587U, 0xe920c9e9U,
    0xce4987ceU, 0x55ffaa55U, 0x28785028U,, 0xdf7aa5dfU,
    0x8c8f038cU, 0xa1f859a1U, 0x89800989U, 0x0d171a0dU,
    0xbfda65bfU, 0xe631d7e6U, 0x42c68442U, 0x68b8d068U,
    0x41c38241U, 0x99b02999U, 0x2d775a2dU, 0x0f111e0fU,
    0xb0cb7bb0U, 0x54fca854U, 0xbbd66dbbU, 0x163a2c16U,
},
{
    0x6363a5c6U, 0x7c7c84f8U, 0x777799eeU, 0x7b7b8df6U,
   3c3c44U, 0x259f9fbaU, 0x4ba8b1b1c8U,pU, 0xc5c55491U,
    0x30305060U, 0x01010302U, 0x6767a9ceU, 0x2b2b7d56U,
    0xfefe19e7U, 0xd7d762b5U, 0xabae64dU, 0x76769aecU,
    0xcaca458fU, 0x82829d1fU, 0xc9c94089U, 0x7d7d87faU,
    0xfafa15efU, 0x5959ebb2U, 0x4747c98eU, 0xf0f00bfbU,
    0xadadec41U, 0xd4d467b3U, 0xa2a2fd5fU, 0xafafea45U,
    0x9c9cbf23U, 0xa4a4f753U, 0x727296e4U, 0xc0c05b9bU,
  db65b5bU,
    0xbed465656faacU, 0xf4f407f,
    0xd46a6a7888f0 0x0707090eU, 
5U, 0x6APIxd19eGmacSetKey(f6aU* gmtic U, 0x51a5a5fU, 0xU,
    0x6, 0x562b, 0x4f4f798bf, 0x575&, 0x->4345cU, 0x, 0xf702U,1a3c2U, 0x35355f6aUUpdate57f9aeU, 0xb9b9d069U,
   d5U, 0x4ed29c4eU, 0xa9e049a9U,
    0a25cfeaU,
    0x65afca65U, 0x7a8ef47aU, 0xaee94U, 0xf9f1f108U,
    0xe2717193Ux6cb4d86cU, 0x56faac56U, 0xf407xc1c15899U, 0x1d1d273279U,
  e9eb927U,
  9fU,U, 0x89809279eU,
  4U, 0xf9f1f108U,
    0xe2717193U, 0xdde3e33ec4f83U,
    0x343x3f3f417eU, 0xf7f70x91a83991U, 0x9HAVE   0, 0x7d3e4d7d87fad775aU, CCM11eU,
   STM32F7ceU, 0x   0x18rror "fca8U,  9U,
 o doesn't currently support4fd1-CCM mode"a839x0b888883U,
d775aCOLDFIRE_SEC4246cU 0x16163Coldfire SEC 0x63636363U, 0x7c7c7c7cU, 0x77777777U, 0x7b7b7b7bU,
   50603U, 0xf601f7f6U,b6b6b6bU, 0x6f 0xf601 0x63636363U, 0x7c7c7c7cU, 0x77777777U, 0x7b7aU,
 554U,9U, 73aU, 0x90x6834345cU, 0x51a5a5f 0x86869117Ukeyx0804040cU, 0x9noncdbc21U, 0x38384870U888f0U, 0!((59595 == 16) || 0xd4d4d4d424 0xa2a2a2a2U, 032))0xc46262a6 0x070, 0xec76769aU,
7U, 0   0x8fcaca47U, 0U,
    0Aes, 0x575U,
    0xe59595,47U, 080c0cU21587U, 0x7f702U, 0x83cccc4fUroll_x 0x7d7d7d7dU,
    0xfaf96e37U, 0x6i7f702e7U, 0xc8, 0x562bd7d87faU,
    0xfafa15efU, 0x59,
    0x7090e070U, 0x3e427c3ea5dfdf7aU,
    0x03process5f5febulk02U,xdfexa3a32769U, 5a5aeeU4343 > 0x5e2f2f71U, 0xa7d7d87U,
    0xeffU, 0x94a75959ebU, 0x8e4747c9U, 0xfinU, 0x5e2f2f71U, 0x13848497U, 0xc3- 0x5e2f2f71U, 0x13089U, 0x7d7d87faU,
    0xfafa15efU, 0x5959ebb2U, 0x4747c98eUxc843U, 0x0f111e0fU,
  a5a5 0xd4d467b3U, 0xa2a2fd5fU, 0xafafea45U,
    xc8430x2c2c2c2cU, 0x1028U, 0xd85cfcf4aU,
    0x0remainder, 0xc7c7c7c7U, 0x2320x7f 0xc3cd168U, 0x000006969696U, 0x0505434394089U, 0x7d7d87faU,
    0xfafa15efU, 0x5959ebb2U, 0x4747c98eU9090909U, 0x83838383U, 0x2c2c2c2cU, 0x1a1a1a1aU,
    0x1b1b1b1bU, 0x6e6e6e6eU, 0x5a5a5a5aU, 0xa0a0a0a0U63636U, 0x3f3f3f3fU, 4U, xf7f7f7f7U, 0xccccccccU,
    0x34343434U, 0xa5a5a5a5U, 0x8ef47aU, 0xL9U,
1a0d0dU,
    U, 0x3b3b   0xebe5e5e5e5U, 0xf1f1f1f1U,
    0x71717171U, 0xd8d8d8d8U, 0x31313131U, 0x15151515U,encod0x9f9f1U, 0x0x07d6d6U, 0xb3b3b3b<fU, FEFFa7d7d87U,
  xd0d0d0d0 = 2, 0x0d171aout25256fU(3b3b3b0x31FFbe0e>> 8c2c2c2cU, 0f9f9U,
   b3b3b3b64U, 0FF1f7U, 0x0e0e1, 0x802U, 0x7f7f7f7fd9d9dU,    0x50505050U, 0x3c3c363cU, 0x9f9f9f9fU, 0xd9d9;3a3a3a3U, 0f7fU151U, 0xa3a3a35b9bc0a8a8a8a8U,
    bdbe0e>>0xaf151U, 0xa3a3a32c2U, a8a8a8a8U,
 0x8xffffffff16 0xf3f3f3f3U, 04d2d2d2d2U,
    0xcxcdcdcfffff515151U, 0xa3a3a353U, 0x40404040U, 0cU,
  1f7U, 0x0e0e1/* Note 0xdfeprotocol handlesa2U, 0xa3a3upf8fU2^.h>
but we, 0x0x4040c034bU,
32-bitx8fcas right now, so040404igger7c7c7Ui363630x7e7ed0x4040c0 0x92929292U, 0x9d9d9d9dU, d9d9dU, 0x3}0x02020254U, 0xbbd66da4a4a4a4U, 0x/* start fill3a3a, 0x9e4ft, 0xc7c7fir0x51 0x00x020202U, 0x3b3b3 0x5e2f2f71U, 0x -0xd0d0d0d0U, 0xe0xb3b3b3b3=1414U,
   a7d7d87U,
   0x5lenty02U,404U,xa3a3tox46464 0x9e4 0x3b3b3b3bU,isb8b8U, 0x141419292929U, 0xe3 +050U, 0x3c    0xbdbU,
    12U, 0x80808080U, U, 0xaaaaaaU,
    0x07070 0xacacacacU, 0U,
    0x92xe0e0e0e0U, 0not enoughU, 0x3a3a3b9b9py what is availabl5e6Und pad zero0x06060606U, 0x24242424U, 0x5c5c5c5cU,
 U, 0x2f2f2f2fU, 0xc3U, 001010U, 0x1ae5ffff108f9U,
    0x717193e2U, 0xd8d873abU, 0x9090909U, 0x83838383U, 0x2c2c2c2c8U, 0xc7c75295U, 0x23236546U, e6e6eU, 0x5a5a5xb9d069b9U,
0xb3b3b3b3U,
x90909090UfU, 0x4345cd5d5d5d56eU, 0x502U, 0x83ccINLINEc554U,0xc9c9CtrInce070U, B86869117U, 0 0x7aa5dfdfU,
   ix830b8888U,
    0xca8c40xddd0x48249595U, 0xe40x7f++B03U, 0xce6767a9 - 1 - i]9d1d168a4a4a4a4bcbcbU, 0x4U, 0xc6c6c279U,
    0xe732d5e7U, 0xc8438bc8U, 0x37596e37U, 0x643434x0a0c0606U, 0x6c47458U, 0x1a1a2e, 0x262 0xd1e57U, 04eU, 0xa9e049a9U,
    0x6cb4d86cU, 0x56faac56U, 0xf407f3f4U, 0xea25cfeaU,
    0x65afca65U, 0x7a8ef47aU, 0xaee947aeU, 03fU, A9U, 0xb5d7d762U, 0x4dababe6b8b8b8bU, 0x8a8a, 0x4dababe6x4b4b4ddU, 0x74747474U, 0xe5e5e5e5U, 0xf1f1f1f1U,
    0x71717171U, 0xd8d8d8d8U, 0x31313131U, 0x1515151b1b1c8U,B+13U, 0x262 0x5757c2c2U, 0xddd 0xdedededeU, 0x5e5eaU,
0x603) 0x5757494U,
B981981U, 0xaee9b3U, ? 64e9U, dd3d3U, 0x+ (8 * (( 0x0d0 0x9a9ab5 - 2) / 29c9c9cU, 0xx686cU, 0x- 1c2c2U, 1f1f1f1fU,
    0x4b4b4b4bU,0xc9e9e9208b8b8bU, 0x8a8a8a8aU,
   =b3b3b3b3fd19 * i))a8U,
  9b9b9bU, 0x1e1e1e1eU, 0x87878787U, 0xe99b02999U, 0x2d7B0909U, 0x83838383U, A7a7a7a7aU, 0xaeaeaeaeU, 0x08080808U,
B 0x3bab6bcbU028U, 0xd0x7fbU, 0xe6e6e65U, 0x2e2e2e2eU3939U, 0x3f3f417eU, 0xf7f702x3bab6bcU, 0x25252525U, 0x2e2e2e2eU,
    0x1c1c1c1cUx3bab6bcb1b1c8U,4U, 0x686U, 00x9a9ab52fU,
   xbfbfbfd2dU, 0x00f0f0fU,
    0xb0b0b0b0U, 0x54545454U, 0xbbbbbbbbU, 0x16161616U,
}
};
a9a9a9a = {
{
    0x51f4a750U, 0x7e416553U, 0x1a17a4c3U, 0x3a275e96U,
    0x3bab6bcbU, 0x1f9d45f1U, 0xacfa58abU, 0x4be30393U,
    0x2030x9696a137U, 0x05ea0e98U, 0x5dfec0e1U,15
};
02U, 0x32323U, 0xc3c3c3c3U,
    0x18181818U, 0x9d7d87faU,
    0xfafa15efU, 0x5959ebb2U, 0x4747c98eUU, 0x3a275e96U,
    0x3bab6bc467b3U, 0xa2a2fd5fU, 0xafafea45U,
    0x4be30393Uf753U, 0x727296e4U, 0xc0c0A0x05050505U, 0x9a9a9a9aU,
    0b1b1c8U,xc843603030U, 0x03020101U0xd970a9d9U, 6c6c6U,
 Bxe1e1d5U, 0x4e4e4e4eU, U, 0xe2e2e2e2U,
   U,
    0x07070707U, 0x12121212U, 0x8082424U
    0xbabad56fU, 0x787888f0U, 0b3b3b3U,
    0x292920x97513360U, 0x62537f45U,
    0xb16477e0U, 0xbb6bae84U, 0xfe81a01cU, 0xf9082b94U,
    0x70486858U, 0x8f45fd19U, 0x94de6c87U, 0x527bf8b7U,
    0xab73d323U, 0x724b0U, 0x2f2f2f2fU,ab2aU,
    0xb2eU, 0x2f2f2f 0x53a46769aU,
 0xec41adadU, 0x67b3d4d4U, 6769aU,
B,
    0x60402020U, 0x1eU, 0x121236C4U, 0x80809b1bU, 0xe2e23ddfU,
    0xebeb26cdU, 0x27276f6f6f6U, 0x0e0e0e0eU,
    0x61616161U, 0x35353535U, 0x57575757U, 0xb9b9b9b9U,
 8U, 0x1a1a2e34U,
    0x1b1b2d36U, 0x6e6eb2dcU, 0x5a5aeeb4U, 0xa0a0fb5bU,
    0x5252f6a4U, 0x3b3b4d76UU, 0x11111111U,
    0x69696969U, 0xd9d9d9d9U, 0x8e8e8e8eU, 0* o8e8e8eU, 0x94949494U,
    0x9b, o0x0b0b0b0nt9e4f4fd195U, U, 0xe5e5e5e5U, 0xf1f1f1f1U,
    0x71717171U, 0xd8d8d8d8U, 0x31313131U, 0x1515151o0x00000000U,o 0xa143435a49U, 0x25ba10xdfdfdfdfU,
    0x8c8c8c8cU, 0xa1a1a1a1U, 0x89898989U, 0x0d0d0d0dU,
 ec0e1U,
    0xc32f7502U, 0x814cf012U, 0x8d4697a3U, 0x6bd3f9c6U,
    0x038f5fe7U, 0x15929c95U, 0xbf0xc920ac66U, 0x, 0xdf7aa5df, 0x   0x63df4a18U, 0xe51a3182U, 0x97513360U, 0x62537f45U,
    0xb16477e0U, 0xbb6bae84U, 0xfe81a01cU, 0xf9082b94U,
    0x70486858U, 0x8f45fd19U, 0x94de6c87U, 0x527bf8b7U,
    0xab73d323U, 0x724b02e2U, 0xe31f8f57U, 0x6655ab2aU,
  0xb2eb2807U, 0x2fb5c203U, 0x86c57b9aU, 0xd33708a5U,
    0x30288, 0x 0x23bfa5b2U, 0x02036abaU, 0xed16825cU,
    0x8acf1c2bU, 0779b492U, 0xf307f2f0U, 0x4e69e2a1U,
    0x65daf4cdU, 0x0605bed5U, 0xd134621fU, 0xc4a6fe8aU,
    0x342e539dU, 0xa2f355a0U, 0x058ae132U, 0xa4f6eb75U,
    0x0b83ec39U, 0x4060efaaU, 0x5e719f06U, 0xbd6e1051U,
    0x3e218aoU, 0x96dd063dU, 0xdd3e0xb2efd52da9U,  0x53a4814cf012U, 0x8d4697a3U, 0x6bd3f9c6U,
    0x038f5fe7U, 0x15929c95U, 0xbf6d7aebU, 0x955259daU,
    0xd4be832dU, 0x587421d3U, 0x49e06929U, 0x8ec9c844U,
    0x75c2896aU, 0xf48e7978U, 0x99583e6bU, 0x2ba0aU, 0xc0a02ae5U, 0x3c22e043    0xbfbfbfbfU, 0xe6e6e6e6U, 0x42424242U, 0x68686868U,
    0x41414141U, 0x99999999U, 0x2d2d2d2dU, 0x0f0f0f0fU,
    0xb0b0b0b0U, 0x54545454U, 0xbbbbbbbbU, 0x16161616U,
}
};

static const word32 Td[5][256] = {
{
    0x51f4a750U, 0x7e416553U, 0x1a17a4c3U, 0x3a275e96U,
    0x3bab6bcbU, 0x1f9d45f1U, 0xacfa58abU, 0x4be30393U,
    0x2030fa55U, 0xad766df6U, 0x88cc7691U, 0xf5024c25U,
    0x4fe5d7fcU, 0xc52acbd7U, 0x26354480U, 0xb562a38fUo 0xc8deb15aec0e1U,
    0xc32f7502U, 0x814cf012U, 0x8d4697a3U, 0x6bd3f9c6U,
    0x038f5fe7U, 0x15929c95U, 0xbf6d7aebU, 0x955259daU,
    0xd4be832dU, 0x587421d3U, 0x49e06929U, 0x8B3bab6bcbU, 0x1f9d45f1U, 0xacfa58abU, 0x4xb968c43eU, 0x27b971ddU,
 Ade6c80e98U, 0x5dfec0e17baU, 0x19195ea0e98U, e6U,
    0x6060a0c0U, 0x81819/* I0xc7c7ba25U, 0check fails, do6363keepxc7c7c 0x808ed3a3a3.dd3d3U, 0x* Unfortunately, you nee5dU, 5c74U, 0xd0b857a3aUc4478U, 0x9f92U,
},
{
   b8461Uvalue  0xad3f9292U6769aU,
xc843, 0xU,
    0x30288ee96d2U, a55UCU, 0xdcdc7fa3U,,
    0x91548db5U, 0x71c45d05U, 0x0406d46fU, 0x605015ffU,
    0x1998fb24Ua0aU, 0x9fU,fU,
    0x0707e4f4fd999b029U, 0x2d2d775aU, 77770f111eU,
    0xb0CAVIUbU, 0nclude <cyassl/ctao9U,
 /logging.h>8d4697U, 0"cavium_common.h"42a2a8d9eiliaze0xc6187dause with Nitrox device32f7U, 0x798d9eC, 0xe 0x7d7d7d7d0xb4devId, 0x562b2x7fbesd4d49fU,
x90909090U, 0x8 -10xadadadadUCspAllocCon5efe(CONTEXT_SSL, &0x522c8adU, Hx7e7e,89U, 0x9d1d16 0xdd27b971U,
    0xb6bee0x5229U, 0 =89U, 0x49deb0x522magic6511a3c2U, U, 0, 0xa_MAGICx49de0e0e121cU,
    0x61/* Fre   0x2drombe83U, 0xd3587421U, 0x2949e4U, 0xc68f45ec9c8U,
    0x6x78f48e79U, 0x6b99583eU, 0xdd27b971U,
 0xadadadadUU, 0x84bb6b!aeU, 0x1cfe81a0U, 0x94f90
    0x07b2eb28U, 0x032Csp3U, 08adU, 0x66c920acU, 0b47dce3aU,
    0x186562537fU,
0x49debU, 0x84bb6bae090eU, 0x91c5cU, 0x79ec9c8Uc9c9U, 0x7d7d7d7dU,
    0xfafafafaU, 0x591U, 0x9U, 0x8e8e8907U, 0x9494a733U,
    0x6969bbdx78f48e79U, 0x6b99583eU, 0xdd27b971U,
    0xb6bee 0x25ba1bx3e427c    0xe1e1gth);x6456c0x70st6464holds909U, ivdd3e05Uix984g0x02020202U,f9f9f9U4d4U,  0x5050505x522type766dU, 129dU, 0x 0x929292c45dU, 0x624406d4U, 0xff605015U,
    0x9c3cU, 0U, 0x97d6bde9U, 0xcd3U,6d4U, 0xff605015U,
    0256fU,
    0x0707U, 0xfIV
    0xvxa6a6a6a6U, 0xdaf4U, 0xd506Cbc279U,
    0xe732d5e7U, 0xc8438bc8U, 0x37596eU, 0x8e8e8907U, 0x9494a733U,
  6869117U, 0d96d 0x562bc66bd3_e4U, offse2U, 0x1 0xefefefefU,queste0b1, 0xdf7aa5dff9f9f9U>eU, 0x1cMAX_16BIT5295c7c7U, 0x65416 slen};

ee96U,)0c0a67U, 0x0f9352036abaU, 04fU, 0279U,
 Aes(a0U, 0x0xce6ING    0x2b8acf1cU, 0x92aa0U, 0xNO_UPDATbU, 0x1e223c1eU,   0x0b0e090dff605015U, 0x9e,0e070U, x0700a0fd9U,
   , 0xc8141eU, 0x8e8e8907U, 0x9494a733Ue070U, 0x3e4reg0xb92db6a  0xf93e21&d19b5b54U0x1d121b17U,
    0x0b0e090dU, 0xa3df4aU, 0x826U,
    0x399190c0a67U,SG("Bad ec9c8U  0x2 0x48d89048 0x81819819U, 0x4f4  0x 0x5899c1c1U, 0x27f9f9f9U-aeU, 0x1c0c0c5U, 0xa261dc20Ua0fd9U,+ 0x7d854a24U, 0xf8d2bb3dU, 0e10U,
    0xf37f609U,
    0x85 -50505U, 0x9a9a9050505U, 0x9a9a9a9aU,
 7888f0U, 05U, 0x2e7U, 0xd2b4ee96U, 0x9e1b9b91U,
  5U, 0xxa261dc20U, 0x695a774bU, 0x161c121aU,
    0x0ae293baU, 0xe5c0a02aU, 0x433c22e0U, 0x1d121b17U,
    0x0b0e090dU, 0xadf28bc7U, 0xb92db6a8U, 0xc8141ea9U,
    0x8557f119U, 0x4caf7507U, 0xbbee99ddU, 0xfda37f60U,
    0x9ff70126U, 0xbc5c72f5U, 0xc544663bU, 0x345bfb7eU,
    0x768b4329U, 0xdccb23c6U, 0x68b6edfcU, 0x63b8e4f1U,
    0xcad731dcU, 0x10426385U, 0x40139722U, 0x2084c6e2fU, 0xf3dcb230U, 0xec0d8652U+11U,
   0xd077c1e3U,
    0x6c2bb316U, 0x99a970b9U, 0 0x0707090eU,00000000U,
    0x830980, 0x80809b1bU, 0xe2e23ddfU,
    0xebeb26cdU,    0xfbfd0effU, 0x560f8538U, 0x1e3daed5U, 0x27362d39a6U, 0xd19b5b54U, 2d39U,
    0x640a0fd9U, 0x210x3a24362eU,
    0xb10c0a67U, 0x0f9357e7U, 0xd2b4ee96U, 0x9e1b9b91U,
    0x4f80c0c5U, 0xa261dc20Ue10U,
    0xftmpa75cec0d8652U,+ 0x9e1U, 0xa8834f9aU,
    0x65e6956eU, 0x7eaa6bee14fU, 0, 0x808 0x161c121aU,
    0x0ae293baU, 0xe5c0a02aU, 0x433c22e0U, 0x1d121b17U,
    0x0b0e090dU, 0xadf28bc7U, 0xb92db6a8U, 0xc8141ea9U,
    0x8557f119U, 0x4caf7507U, 0xbbee99ddU, 0xfda37f60U,
    0x9ff70126U, 0xbc5c72f5U, 0xc544663bU, 0x345bfb7eU,
    0x768b4329U, 0xdccb23c6U, 0x68b6edfcU, 0x63b8e4f1U,0xcfcf4a85U31dcU, 0x10426385U, 0x40139722U, 0x2084c611U,
    0x7d854a24U, 0xf8d2bb3dU, 0x11aef932U, 0x6dc729a1U,
    0x4b1d9e2fU, 0xf3dcb230U,4ccaa4dU, 0x6c2bb316U, 0x99a970b9U, 0xfa119448U, 0x2247e964U,
    0xc4a8fc8cU, 0x1aa0f03fU, 0xd85b0U, 0x54ccaa4dU, 0xdfe49604U,
    0xe39ed1b5U, 0x1b4c6a88U, 0xb8c12c1fU, 0x7f466551U,
    0x049d5eeaU, 0x5d018c35U, 0x73fa8774U, 0x2efb0b41U,
    0x5ab3671dU, 0x5292dbd2U, 0x33e91056U, 0x136dd647U,
    0x8c9ad761U, 0x7a37a10cU, 0x8e59f814U, 0x89eb133cU,
    0xeecea927U, 0x35b761c9U, 0xede11ce5U, 0x3c7a47b1U,
    0x599cd2dfU, 0x3f55f273U, 0x791814ceU, 0xbf73c737U,
    0xea53f7cdU, 0x5b5ffdaaU, 0x14df3d6fU, 0x867844dbU,
    0x81caaff3U,8b283c49U, 0x41ff0d95U,
    0x7139a801U, 0xde080cb3U, 0 0x0707090eU,29U, 0x2d2d775aa0U, 032f753991U, 0x9N    032f75