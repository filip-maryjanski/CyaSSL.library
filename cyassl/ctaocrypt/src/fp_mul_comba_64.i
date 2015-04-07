/* fp_mul_comba_64.i
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


#ifdef TFM_MUL64
void fp_mul_comba64(fp_int *A, fp_int *B, fp_int *C)
{
   fp_digit c0, c1, c2, at[128];

   memcpy(at, A->dp, 64 * sizeof(fp_digit));
   memcpy(at+64, B->dp, 64 * sizeof(fp_digit));
   COMBA_START;

   COMBA_CLEAR;
   /* 0 */
   MULADD(at[0], at[64]); 
   COMBA_STORE(C->dp[0]);
   /* 1 */
   COMBA_FORWARD;
   MULADD(at[0], at[65]);    MULADD(at[1], at[64]); 
   COMBA_STORE(C->dp[1]);
   /* 2 */
   COMBA_FORWARD;
   MULADD(at[0], at[66]);    MULADD(at[1], at[65]);    MULADD(at[2], at[64]); 
   COMBA_STORE(C->dp[2]);
   /* 3 */
   COMBA_FORWARD;
   MULADD(at[0], at[67]);    MULADD(at[1], at[66]);    MULADD(at[2], at[65]);    MULADD(at[3], at[64]); 
   COMBA_STORE(C->dp[3]);
   /* 4 */
   COMBA_FORWARD;
   MULADD(at[0], at[68]);    MULADD(at[1], at[67]);    MULADD(at[2], at[66]);    MULADD(at[3], at[65]);    MULADD(at[4], at[64]); 
   COMBA_STORE(C->dp[4]);
   /* 5 */
   COMBA_FORWARD;
   MULADD(at[0], at[69]);    MULADD(at[1], at[68]);    MULADD(at[2], at[67]);    MULADD(at[3], at[66]);    MULADD(at[4], at[65]);    MULADD(at[5], at[64]); 
   COMBA_STORE(C->dp[5]);
   /* 6 */
   COMBA_FORWARD;
   MULADD(at[0], at[70]);    MULADD(at[1], at[69]);    MULADD(at[2], at[68]);    MULADD(at[3], at[67]);    MULADD(at[4], at[66]);    MULADD(at[5], at[65]);    MULADD(at[6], at[64]); 
   COMBA_STORE(C->dp[6]);
   /* 7 */
   COMBA_FORWARD;
   MULADD(at[0], at[71]);    MULADD(at[1], at[70]);    MULADD(at[2], at[69]);    MULADD(at[3], at[68]);    MULADD(at[4], at[67]);    MULADD(at[5], at[66]);    MULADD(at[6], at[65]);    MULADD(at[7], at[64]); 
   COMBA_STORE(C->dp[7]);
   /* 8 */
   COMBA_FORWARD;
   MULADD(at[0], at[72]);    MULADD(at[1], at[71]);    MULADD(at[2], at[70]);    MULADD(at[3], at[69]);    MULADD(at[4], at[68]);    MULADD(at[5], at[67]);    MULADD(at[6], at[66]);    MULADD(at[7], at[65]);    MULADD(at[8], at[64]); 
   COMBA_STORE(C->dp[8]);
   /* 9 */
   COMBA_FORWARD;
   MULADD(at[0], at[73]);    MULADD(at[1], at[72]);    MULADD(at[2], at[71]);    MULADD(at[3], at[70]);    MULADD(at[4], at[69]);    MULADD(at[5], at[68]);    MULADD(at[6], at[67]);    MULADD(at[7], at[66]);    MULADD(at[8], at[65]);    MULADD(at[9], at[64]); 
   COMBA_STORE(C->dp[9]);
   /* 10 */
   COMBA_FORWARD;
   MULADD(at[0], at[74]);    MULADD(at[1], at[73]);    MULADD(at[2], at[72]);    MULADD(at[3], at[71]);    MULADD(at[4], at[70]);    MULADD(at[5], at[69]);    MULADD(at[6], at[68]);    MULADD(at[7], at[67]);    MULADD(at[8], at[66]);    MULADD(at[9], at[65]);    MULADD(at[10], at[64]); 
   COMBA_STORE(C->dp[10]);
   /* 11 */
   COMBA_FORWARD;
   MULADD(at[0], at[75]);    MULADD(at[1], at[74]);    MULADD(at[2], at[73]);    MULADD(at[3], at[72]);    MULADD(at[4], at[71]);    MULADD(at[5], at[70]);    MULADD(at[6], at[69]);    MULADD(at[7], at[68]);    MULADD(at[8], at[67]);    MULADD(at[9], at[66]);    MULADD(at[10], at[65]);    MULADD(at[11], at[64]); 
   COMBA_STORE(C->dp[11]);
   /* 12 */
   COMBA_FORWARD;
   MULADD(at[0], at[76]);    MULADD(at[1], at[75]);    MULADD(at[2], at[74]);    MULADD(at[3], at[73]);    MULADD(at[4], at[72]);    MULADD(at[5], at[71]);    MULADD(at[6], at[70]);    MULADD(at[7], at[69]);    MULADD(at[8], at[68]);    MULADD(at[9], at[67]);    MULADD(at[10], at[66]);    MULADD(at[11], at[65]);    MULADD(at[12], at[64]); 
   COMBA_STORE(C->dp[12]);
   /* 13 */
   COMBA_FORWARD;
   MULADD(at[0], at[77]);    MULADD(at[1], at[76]);    MULADD(at[2], at[75]);    MULADD(at[3], at[74]);    MULADD(at[4], at[73]);    MULADD(at[5], at[72]);    MULADD(at[6], at[71]);    MULADD(at[7], at[70]);    MULADD(at[8], at[69]);    MULADD(at[9], at[68]);    MULADD(at[10], at[67]);    MULADD(at[11], at[66]);    MULADD(at[12], at[65]);    MULADD(at[13], at[64]); 
   COMBA_STORE(C->dp[13]);
   /* 14 */
   COMBA_FORWARD;
   MULADD(at[0], at[78]);    MULADD(at[1], at[77]);    MULADD(at[2], at[76]);    MULADD(at[3], at[75]);    MULADD(at[4], at[74]);    MULADD(at[5], at[73]);    MULADD(at[6], at[72]);    MULADD(at[7], at[71]);    MULADD(at[8], at[70]);    MULADD(at[9], at[69]);    MULADD(at[10], at[68]);    MULADD(at[11], at[67]);    MULADD(at[12], at[66]);    MULADD(at[13], at[65]);    MULADD(at[14], at[64]); 
   COMBA_STORE(C->dp[14]);
   /* 15 */
   COMBA_FORWARD;
   MULADD(at[0], at[79]);    MULADD(at[1], at[78]);    MULADD(at[2], at[77]);    MULADD(at[3], at[76]);    MULADD(at[4], at[75]);    MULADD(at[5], at[74]);    MULADD(at[6], at[73]);    MULADD(at[7], at[72]);    MULADD(at[8], at[71]);    MULADD(at[9], at[70]);    MULADD(at[10], at[69]);    MULADD(at[11], at[68]);    MULADD(at[12], at[67]);    MULADD(at[13], at[66]);    MULADD(at[14], at[65]);    MULADD(at[15], at[64]); 
   COMBA_STORE(C->dp[15]);
   /* 16 */
   COMBA_FORWARD;
   MULADD(at[0], at[80]);    MULADD(at[1], at[79]);    MULADD(at[2], at[78]);    MULADD(at[3], at[77]);    MULADD(at[4], at[76]);    MULADD(at[5], at[75]);    MULADD(at[6], at[74]);    MULADD(at[7], at[73]);    MULADD(at[8], at[72]);    MULADD(at[9], at[71]);    MULADD(at[10], at[70]);    MULADD(at[11], at[69]);    MULADD(at[12], at[68]);    MULADD(at[13], at[67]);    MULADD(at[14], at[66]);    MULADD(at[15], at[65]);    MULADD(at[16], at[64]); 
   COMBA_STORE(C->dp[16]);
   /* 17 */
   COMBA_FORWARD;
   MULADD(at[0], at[81]);    MULADD(at[1], at[80]);    MULADD(at[2], at[79]);    MULADD(at[3], at[78]);    MULADD(at[4], at[77]);    MULADD(at[5], at[76]);    MULADD(at[6], at[75]);    MULADD(at[7], at[74]);    MULADD(at[8], at[73]);    MULADD(at[9], at[72]);    MULADD(at[10], at[71]);    MULADD(at[11], at[70]);    MULADD(at[12], at[69]);    MULADD(at[13], at[68]);    MULADD(at[14], at[67]);    MULADD(at[15], at[66]);    MULADD(at[16], at[65]);    MULADD(at[17], at[64]); 
   COMBA_STORE(C->dp[17]);
   /* 18 */
   COMBA_FORWARD;
   MULADD(at[0], at[82]);    MULADD(at[1], at[81]);    MULADD(at[2], at[80]);    MULADD(at[3], at[79]);    MULADD(at[4], at[78]);    MULADD(at[5], at[77]);    MULADD(at[6], at[76]);    MULADD(at[7], at[75]);    MULADD(at[8], at[74]);    MULADD(at[9], at[73]);    MULADD(at[10], at[72]);    MULADD(at[11], at[71]);    MULADD(at[12], at[70]);    MULADD(at[13], at[69]);    MULADD(at[14], at[68]);    MULADD(at[15], at[67]);    MULADD(at[16], at[66]);    MULADD(at[17], at[65]);    MULADD(at[18], at[64]); 
   COMBA_STORE(C->dp[18]);
   /* 19 */
   COMBA_FORWARD;
   MULADD(at[0], at[83]);    MULADD(at[1], at[82]);    MULADD(at[2], at[81]);    MULADD(at[3], at[80]);    MULADD(at[4], at[79]);    MULADD(at[5], at[78]);    MULADD(at[6], at[77]);    MULADD(at[7], at[76]);    MULADD(at[8], at[75]);    MULADD(at[9], at[74]);    MULADD(at[10], at[73]);    MULADD(at[11], at[72]);    MULADD(at[12], at[71]);    MULADD(at[13], at[70]);    MULADD(at[14], at[69]);    MULADD(at[15], at[68]);    MULADD(at[16], at[67]);    MULADD(at[17], at[66]);    MULADD(at[18], at[65]);    MULADD(at[19], at[64]); 
   COMBA_STORE(C->dp[19]);
   /* 20 */
   COMBA_FORWARD;
   MULADD(at[0], at[84]);    MULADD(at[1], at[83]);    MULADD(at[2], at[82]);    MULADD(at[3], at[81]);    MULADD(at[4], at[80]);    MULADD(at[5], at[79]);    MULADD(at[6], at[78]);    MULADD(at[7], at[77]);    MULADD(at[8], at[76]);    MULADD(at[9], at[75]);    MULADD(at[10], at[74]);    MULADD(at[11], at[73]);    MULADD(at[12], at[72]);    MULADD(at[13], at[71]);    MULADD(at[14], at[70]);    MULADD(at[15], at[69]);    MULADD(at[16], at[68]);    MULADD(at[17], at[67]);    MULADD(at[18], at[66]);    MULADD(at[19], at[65]);    MULADD(at[20], at[64]); 
   COMBA_STORE(C->dp[20]);
   /* 21 */
   COMBA_FORWARD;
   MULADD(at[0], at[85]);    MULADD(at[1], at[84]);    MULADD(at[2], at[83]);    MULADD(at[3], at[82]);    MULADD(at[4], at[81]);    MULADD(at[5], at[80]);    MULADD(at[6], at[79]);    MULADD(at[7], at[78]);    MULADD(at[8], at[77]);    MULADD(at[9], at[76]);    MULADD(at[10], at[75]);    MULADD(at[11], at[74]);    MULADD(at[12], at[73]);    MULADD(at[13], at[72]);    MULADD(at[14], at[71]);    MULADD(at[15], at[70]);    MULADD(at[16], at[69]);    MULADD(at[17], at[68]);    MULADD(at[18], at[67]);    MULADD(at[19], at[66]);    MULADD(at[20], at[65]);    MULADD(at[21], at[64]); 
   COMBA_STORE(C->dp[21]);
   /* 22 */
   COMBA_FORWARD;
   MULADD(at[0], at[86]);    MULADD(at[1], at[85]);    MULADD(at[2], at[84]);    MULADD(at[3], at[83]);    MULADD(at[4], at[82]);    MULADD(at[5], at[81]);    MULADD(at[6], at[80]);    MULADD(at[7], at[79]);    MULADD(at[8], at[78]);    MULADD(at[9], at[77]);    MULADD(at[10], at[76]);    MULADD(at[11], at[75]);    MULADD(at[12], at[74]);    MULADD(at[13], at[73]);    MULADD(at[14], at[72]);    MULADD(at[15], at[71]);    MULADD(at[16], at[70]);    MULADD(at[17], at[69]);    MULADD(at[18], at[68]);    MULADD(at[19], at[67]);    MULADD(at[20], at[66]);    MULADD(at[21], at[65]);    MULADD(at[22], at[64]); 
   COMBA_STORE(C->dp[22]);
   /* 23 */
   COMBA_FORWARD;
   MULADD(at[0], at[87]);    MULADD(at[1], at[86]);    MULADD(at[2], at[85]);    MULADD(at[3], at[84]);    MULADD(at[4], at[83]);    MULADD(at[5], at[82]);    MULADD(at[6], at[81]);    MULADD(at[7], at[80]);    MULADD(at[8], at[79]);    MULADD(at[9], at[78]);    MULADD(at[10], at[77]);    MULADD(at[11], at[76]);    MULADD(at[12], at[75]);    MULADD(at[13], at[74]);    MULADD(at[14], at[73]);    MULADD(at[15], at[72]);    MULADD(at[16], at[71]);    MULADD(at[17], at[70]);    MULADD(at[18], at[69]);    MULADD(at[19], at[68]);    MULADD(at[20], at[67]);    MULADD(at[21], at[66]);    MULADD(at[22], at[65]);    MULADD(at[23], at[64]); 
   COMBA_STORE(C->dp[23]);
   /* 24 */
   COMBA_FORWARD;
   MULADD(at[0], at[88]);    MULADD(at[1], at[87]);    MULADD(at[2], at[86]);    MULADD(at[3], at[85]);    MULADD(at[4], at[84]);    MULADD(at[5], at[83]);    MULADD(at[6], at[82]);    MULADD(at[7], at[81]);    MULADD(at[8], at[80]);    MULADD(at[9], at[79]);    MULADD(at[10], at[78]);    MULADD(at[11], at[77]);    MULADD(at[12], at[76]);    MULADD(at[13], at[75]);    MULADD(at[14], at[74]);    MULADD(at[15], at[73]);    MULADD(at[16], at[72]);    MULADD(at[17], at[71]);    MULADD(at[18], at[70]);    MULADD(at[19], at[69]);    MULADD(at[20], at[68]);    MULADD(at[21], at[67]);    MULADD(at[22], at[66]);    MULADD(at[23], at[65]);    MULADD(at[24], at[64]); 
   COMBA_STORE(C->dp[24]);
   /* 25 */
   COMBA_FORWARD;
   MULADD(at[0], at[89]);    MULADD(at[1], at[88]);    MULADD(at[2], at[87]);    MULADD(at[3], at[86]);    MULADD(at[4], at[85]);    MULADD(at[5], at[84]);    MULADD(at[6], at[83]);    MULADD(at[7], at[82]);    MULADD(at[8], at[81]);    MULADD(at[9], at[80]);    MULADD(at[10], at[79]);    MULADD(at[11], at[78]);    MULADD(at[12], at[77]);    MULADD(at[13], at[76]);    MULADD(at[14], at[75]);    MULADD(at[15], at[74]);    MULADD(at[16], at[73]);    MULADD(at[17], at[72]);    MULADD(at[18], at[71]);    MULADD(at[19], at[70]);    MULADD(at[20], at[69]);    MULADD(at[21], at[68]);    MULADD(at[22], at[67]);    MULADD(at[23], at[66]);    MULADD(at[24], at[65]);    MULADD(at[25], at[64]); 
   COMBA_STORE(C->dp[25]);
   /* 26 */
   COMBA_FORWARD;
   MULADD(at[0], at[90]);    MULADD(at[1], at[89]);    MULADD(at[2], at[88]);    MULADD(at[3], at[87]);    MULADD(at[4], at[86]);    MULADD(at[5], at[85]);    MULADD(at[6], at[84]);    MULADD(at[7], at[83]);    MULADD(at[8], at[82]);    MULADD(at[9], at[81]);    MULADD(at[10], at[80]);    MULADD(at[11], at[79]);    MULADD(at[12], at[78]);    MULADD(at[13], at[77]);    MULADD(at[14], at[76]);    MULADD(at[15], at[75]);    MULADD(at[16], at[74]);    MULADD(at[17], at[73]);    MULADD(at[18], at[72]);    MULADD(at[19], at[71]);    MULADD(at[20], at[70]);    MULADD(at[21], at[69]);    MULADD(at[22], at[68]);    MULADD(at[23], at[67]);    MULADD(at[24], at[66]);    MULADD(at[25], at[65]);    MULADD(at[26], at[64]); 
   COMBA_STORE(C->dp[26]);
   /* 27 */
   COMBA_FORWARD;
   MULADD(at[0], at[91]);    MULADD(at[1], at[90]);    MULADD(at[2], at[89]);    MULADD(at[3], at[88]);    MULADD(at[4], at[87]);    MULADD(at[5], at[86]);    MULADD(at[6], at[85]);    MULADD(at[7], at[84]);    MULADD(at[8], at[83]);    MULADD(at[9], at[82]);    MULADD(at[10], at[81]);    MULADD(at[11], at[80]);    MULADD(at[12], at[79]);    MULADD(at[13], at[78]);    MULADD(at[14], at[77]);    MULADD(at[15], at[76]);    MULADD(at[16], at[75]);    MULADD(at[17], at[74]);    MULADD(at[18], at[73]);    MULADD(at[19], at[72]);    MULADD(at[20], at[71]);    MULADD(at[21], at[70]);    MULADD(at[22], at[69]);    MULADD(at[23], at[68]);    MULADD(at[24], at[67]);    MULADD(at[25], at[66]);    MULADD(at[26], at[65]);    MULADD(at[27], at[64]); 
   COMBA_STORE(C->dp[27]);
   /* 28 */
   COMBA_FORWARD;
   MULADD(at[0], at[92]);    MULADD(at[1], at[91]);    MULADD(at[2], at[90]);    MULADD(at[3], at[89]);    MULADD(at[4], at[88]);    MULADD(at[5], at[87]);    MULADD(at[6], at[86]);    MULADD(at[7], at[85]);    MULADD(at[8], at[84]);    MULADD(at[9], at[83]);    MULADD(at[10], at[82]);    MULADD(at[11], at[81]);    MULADD(at[12], at[80]);    MULADD(at[13], at[79]);    MULADD(at[14], at[78]);    MULADD(at[15], at[77]);    MULADD(at[16], at[76]);    MULADD(at[17], at[75]);    MULADD(at[18], at[74]);    MULADD(at[19], at[73]);    MULADD(at[20], at[72]);    MULADD(at[21], at[71]);    MULADD(at[22], at[70]);    MULADD(at[23], at[69]);    MULADD(at[24], at[68]);    MULADD(at[25], at[67]);    MULADD(at[26], at[66]);    MULADD(at[27], at[65]);    MULADD(at[28], at[64]); 
   COMBA_STORE(C->dp[28]);
   /* 29 */
   COMBA_FORWARD;
   MULADD(at[0], at[93]);    MULADD(at[1], at[92]);    MULADD(at[2], at[91]);    MULADD(at[3], at[90]);    MULADD(at[4], at[89]);    MULADD(at[5], at[88]);    MULADD(at[6], at[87]);    MULADD(at[7], at[86]);    MULADD(at[8], at[85]);    MULADD(at[9], at[84]);    MULADD(at[10], at[83]);    MULADD(at[11], at[82]);    MULADD(at[12], at[81]);    MULADD(at[13], at[80]);    MULADD(at[14], at[79]);    MULADD(at[15], at[78]);    MULADD(at[16], at[77]);    MULADD(at[17], at[76]);    MULADD(at[18], at[75]);    MULADD(at[19], at[74]);    MULADD(at[20], at[73]);    MULADD(at[21], at[72]);    MULADD(at[22], at[71]);    MULADD(at[23], at[70]);    MULADD(at[24], at[69]);    MULADD(at[25], at[68]);    MULADD(at[26], at[67]);    MULADD(at[27], at[66]);    MULADD(at[28], at[65]);    MULADD(at[29], at[64]); 
   COMBA_STORE(C->dp[29]);
   /* 30 */
   COMBA_FORWARD;
   MULADD(at[0], at[94]);    MULADD(at[1], at[93]);    MULADD(at[2], at[92]);    MULADD(at[3], at[91]);    MULADD(at[4], at[90]);    MULADD(at[5], at[89]);    MULADD(at[6], at[88]);    MULADD(at[7], at[87]);    MULADD(at[8], at[86]);    MULADD(at[9], at[85]);    MULADD(at[10], at[84]);    MULADD(at[11], at[83]);    MULADD(at[12], at[82]);    MULADD(at[13], at[81]);    MULADD(at[14], at[80]);    MULADD(at[15], at[79]);    MULADD(at[16], at[78]);    MULADD(at[17], at[77]);    MULADD(at[18], at[76]);    MULADD(at[19], at[75]);    MULADD(at[20], at[74]);    MULADD(at[21], at[73]);    MULADD(at[22], at[72]);    MULADD(at[23], at[71]);    MULADD(at[24], at[70]);    MULADD(at[25], at[69]);    MULADD(at[26], at[68]);    MULADD(at[27], at[67]);    MULADD(at[28], at[66]);    MULADD(at[29], at[65]);    MULADD(at[30], at[64]); 
   COMBA_STORE(C->dp[30]);
   /* 31 */
   COMBA_FORWARD;
   MULADD(at[0], at[95]);    MULADD(at[1], at[94]);    MULADD(at[2], at[93]);    MULADD(at[3], at[92]);    MULADD(at[4], at[91]);    MULADD(at[5], at[90]);    MULADD(at[6], at[89]);    MULADD(at[7], at[88]);    MULADD(at[8], at[87]);    MULADD(at[9], at[86]);    MULADD(at[10], at[85]);    MULADD(at[11], at[84]);    MULADD(at[12], at[83]);    MULADD(at[13], at[82]);    MULADD(at[14], at[81]);    MULADD(at[15], at[80]);    MULADD(at[16], at[79]);    MULADD(at[17], at[78]);    MULADD(at[18], at[77]);    MULADD(at[19], at[76]);    MULADD(at[20], at[75]);    MULADD(at[21], at[74]);    MULADD(at[22], at[73]);    MULADD(at[23], at[72]);    MULADD(at[24], at[71]);    MULADD(at[25], at[70]);    MULADD(at[26], at[69]);    MULADD(at[27], at[68]);    MULADD(at[28], at[67]);    MULADD(at[29], at[66]);    MULADD(at[30], at[65]);    MULADD(at[31], at[64]); 
   COMBA_STORE(C->dp[31]);
   /* 32 */
   COMBA_FORWARD;
   MULADD(at[0], at[96]);    MULADD(at[1], at[95]);    MULADD(at[2], at[94]);    MULADD(at[3], at[93]);    MULADD(at[4], at[92]);    MULADD(at[5], at[91]);    MULADD(at[6], at[90]);    MULADD(at[7], at[89]);    MULADD(at[8], at[88]);    MULADD(at[9], at[87]);    MULADD(at[10], at[86]);    MULADD(at[11], at[85]);    MULADD(at[12], at[84]);    MULADD(at[13], at[83]);    MULADD(at[14], at[82]);    MULADD(at[15], at[81]);    MULADD(at[16], at[80]);    MULADD(at[17], at[79]);    MULADD(at[18], at[78]);    MULADD(at[19], at[77]);    MULADD(at[20], at[76]);    MULADD(at[21], at[75]);    MULADD(at[22], at[74]);    MULADD(at[23], at[73]);    MULADD(at[24], at[72]);    MULADD(at[25], at[71]);    MULADD(at[26], at[70]);    MULADD(at[27], at[69]);    MULADD(at[28], at[68]);    MULADD(at[29], at[67]);    MULADD(at[30], at[66]);    MULADD(at[31], at[65]);    MULADD(at[32], at[64]); 
   COMBA_STORE(C->dp[32]);
   /* 33 */
   COMBA_FORWARD;
   MULADD(at[0], at[97]);    MULADD(at[1], at[96]);    MULADD(at[2], at[95]);    MULADD(at[3], at[94]);    MULADD(at[4], at[93]);    MULADD(at[5], at[92]);    MULADD(at[6], at[91]);    MULADD(at[7], at[90]);    MULADD(at[8], at[89]);    MULADD(at[9], at[88]);    MULADD(at[10], at[87]);    MULADD(at[11], at[86]);    MULADD(at[12], at[85]);    MULADD(at[13], at[84]);    MULADD(at[14], at[83]);    MULADD(at[15], at[82]);    MULADD(at[16], at[81]);    MULADD(at[17], at[80]);    MULADD(at[18], at[79]);    MULADD(at[19], at[78]);    MULADD(at[20], at[77]);    MULADD(at[21], at[76]);    MULADD(at[22], at[75]);    MULADD(at[23], at[74]);    MULADD(at[24], at[73]);    MULADD(at[25], at[72]);    MULADD(at[26], at[71]);    MULADD(at[27], at[70]);    MULADD(at[28], at[69]);    MULADD(at[29], at[68]);    MULADD(at[30], at[67]);    MULADD(at[31], at[66]);    MULADD(at[32], at[65]);    MULADD(at[33], at[64]); 
   COMBA_STORE(C->dp[33]);
   /* 34 */
   COMBA_FORWARD;
   MULADD(at[0], at[98]);    MULADD(at[1], at[97]);    MULADD(at[2], at[96]);    MULADD(at[3], at[95]);    MULADD(at[4], at[94]);    MULADD(at[5], at[93]);    MULADD(at[6], at[92]);    MULADD(at[7], at[91]);    MULADD(at[8], at[90]);    MULADD(at[9], at[89]);    MULADD(at[10], at[88]);    MULADD(at[11], at[87]);    MULADD(at[12], at[86]);    MULADD(at[13], at[85]);    MULADD(at[14], at[84]);    MULADD(at[15], at[83]);    MULADD(at[16], at[82]);    MULADD(at[17], at[81]);    MULADD(at[18], at[80]);    MULADD(at[19], at[79]);    MULADD(at[20], at[78]);    MULADD(at[21], at[77]);    MULADD(at[22], at[76]);    MULADD(at[23], at[75]);    MULADD(at[24], at[74]);    MULADD(at[25], at[73]);    MULADD(at[26], at[72]);    MULADD(at[27], at[71]);    MULADD(at[28], at[70]);    MULADD(at[29], at[69]);    MULADD(at[30], at[68]);    MULADD(at[31], at[67]);    MULADD(at[32], at[66]);    MULADD(at[33], at[65]);    MULADD(at[34], at[64]); 
   COMBA_STORE(C->dp[34]);
   /* 35 */
   COMBA_FORWARD;
   MULADD(at[0], at[99]);    MULADD(at[1], at[98]);    MULADD(at[2], at[97]);    MULADD(at[3], at[96]);    MULADD(at[4], at[95]);    MULADD(at[5], at[94]);    MULADD(at[6], at[93]);    MULADD(at[7], at[92]);    MULADD(at[8], at[91]);    MULADD(at[9], at[90]);    MULADD(at[10], at[89]);    MULADD(at[11], at[88]);    MULADD(at[12], at[87]);    MULADD(at[13], at[86]);    MULADD(at[14], at[85]);    MULADD(at[15], at[84]);    MULADD(at[16], at[83]);    MULADD(at[17], at[82]);    MULADD(at[18], at[81]);    MULADD(at[19], at[80]);    MULADD(at[20], at[79]);    MULADD(at[21], at[78]);    MULADD(at[22], at[77]);    MULADD(at[23], at[76]);    MULADD(at[24], at[75]);    MULADD(at[25], at[74]);    MULADD(at[26], at[73]);    MULADD(at[27], at[72]);    MULADD(at[28], at[71]);    MULADD(at[29], at[70]);    MULADD(at[30], at[69]);    MULADD(at[31], at[68]);    MULADD(at[32], at[67]);    MULADD(at[33], at[66]);    MULADD(at[34], at[65]);    MULADD(at[35], at[64]); 
   COMBA_STORE(C->dp[35]);
   /* 36 */
   COMBA_FORWARD;
   MULADD(at[0], at[100]);    MULADD(at[1], at[99]);    MULADD(at[2], at[98]);    MULADD(at[3], at[97]);    MULADD(at[4], at[96]);    MULADD(at[5], at[95]);    MULADD(at[6], at[94]);    MULADD(at[7], at[93]);    MULADD(at[8], at[92]);    MULADD(at[9], at[91]);    MULADD(at[10], at[90]);    MULADD(at[11], at[89]);    MULADD(at[12], at[88]);    MULADD(at[13], at[87]);    MULADD(at[14], at[86]);    MULADD(at[15], at[85]);    MULADD(at[16], at[84]);    MULADD(at[17], at[83]);    MULADD(at[18], at[82]);    MULADD(at[19], at[81]);    MULADD(at[20], at[80]);    MULADD(at[21], at[79]);    MULADD(at[22], at[78]);    MULADD(at[23], at[77]);    MULADD(at[24], at[76]);    MULADD(at[25], at[75]);    MULADD(at[26], at[74]);    MULADD(at[27], at[73]);    MULADD(at[28], at[72]);    MULADD(at[29], at[71]);    MULADD(at[30], at[70]);    MULADD(at[31], at[69]);    MULADD(at[32], at[68]);    MULADD(at[33], at[67]);    MULADD(at[34], at[66]);    MULADD(at[35], at[65]);    MULADD(at[36], at[64]); 
   COMBA_STORE(C->dp[36]);
   /* 37 */
   COMBA_FORWARD;
   MULADD(at[0], at[101]);    MULADD(at[1], at[100]);    MULADD(at[2], at[99]);    MULADD(at[3], at[98]);    MULADD(at[4], at[97]);    MULADD(at[5], at[96]);    MULADD(at[6], at[95]);    MULADD(at[7], at[94]);    MULADD(at[8], at[93]);    MULADD(at[9], at[92]);    MULADD(at[10], at[91]);    MULADD(at[11], at[90]);    MULADD(at[12], at[89]);    MULADD(at[13], at[88]);    MULADD(at[14], at[87]);    MULADD(at[15], at[86]);    MULADD(at[16], at[85]);    MULADD(at[17], at[84]);    MULADD(at[18], at[83]);    MULADD(at[19], at[82]);    MULADD(at[20], at[81]);    MULADD(at[21], at[80]);    MULADD(at[22], at[79]);    MULADD(at[23], at[78]);    MULADD(at[24], at[77]);    MULADD(at[25], at[76]);    MULADD(at[26], at[75]);    MULADD(at[27], at[74]);    MULADD(at[28], at[73]);    MULADD(at[29], at[72]);    MULADD(at[30], at[71]);    MULADD(at[31], at[70]);    MULADD(at[32], at[69]);    MULADD(at[33], at[68]);    MULADD(at[34], at[67]);    MULADD(at[35], at[66]);    MULADD(at[36], at[65]);    MULADD(at[37], at[64]); 
   COMBA_STORE(C->dp[37]);
   /* 38 */
   COMBA_FORWARD;
   MULADD(at[0], at[102]);    MULADD(at[1], at[101]);    MULADD(at[2], at[100]);    MULADD(at[3], at[99]);    MULADD(at[4], at[98]);    MULADD(at[5], at[97]);    MULADD(at[6], at[96]);    MULADD(at[7], at[95]);    MULADD(at[8], at[94]);    MULADD(at[9], at[93]);    MULADD(at[10], at[92]);    MULADD(at[11], at[91]);    MULADD(at[12], at[90]);    MULADD(at[13], at[89]);    MULADD(at[14], at[88]);    MULADD(at[15], at[87]);    MULADD(at[16], at[86]);    MULADD(at[17], at[85]);    MULADD(at[18], at[84]);    MULADD(at[19], at[83]);    MULADD(at[20], at[82]);    MULADD(at[21], at[81]);    MULADD(at[22], at[80]);    MULADD(at[23], at[79]);    MULADD(at[24], at[78]);    MULADD(at[25], at[77]);    MULADD(at[26], at[76]);    MULADD(at[27], at[75]);    MULADD(at[28], at[74]);    MULADD(at[29], at[73]);    MULADD(at[30], at[72]);    MULADD(at[31], at[71]);    MULADD(at[32], at[70]);    MULADD(at[33], at[69]);    MULADD(at[34], at[68]);    MULADD(at[35], at[67]);    MULADD(at[36], at[66]);    MULADD(at[37], at[65]);    MULADD(at[38], at[64]); 
   COMBA_STORE(C->dp[38]);
   /* 39 */
   COMBA_FORWARD;
   MULADD(at[0], at[103]);    MULADD(at[1], at[102]);    MULADD(at[2], at[101]);    MULADD(at[3], at[100]);    MULADD(at[4], at[99]);    MULADD(at[5], at[98]);    MULADD(at[6], at[97]);    MULADD(at[7], at[96]);    MULADD(at[8], at[95]);    MULADD(at[9], at[94]);    MULADD(at[10], at[93]);    MULADD(at[11], at[92]);    MULADD(at[12], at[91]);    MULADD(at[13], at[90]);    MULADD(at[14], at[89]);    MULADD(at[15], at[88]);    MULADD(at[16], at[87]);    MULADD(at[17], at[86]);    MULADD(at[18], at[85]);    MULADD(at[19], at[84]);    MULADD(at[20], at[83]);    MULADD(at[21], at[82]);    MULADD(at[22], at[81]);    MULADD(at[23], at[80]);    MULADD(at[24], at[79]);    MULADD(at[25], at[78]);    MULADD(at[26], at[77]);    MULADD(at[27], at[76]);    MULADD(at[28], at[75]);    MULADD(at[29], at[74]);    MULADD(at[30], at[73]);    MULADD(at[31], at[72]);    MULADD(at[32], at[71]);    MULADD(at[33], at[70]);    MULADD(at[34], at[69]);    MULADD(at[35], at[68]);    MULADD(at[36], at[67]);    MULADD(at[37], at[66]);    MULADD(at[38], at[65]);    MULADD(at[39], at[64]); 
   COMBA_STORE(C->dp[39]);
   /* 40 */
   COMBA_FORWARD;
   MULADD(at[0], at[104]);    MULADD(at[1], at[103]);    MULADD(at[2], at[102]);    MULADD(at[3], at[101]);    MULADD(at[4], at[100]);    MULADD(at[5], at[99]);    MULADD(at[6], at[98]);    MULADD(at[7], at[97]);    MULADD(at[8], at[96]);    MULADD(at[9], at[95]);    MULADD(at[10], at[94]);    MULADD(at[11], at[93]);    MULADD(at[12], at[92]);    MULADD(at[13], at[91]);    MULADD(at[14], at[90]);    MULADD(at[15], at[89]);    MULADD(at[16], at[88]);    MULADD(at[17], at[87]);    MULADD(at[18], at[86]);    MULADD(at[19], at[85]);    MULADD(at[20], at[84]);    MULADD(at[21], at[83]);    MULADD(at[22], at[82]);    MULADD(at[23], at[81]);    MULADD(at[24], at[80]);    MULADD(at[25], at[79]);    MULADD(at[26], at[78]);    MULADD(at[27], at[77]);    MULADD(at[28], at[76]);    MULADD(at[29], at[75]);    MULADD(at[30], at[74]);    MULADD(at[31], at[73]);    MULADD(at[32], at[72]);    MULADD(at[33], at[71]);    MULADD(at[34], at[70]);    MULADD(at[35], at[69]);    MULADD(at[36], at[68]);    MULADD(at[37], at[67]);    MULADD(at[38], at[66]);    MULADD(at[39], at[65]);    MULADD(at[40], at[64]); 
   COMBA_STORE(C->dp[40]);
   /* 41 */
   COMBA_FORWARD;
   MULADD(at[0], at[105]);    MULADD(at[1], at[104]);    MULADD(at[2], at[103]);    MULADD(at[3], at[102]);    MULADD(at[4], at[101]);    MULADD(at[5], at[100]);    MULADD(at[6], at[99]);    MULADD(at[7], at[98]);    MULADD(at[8], at[97]);    MULADD(at[9], at[96]);    MULADD(at[10], at[95]);    MULADD(at[11], at[94]);    MULADD(at[12], at[93]);    MULADD(at[13], at[92]);    MULADD(at[14], at[91]);    MULADD(at[15], at[90]);    MULADD(at[16], at[89]);    MULADD(at[17], at[88]);    MULADD(at[18], at[87]);    MULADD(at[19], at[86]);    MULADD(at[20], at[85]);    MULADD(at[21], at[84]);    MULADD(at[22], at[83]);    MULADD(at[23], at[82]);    MULADD(at[24], at[81]);    MULADD(at[25], at[80]);    MULADD(at[26], at[79]);    MULADD(at[27], at[78]);    MULADD(at[28], at[77]);    MULADD(at[29], at[76]);    MULADD(at[30], at[75]);    MULADD(at[31], at[74]);    MULADD(at[32], at[73]);    MULADD(at[33], at[72]);    MULADD(at[34], at[71]);    MULADD(at[35], at[70]);    MULADD(at[36], at[69]);    MULADD(at[37], at[68]);    MULADD(at[38], at[67]);    MULADD(at[39], at[66]);    MULADD(at[40], at[65]);    MULADD(at[41], at[64]); 
   COMBA_STORE(C->dp[41]);
   /* 42 */
   COMBA_FORWARD;
   MULADD(at[0], at[106]);    MULADD(at[1], at[105]);    MULADD(at[2], at[104]);    MULADD(at[3], at[103]);    MULADD(at[4], at[102]);    MULADD(at[5], at[101]);    MULADD(at[6], at[100]);    MULADD(at[7], at[99]);    MULADD(at[8], at[98]);    MULADD(at[9], at[97]);    MULADD(at[10], at[96]);    MULADD(at[11], at[95]);    MULADD(at[12], at[94]);    MULADD(at[13], at[93]);    MULADD(at[14], at[92]);    MULADD(at[15], at[91]);    MULADD(at[16], at[90]);    MULADD(at[17], at[89]);    MULADD(at[18], at[88]);    MULADD(at[19], at[87]);    MULADD(at[20], at[86]);    MULADD(at[21], at[85]);    MULADD(at[22], at[84]);    MULADD(at[23], at[83]);    MULADD(at[24], at[82]);    MULADD(at[25], at[81]);    MULADD(at[26], at[80]);    MULADD(at[27], at[79]);    MULADD(at[28], at[78]);    MULADD(at[29], at[77]);    MULADD(at[30], at[76]);    MULADD(at[31], at[75]);    MULADD(at[32], at[74]);    MULADD(at[33], at[73]);    MULADD(at[34], at[72]);    MULADD(at[35], at[71]);    MULADD(at[36], at[70]);    MULADD(at[37], at[69]);    MULADD(at[38], at[68]);    MULADD(at[39], at[67]);    MULADD(at[40], at[66]);    MULADD(at[41], at[65]);    MULADD(at[42], at[64]); 
   COMBA_STORE(C->dp[42]);
   /* 43 */
   COMBA_FORWARD;
   MULADD(at[0], at[107]);    MULADD(at[1], at[106]);    MULADD(at[2], at[105]);    MULADD(at[3], at[104]);    MULADD(at[4], at[103]);    MULADD(at[5], at[102]);    MULADD(at[6], at[101]);    MULADD(at[7], at[100]);    MULADD(at[8], at[99]);    MULADD(at[9], at[98]);    MULADD(at[10], at[97]);    MULADD(at[11], at[96]);    MULADD(at[12], at[95]);    MULADD(at[13], at[94]);    MULADD(at[14], at[93]);    MULADD(at[15], at[92]);    MULADD(at[16], at[91]);    MULADD(at[17], at[90]);    MULADD(at[18], at[89]);    MULADD(at[19], at[88]);    MULADD(at[20], at[87]);    MULADD(at[21], at[86]);    MULADD(at[22], at[85]);    MULADD(at[23], at[84]);    MULADD(at[24], at[83]);    MULADD(at[25], at[82]);    MULADD(at[26], at[81]);    MULADD(at[27], at[80]);    MULADD(at[28], at[79]);    MULADD(at[29], at[78]);    MULADD(at[30], at[77]);    MULADD(at[31], at[76]);    MULADD(at[32], at[75]);    MULADD(at[33], at[74]);    MULADD(at[34], at[73]);    MULADD(at[35], at[72]);    MULADD(at[36], at[71]);    MULADD(at[37], at[70]);    MULADD(at[38], at[69]);    MULADD(at[39], at[68]);    MULADD(at[40], at[67]);    MULADD(at[41], at[66]);    MULADD(at[42], at[65]);    MULADD(at[43], at[64]); 
   COMBA_STORE(C->dp[43]);
   /* 44 */
   COMBA_FORWARD;
   MULADD(at[0], at[108]);    MULADD(at[1], at[107]);    MULADD(at[2], at[106]);    MULADD(at[3], at[105]);    MULADD(at[4], at[104]);    MULADD(at[5], at[103]);    MULADD(at[6], at[102]);    MULADD(at[7], at[101]);    MULADD(at[8], at[100]);    MULADD(at[9], at[99]);    MULADD(at[10], at[98]);    MULADD(at[11], at[97]);    MULADD(at[12], at[96]);    MULADD(at[13], at[95]);    MULADD(at[14], at[94]);    MULADD(at[15], at[93]);    MULADD(at[16], at[92]);    MULADD(at[17], at[91]);    MULADD(at[18], at[90]);    MULADD(at[19], at[89]);    MULADD(at[20], at[88]);    MULADD(at[21], at[87]);    MULADD(at[22], at[86]);    MULADD(at[23], at[85]);    MULADD(at[24], at[84]);    MULADD(at[25], at[83]);    MULADD(at[26], at[82]);    MULADD(at[27], at[81]);    MULADD(at[28], at[80]);    MULADD(at[29], at[79]);    MULADD(at[30], at[78]);    MULADD(at[31], at[77]);    MULADD(at[32], at[76]);    MULADD(at[33], at[75]);    MULADD(at[34], at[74]);    MULADD(at[35], at[73]);    MULADD(at[36], at[72]);    MULADD(at[37], at[71]);    MULADD(at[38], at[70]);    MULADD(at[39], at[69]);    MULADD(at[40], at[68]);    MULADD(at[41], at[67]);    MULADD(at[42], at[66]);    MULADD(at[43], at[65]);    MULADD(at[44], at[64]); 
   COMBA_STORE(C->dp[44]);
   /* 45 */
   COMBA_FORWARD;
   MULADD(at[0], at[109]);    MULADD(at[1], at[108]);    MULADD(at[2], at[107]);    MULADD(at[3], at[106]);    MULADD(at[4], at[105]);    MULADD(at[5], at[104]);    MULADD(at[6], at[103]);    MULADD(at[7], at[102]);    MULADD(at[8], at[101]);    MULADD(at[9], at[100]);    MULADD(at[10], at[99]);    MULADD(at[11], at[98]);    MULADD(at[12], at[97]);    MULADD(at[13], at[96]);    MULADD(at[14], at[95]);    MULADD(at[15], at[94]);    MULADD(at[16], at[93]);    MULADD(at[17], at[92]);    MULADD(at[18], at[91]);    MULADD(at[19], at[90]);    MULADD(at[20], at[89]);    MULADD(at[21], at[88]);    MULADD(at[22], at[87]);    MULADD(at[23], at[86]);    MULADD(at[24], at[85]);    MULADD(at[25], at[84]);    MULADD(at[26], at[83]);    MULADD(at[27], at[82]);    MULADD(at[28], at[81]);    MULADD(at[29], at[80]);    MULADD(at[30], at[79]);    MULADD(at[31], at[78]);    MULADD(at[32], at[77]);    MULADD(at[33], at[76]);    MULADD(at[34], at[75]);    MULADD(at[35], at[74]);    MULADD(at[36], at[73]);    MULADD(at[37], at[72]);    MULADD(at[38], at[71]);    MULADD(at[39], at[70]);    MULADD(at[40], at[69]);    MULADD(at[41], at[68]);    MULADD(at[42], at[67]);    MULADD(at[43], at[66]);    MULADD(at[44], at[65]);    MULADD(at[45], at[64]); 
   COMBA_STORE(C->dp[45]);
   /* 46 */
   COMBA_FORWARD;
   MULADD(at[0], at[110]);    MULADD(at[1], at[109]);    MULADD(at[2], at[108]);    MULADD(at[3], at[107]);    MULADD(at[4], at[106]);    MULADD(at[5], at[105]);    MULADD(at[6], at[104]);    MULADD(at[7], at[103]);    MULADD(at[8], at[102]);    MULADD(at[9], at[101]);    MULADD(at[10], at[100]);    MULADD(at[11], at[99]);    MULADD(at[12], at[98]);    MULADD(at[13], at[97]);    MULADD(at[14], at[96]);    MULADD(at[15], at[95]);    MULADD(at[16], at[94]);    MULADD(at[17], at[93]);    MULADD(at[18], at[92]);    MULADD(at[19], at[91]);    MULADD(at[20], at[90]);    MULADD(at[21], at[89]);    MULADD(at[22], at[88]);    MULADD(at[23], at[87]);    MULADD(at[24], at[86]);    MULADD(at[25], at[85]);    MULADD(at[26], at[84]);    MULADD(at[27], at[83]);    MULADD(at[28], at[82]);    MULADD(at[29], at[81]);    MULADD(at[30], at[80]);    MULADD(at[31], at[79]);    MULADD(at[32], at[78]);    MULADD(at[33], at[77]);    MULADD(at[34], at[76]);    MULADD(at[35], at[75]);    MULADD(at[36], at[74]);    MULADD(at[37], at[73]);    MULADD(at[38], at[72]);    MULADD(at[39], at[71]);    MULADD(at[40], at[70]);    MULADD(at[41], at[69]);    MULADD(at[42], at[68]);    MULADD(at[43], at[67]);    MULADD(at[44], at[66]);    MULADD(at[45], at[65]);    MULADD(at[46], at[64]); 
   COMBA_STORE(C->dp[46]);
   /* 47 */
   COMBA_FORWARD;
   MULADD(at[0], at[111]);    MULADD(at[1], at[110]);    MULADD(at[2], at[109]);    MULADD(at[3], at[108]);    MULADD(at[4], at[107]);    MULADD(at[5], at[106]);    MULADD(at[6], at[105]);    MULADD(at[7], at[104]);    MULADD(at[8], at[103]);    MULADD(at[9], at[102]);    MULADD(at[10], at[101]);    MULADD(at[11], at[100]);    MULADD(at[12], at[99]);    MULADD(at[13], at[98]);    MULADD(at[14], at[97]);    MULADD(at[15], at[96]);    MULADD(at[16], at[95]);    MULADD(at[17], at[94]);    MULADD(at[18], at[93]);    MULADD(at[19], at[92]);    MULADD(at[20], at[91]);    MULADD(at[21], at[90]);    MULADD(at[22], at[89]);    MULADD(at[23], at[88]);    MULADD(at[24], at[87]);    MULADD(at[25], at[86]);    MULADD(at[26], at[85]);    MULADD(at[27], at[84]);    MULADD(at[28], at[83]);    MULADD(at[29], at[82]);    MULADD(at[30], at[81]);    MULADD(at[31], at[80]);    MULADD(at[32], at[79]);    MULADD(at[33], at[78]);    MULADD(at[34], at[77]);    MULADD(at[35], at[76]);    MULADD(at[36], at[75]);    MULADD(at[37], at[74]);    MULADD(at[38], at[73]);    MULADD(at[39], at[72]);    MULADD(at[40], at[71]);    MULADD(at[41], at[70]);    MULADD(at[42], at[69]);    MULADD(at[43], at[68]);    MULADD(at[44], at[67]);    MULADD(at[45], at[66]);    MULADD(at[46], at[65]);    MULADD(at[47], at[64]); 
   COMBA_STORE(C->dp[47]);
   /* 48 */
   COMBA_FORWARD;
   MULADD(at[0], at[112]);    MULADD(at[1], at[111]);    MULADD(at[2], at[110]);    MULADD(at[3], at[109]);    MULADD(at[4], at[108]);    MULADD(at[5], at[107]);    MULADD(at[6], at[106]);    MULADD(at[7], at[105]);    MULADD(at[8], at[104]);    MULADD(at[9], at[103]);    MULADD(at[10], at[102]);    MULADD(at[11], at[101]);    MULADD(at[12], at[100]);    MULADD(at[13], at[99]);    MULADD(at[14], at[98]);    MULADD(at[15], at[97]);    MULADD(at[16], at[96]);    MULADD(at[17], at[95]);    MULADD(at[18], at[94]);    MULADD(at[19], at[93]);    MULADD(at[20], at[92]);    MULADD(at[21], at[91]);    MULADD(at[22], at[90]);    MULADD(at[23], at[89]);    MULADD(at[24], at[88]);    MULADD(at[25], at[87]);    MULADD(at[26], at[86]);    MULADD(at[27], at[85]);    MULADD(at[28], at[84]);    MULADD(at[29], at[83]);    MULADD(at[30], at[82]);    MULADD(at[31], at[81]);    MULADD(at[32], at[80]);    MULADD(at[33], at[79]);    MULADD(at[34], at[78]);    MULADD(at[35], at[77]);    MULADD(at[36], at[76]);    MULADD(at[37], at[75]);    MULADD(at[38], at[74]);    MULADD(at[39], at[73]);    MULADD(at[40], at[72]);    MULADD(at[41], at[71]);    MULADD(at[42], at[70]);    MULADD(at[43], at[69]);    MULADD(at[44], at[68]);    MULADD(at[45], at[67]);    MULADD(at[46], at[66]);    MULADD(at[47], at[65]);    MULADD(at[48], at[64]); 
   COMBA_STORE(C->dp[48]);
   /* 49 */
   COMBA_FORWARD;
   MULADD(at[0], at[113]);    MULADD(at[1], at[112]);    MULADD(at[2], at[111]);    MULADD(at[3], at[110]);    MULADD(at[4], at[109]);    MULADD(at[5], at[108]);    MULADD(at[6], at[107]);    MULADD(at[7], at[106]);    MULADD(at[8], at[105]);    MULADD(at[9], at[104]);    MULADD(at[10], at[103]);    MULADD(at[11], at[102]);    MULADD(at[12], at[101]);    MULADD(at[13], at[100]);    MULADD(at[14], at[99]);    MULADD(at[15], at[98]);    MULADD(at[16], at[97]);    MULADD(at[17], at[96]);    MULADD(at[18], at[95]);    MULADD(at[19], at[94]);    MULADD(at[20], at[93]);    MULADD(at[21], at[92]);    MULADD(at[22], at[91]);    MULADD(at[23], at[90]);    MULADD(at[24], at[89]);    MULADD(at[25], at[88]);    MULADD(at[26], at[87]);    MULADD(at[27], at[86]);    MULADD(at[28], at[85]);    MULADD(at[29], at[84]);    MULADD(at[30], at[83]);    MULADD(at[31], at[82]);    MULADD(at[32], at[81]);    MULADD(at[33], at[80]);    MULADD(at[34], at[79]);    MULADD(at[35], at[78]);    MULADD(at[36], at[77]);    MULADD(at[37], at[76]);    MULADD(at[38], at[75]);    MULADD(at[39], at[74]);    MULADD(at[40], at[73]);    MULADD(at[41], at[72]);    MULADD(at[42], at[71]);    MULADD(at[43], at[70]);    MULADD(at[44], at[69]);    MULADD(at[45], at[68]);    MULADD(at[46], at[67]);    MULADD(at[47], at[66]);    MULADD(at[48], at[65]);    MULADD(at[49], at[64]); 
   COMBA_STORE(C->dp[49]);
   /* 50 */
   COMBA_FORWARD;
   MULADD(at[0], at[114]);    MULADD(at[1], at[113]);    MULADD(at[2], at[112]);    MULADD(at[3], at[111]);    MULADD(at[4], at[110]);    MULADD(at[5], at[109]);    MULADD(at[6], at[108]);    MULADD(at[7], at[107]);    MULADD(at[8], at[106]);    MULADD(at[9], at[105]);    MULADD(at[10], at[104]);    MULADD(at[11], at[103]);    MULADD(at[12], at[102]);    MULADD(at[13], at[101]);    MULADD(at[14], at[100]);    MULADD(at[15], at[99]);    MULADD(at[16], at[98]);    MULADD(at[17], at[97]);    MULADD(at[18], at[96]);    MULADD(at[19], at[95]);    MULADD(at[20], at[94]);    MULADD(at[21], at[93]);    MULADD(at[22], at[92]);    MULADD(at[23], at[91]);    MULADD(at[24], at[90]);    MULADD(at[25], at[89]);    MULADD(at[26], at[88]);    MULADD(at[27], at[87]);    MULADD(at[28], at[86]);    MULADD(at[29], at[85]);    MULADD(at[30], at[84]);    MULADD(at[31], at[83]);    MULADD(at[32], at[82]);    MULADD(at[33], at[81]);    MULADD(at[34], at[80]);    MULADD(at[35], at[79]);    MULADD(at[36], at[78]);    MULADD(at[37], at[77]);    MULADD(at[38], at[76]);    MULADD(at[39], at[75]);    MULADD(at[40], at[74]);    MULADD(at[41], at[73]);    MULADD(at[42], at[72]);    MULADD(at[43], at[71]);    MULADD(at[44], at[70]);    MULADD(at[45], at[69]);    MULADD(at[46], at[68]);    MULADD(at[47], at[67]);    MULADD(at[48], at[66]);    MULADD(at[49], at[65]);    MULADD(at[50], at[64]); 
   COMBA_STORE(C->dp[50]);
   /* 51 */
   COMBA_FORWARD;
   MULADD(at[0], at[115]);    MULADD(at[1], at[114]);    MULADD(at[2], at[113]);    MULADD(at[3], at[112]);    MULADD(at[4], at[111]);    MULADD(at[5], at[110]);    MULADD(at[6], at[109]);    MULADD(at[7], at[108]);    MULADD(at[8], at[107]);    MULADD(at[9], at[106]);    MULADD(at[10], at[105]);    MULADD(at[11], at[104]);    MULADD(at[12], at[103]);    MULADD(at[13], at[102]);    MULADD(at[14], at[101]);    MULADD(at[15], at[100]);    MULADD(at[16], at[99]);    MULADD(at[17], at[98]);    MULADD(at[18], at[97]);    MULADD(at[19], at[96]);    MULADD(at[20], at[95]);    MULADD(at[21], at[94]);    MULADD(at[22], at[93]);    MULADD(at[23], at[92]);    MULADD(at[24], at[91]);    MULADD(at[25], at[90]);    MULADD(at[26], at[89]);    MULADD(at[27], at[88]);    MULADD(at[28], at[87]);    MULADD(at[29], at[86]);    MULADD(at[30], at[85]);    MULADD(at[31], at[84]);    MULADD(at[32], at[83]);    MULADD(at[33], at[82]);    MULADD(at[34], at[81]);    MULADD(at[35], at[80]);    MULADD(at[36], at[79]);    MULADD(at[37], at[78]);    MULADD(at[38], at[77]);    MULADD(at[39], at[76]);    MULADD(at[40], at[75]);    MULADD(at[41], at[74]);    MULADD(at[42], at[73]);    MULADD(at[43], at[72]);    MULADD(at[44], at[71]);    MULADD(at[45], at[70]);    MULADD(at[46], at[69]);    MULADD(at[47], at[68]);    MULADD(at[48], at[67]);    MULADD(at[49], at[66]);    MULADD(at[50], at[65]);    MULADD(at[51], at[64]); 
   COMBA_STORE(C->dp[51]);
   /* 52 */
   COMBA_FORWARD;
   MULADD(at[0], at[116]);    MULADD(at[1], at[115]);    MULADD(at[2], at[114]);    MULADD(at[3], at[113]);    MULADD(at[4], at[112]);    MULADD(at[5], at[111]);    MULADD(at[6], at[110]);    MULADD(at[7], at[109]);    MULADD(at[8], at[108]);    MULADD(at[9], at[107]);    MULADD(at[10], at[106]);    MULADD(at[11], at[105]);    MULADD(at[12], at[104]);    MULADD(at[13], at[103]);    MULADD(at[14], at[102]);    MULADD(at[15], at[101]);    MULADD(at[16], at[100]);    MULADD(at[17], at[99]);    MULADD(at[18], at[98]);    MULADD(at[19], at[97]);    MULADD(at[20], at[96]);    MULADD(at[21], at[95]);    MULADD(at[22], at[94]);    MULADD(at[23], at[93]);    MULADD(at[24], at[92]);    MULADD(at[25], at[91]);    MULADD(at[26], at[90]);    MULADD(at[27], at[89]);    MULADD(at[28], at[88]);    MULADD(at[29], at[87]);    MULADD(at[30], at[86]);    MULADD(at[31], at[85]);    MULADD(at[32], at[84]);    MULADD(at[33], at[83]);    MULADD(at[34], at[82]);    MULADD(at[35], at[81]);    MULADD(at[36], at[80]);    MULADD(at[37], at[79]);    MULADD(at[38], at[78]);    MULADD(at[39], at[77]);    MULADD(at[40], at[76]);    MULADD(at[41], at[75]);    MULADD(at[42], at[74]);    MULADD(at[43], at[73]);    MULADD(at[44], at[72]);    MULADD(at[45], at[71]);    MULADD(at[46], at[70]);    MULADD(at[47], at[69]);    MULADD(at[48], at[68]);    MULADD(at[49], at[67]);    MULADD(at[50], at[66]);    MULADD(at[51], at[65]);    MULADD(at[52], at[64]); 
   COMBA_STORE(C->dp[52]);
   /* 53 */
   COMBA_FORWARD;
   MULADD(at[0], at[117]);    MULADD(at[1], at[116]);    MULADD(at[2], at[115]);    MULADD(at[3], at[114]);    MULADD(at[4], at[113]);    MULADD(at[5], at[112]);    MULADD(at[6], at[111]);    MULADD(at[7], at[110]);    MULADD(at[8], at[109]);    MULADD(at[9], at[108]);    MULADD(at[10], at[107]);    MULADD(at[11], at[106]);    MULADD(at[12], at[105]);    MULADD(at[13], at[104]);    MULADD(at[14], at[103]);    MULADD(at[15], at[102]);    MULADD(at[16], at[101]);    MULADD(at[17], at[100]);    MULADD(at[18], at[99]);    MULADD(at[19], at[98]);    MULADD(at[20], at[97]);    MULADD(at[21], at[96]);    MULADD(at[22], at[95]);    MULADD(at[23], at[94]);    MULADD(at[24], at[93]);    MULADD(at[25], at[92]);    MULADD(at[26], at[91]);    MULADD(at[27], at[90]);    MULADD(at[28], at[89]);    MULADD(at[29], at[88]);    MULADD(at[30], at[87]);    MULADD(at[31], at[86]);    MULADD(at[32], at[85]);    MULADD(at[33], at[84]);    MULADD(at[34], at[83]);    MULADD(at[35], at[82]);    MULADD(at[36], at[81]);    MULADD(at[37], at[80]);    MULADD(at[38], at[79]);    MULADD(at[39], at[78]);    MULADD(at[40], at[77]);    MULADD(at[41], at[76]);    MULADD(at[42], at[75]);    MULADD(at[43], at[74]);    MULADD(at[44], at[73]);    MULADD(at[45], at[72]);    MULADD(at[46], at[71]);    MULADD(at[47], at[70]);    MULADD(at[48], at[69]);    MULADD(at[49], at[68]);    MULADD(at[50], at[67]);    MULADD(at[51], at[66]);    MULADD(at[52], at[65]);    MULADD(at[53], at[64]); 
   COMBA_STORE(C->dp[53]);
   /* 54 */
   COMBA_FORWARD;
   MULADD(at[0], at[118]);    MULADD(at[1], at[117]);    MULADD(at[2], at[116]);    MULADD(at[3], at[115]);    MULADD(at[4], at[114]);    MULADD(at[5], at[113]);    MULADD(at[6], at[112]);    MULADD(at[7], at[111]);    MULADD(at[8], at[110]);    MULADD(at[9], at[109]);    MULADD(at[10], at[108]);    MULADD(at[11], at[107]);    MULADD(at[12], at[106]);    MULADD(at[13], at[105]);    MULADD(at[14], at[104]);    MULADD(at[15], at[103]);    MULADD(at[16], at[102]);    MULADD(at[17], at[101]);    MULADD(at[18], at[100]);    MULADD(at[19], at[99]);    MULADD(at[20], at[98]);    MULADD(at[21], at[97]);    MULADD(at[22], at[96]);    MULADD(at[23], at[95]);    MULADD(at[24], at[94]);    MULADD(at[25], at[93]);    MULADD(at[26], at[92]);    MULADD(at[27], at[91]);    MULADD(at[28], at[90]);    MULADD(at[29], at[89]);    MULADD(at[30], at[88]);    MULADD(at[31], at[87]);    MULADD(at[32], at[86]);    MULADD(at[33], at[85]);    MULADD(at[34], at[84]);    MULADD(at[35], at[83]);    MULADD(at[36], at[82]);    MULADD(at[37], at[81]);    MULADD(at[38], at[80]);    MULADD(at[39], at[79]);    MULADD(at[40], at[78]);    MULADD(at[41], at[77]);    MULADD(at[42], at[76]);    MULADD(at[43], at[75]);    MULADD(at[44], at[74]);    MULADD(at[45], at[73]);    MULADD(at[46], at[72]);    MULADD(at[47], at[71]);    MULADD(at[48], at[70]);    MULADD(at[49], at[69]);    MULADD(at[50], at[68]);    MULADD(at[51], at[67]);    MULADD(at[52], at[66]);    MULADD(at[53], at[65]);    MULADD(at[54], at[64]); 
   COMBA_STORE(C->dp[54]);
   /* 55 */
   COMBA_FORWARD;
   MULADD(at[0], at[119]);    MULADD(at[1], at[118]);    MULADD(at[2], at[117]);    MULADD(at[3], at[116]);    MULADD(at[4], at[115]);    MULADD(at[5], at[114]);    MULADD(at[6], at[113]);    MULADD(at[7], at[112]);    MULADD(at[8], at[111]);    MULADD(at[9], at[110]);    MULADD(at[10], at[109]);    MULADD(at[11], at[108]);    MULADD(at[12], at[107]);    MULADD(at[13], at[106]);    MULADD(at[14], at[105]);    MULADD(at[15], at[104]);    MULADD(at[16], at[103]);    MULADD(at[17], at[102]);    MULADD(at[18], at[101]);    MULADD(at[19], at[100]);    MULADD(at[20], at[99]);    MULADD(at[21], at[98]);    MULADD(at[22], at[97]);    MULADD(at[23], at[96]);    MULADD(at[24], at[95]);    MULADD(at[25], at[94]);    MULADD(at[26], at[93]);    MULADD(at[27], at[92]);    MULADD(at[28], at[91]);    MULADD(at[29], at[90]);    MULADD(at[30], at[89]);    MULADD(at[31], at[88]);    MULADD(at[32], at[87]);    MULADD(at[33], at[86]);    MULADD(at[34], at[85]);    MULADD(at[35], at[84]);    MULADD(at[36], at[83]);    MULADD(at[37], at[82]);    MULADD(at[38], at[81]);    MULADD(at[39], at[80]);    MULADD(at[40], at[79]);    MULADD(at[41], at[78]);    MULADD(at[42], at[77]);    MULADD(at[43], at[76]);    MULADD(at[44], at[75]);    MULADD(at[45], at[74]);    MULADD(at[46], at[73]);    MULADD(at[47], at[72]);    MULADD(at[48], at[71]);    MULADD(at[49], at[70]);    MULADD(at[50], at[69]);    MULADD(at[51], at[68]);    MULADD(at[52], at[67]);    MULADD(at[53], at[66]);    MULADD(at[54], at[65]);    MULADD(at[55], at[64]); 
   COMBA_STORE(C->dp[55]);
   /* 56 */
   COMBA_FORWARD;
   MULADD(at[0], at[120]);    MULADD(at[1], at[119]);    MULADD(at[2], at[118]);    MULADD(at[3], at[117]);    MULADD(at[4], at[116]);    MULADD(at[5], at[115]);    MULADD(at[6], at[114]);    MULADD(at[7], at[113]);    MULADD(at[8], at[112]);    MULADD(at[9], at[111]);    MULADD(at[10], at[110]);    MULADD(at[11], at[109]);    MULADD(at[12], at[108]);    MULADD(at[13], at[107]);    MULADD(at[14], at[106]);    MULADD(at[15], at[105]);    MULADD(at[16], at[104]);    MULADD(at[17], at[103]);    MULADD(at[18], at[102]);    MULADD(at[19], at[101]);    MULADD(at[20], at[100]);    MULADD(at[21], at[99]);    MULADD(at[22], at[98]);    MULADD(at[23], at[97]);    MULADD(at[24], at[96]);    MULADD(at[25], at[95]);    MULADD(at[26], at[94]);    MULADD(at[27], at[93]);    MULADD(at[28], at[92]);    MULADD(at[29], at[91]);    MULADD(at[30], at[90]);    MULADD(at[31], at[89]);    MULADD(at[32], at[88]);    MULADD(at[33], at[87]);    MULADD(at[34], at[86]);    MULADD(at[35], at[85]);    MULADD(at[36], at[84]);    MULADD(at[37], at[83]);    MULADD(at[38], at[82]);    MULADD(at[39], at[81]);    MULADD(at[40], at[80]);    MULADD(at[41], at[79]);    MULADD(at[42], at[78]);    MULADD(at[43], at[77]);    MULADD(at[44], at[76]);    MULADD(at[45], at[75]);    MULADD(at[46], at[74]);    MULADD(at[47], at[73]);    MULADD(at[48], at[72]);    MULADD(at[49], at[71]);    MULADD(at[50], at[70]);    MULADD(at[51], at[69]);    MULADD(at[52], at[68]);    MULADD(at[53], at[67]);    MULADD(at[54], at[66]);    MULADD(at[55], at[65]);    MULADD(at[56], at[64]); 
   COMBA_STORE(C->dp[56]);
   /* 57 */
   COMBA_FORWARD;
   MULADD(at[0], at[121]);    MULADD(at[1], at[120]);    MULADD(at[2], at[119]);    MULADD(at[3], at[118]);    MULADD(at[4], at[117]);    MULADD(at[5], at[116]);    MULADD(at[6], at[115]);    MULADD(at[7], at[114]);    MULADD(at[8], at[113]);    MULADD(at[9], at[112]);    MULADD(at[10], at[111]);    MULADD(at[11], at[110]);    MULADD(at[12], at[109]);    MULADD(at[13], at[108]);    MULADD(at[14], at[107]);    MULADD(at[15], at[106]);    MULADD(at[16], at[105]);    MULADD(at[17], at[104]);    MULADD(at[18], at[103]);    MULADD(at[19], at[102]);    MULADD(at[20], at[101]);    MULADD(at[21], at[100]);    MULADD(at[22], at[99]);    MULADD(at[23], at[98]);    MULADD(at[24], at[97]);    MULADD(at[25], at[96]);    MULADD(at[26], at[95]);    MULADD(at[27], at[94]);    MULADD(at[28], at[93]);    MULADD(at[29], at[92]);    MULADD(at[30], at[91]);    MULADD(at[31], at[90]);    MULADD(at[32], at[89]);    MULADD(at[33], at[88]);    MULADD(at[34], at[87]);    MULADD(at[35], at[86]);    MULADD(at[36], at[85]);    MULADD(at[37], at[84]);    MULADD(at[38], at[83]);    MULADD(at[39], at[82]);    MULADD(at[40], at[81]);    MULADD(at[41], at[80]);    MULADD(at[42], at[79]);    MULADD(at[43], at[78]);    MULADD(at[44], at[77]);    MULADD(at[45], at[76]);    MULADD(at[46], at[75]);    MULADD(at[47], at[74]);    MULADD(at[48], at[73]);    MULADD(at[49], at[72]);    MULADD(at[50], at[71]);    MULADD(at[51], at[70]);    MULADD(at[52], at[69]);    MULADD(at[53], at[68]);    MULADD(at[54], at[67]);    MULADD(at[55], at[66]);    MULADD(at[56], at[65]);    MULADD(at[57], at[64]); 
   COMBA_STORE(C->dp[57]);
   /* 58 */
   COMBA_FORWARD;
   MULADD(at[0], at[122]);    MULADD(at[1], at[121]);    MULADD(at[2], at[120]);    MULADD(at[3], at[119]);    MULADD(at[4], at[118]);    MULADD(at[5], at[117]);    MULADD(at[6], at[116]);    MULADD(at[7], at[115]);    MULADD(at[8], at[114]);    MULADD(at[9], at[113]);    MULADD(at[10], at[112]);    MULADD(at[11], at[111]);    MULADD(at[12], at[110]);    MULADD(at[13], at[109]);    MULADD(at[14], at[108]);    MULADD(at[15], at[107]);    MULADD(at[16], at[106]);    MULADD(at[17], at[105]);    MULADD(at[18], at[104]);    MULADD(at[19], at[103]);    MULADD(at[20], at[102]);    MULADD(at[21], at[101]);    MULADD(at[22], at[100]);    MULADD(at[23], at[99]);    MULADD(at[24], at[98]);    MULADD(at[25], at[97]);    MULADD(at[26], at[96]);    MULADD(at[27], at[95]);    MULADD(at[28], at[94]);    MULADD(at[29], at[93]);    MULADD(at[30], at[92]);    MULADD(at[31], at[91]);    MULADD(at[32], at[90]);    MULADD(at[33], at[89]);    MULADD(at[34], at[88]);    MULADD(at[35], at[87]);    MULADD(at[36], at[86]);    MULADD(at[37], at[85]);    MULADD(at[38], at[84]);    MULADD(at[39], at[83]);    MULADD(at[40], at[82]);    MULADD(at[41], at[81]);    MULADD(at[42], at[80]);    MULADD(at[43], at[79]);    MULADD(at[44], at[78]);    MULADD(at[45], at[77]);    MULADD(at[46], at[76]);    MULADD(at[47], at[75]);    MULADD(at[48], at[74]);    MULADD(at[49], at[73]);    MULADD(at[50], at[72]);    MULADD(at[51], at[71]);    MULADD(at[52], at[70]);    MULADD(at[53], at[69]);    MULADD(at[54], at[68]);    MULADD(at[55], at[67]);    MULADD(at[56], at[66]);    MULADD(at[57], at[65]);    MULADD(at[58], at[64]); 
   COMBA_STORE(C->dp[58]);
   /* 59 */
   COMBA_FORWARD;
   MULADD(at[0], at[123]);    MULADD(at[1], at[122]);    MULADD(at[2], at[121]);    MULADD(at[3], at[120]);    MULADD(at[4], at[119]);    MULADD(at[5], at[118]);    MULADD(at[6], at[117]);    MULADD(at[7], at[116]);    MULADD(at[8], at[115]);    MULADD(at[9], at[114]);    MULADD(at[10], at[113]);    MULADD(at[11], at[112]);    MULADD(at[12], at[111]);    MULADD(at[13], at[110]);    MULADD(at[14], at[109]);    MULADD(at[15], at[108]);    MULADD(at[16], at[107]);    MULADD(at[17], at[106]);    MULADD(at[18], at[105]);    MULADD(at[19], at[104]);    MULADD(at[20], at[103]);    MULADD(at[21], at[102]);    MULADD(at[22], at[101]);    MULADD(at[23], at[100]);    MULADD(at[24], at[99]);    MULADD(at[25], at[98]);    MULADD(at[26], at[97]);    MULADD(at[27], at[96]);    MULADD(at[28], at[95]);    MULADD(at[29], at[94]);    MULADD(at[30], at[93]);    MULADD(at[31], at[92]);    MULADD(at[32], at[91]);    MULADD(at[33], at[90]);    MULADD(at[34], at[89]);    MULADD(at[35], at[88]);    MULADD(at[36], at[87]);    MULADD(at[37], at[86]);    MULADD(at[38], at[85]);    MULADD(at[39], at[84]);    MULADD(at[40], at[83]);    MULADD(at[41], at[82]);    MULADD(at[42], at[81]);    MULADD(at[43], at[80]);    MULADD(at[44], at[79]);    MULADD(at[45], at[78]);    MULADD(at[46], at[77]);    MULADD(at[47], at[76]);    MULADD(at[48], at[75]);    MULADD(at[49], at[74]);    MULADD(at[50], at[73]);    MULADD(at[51], at[72]);    MULADD(at[52], at[71]);    MULADD(at[53], at[70]);    MULADD(at[54], at[69]);    MULADD(at[55], at[68]);    MULADD(at[56], at[67]);    MULADD(at[57], at[66]);    MULADD(at[58], at[65]);    MULADD(at[59], at[64]); 
   COMBA_STORE(C->dp[59]);
   /* 60 */
   COMBA_FORWARD;
   MULADD(at[0], at[124]);    MULADD(at[1], at[123]);    MULADD(at[2], at[122]);    MULADD(at[3], at[121]);    MULADD(at[4], at[120]);    MULADD(at[5], at[119]);    MULADD(at[6], at[118]);    MULADD(at[7], at[117]);    MULADD(at[8], at[116]);    MULADD(at[9], at[115]);    MULADD(at[10], at[114]);    MULADD(at[11], at[113]);    MULADD(at[12], at[112]);    MULADD(at[13], at[111]);    MULADD(at[14], at[110]);    MULADD(at[15], at[109]);    MULADD(at[16], at[108]);    MULADD(at[17], at[107]);    MULADD(at[18], at[106]);    MULADD(at[19], at[105]);    MULADD(at[20], at[104]);    MULADD(at[21], at[103]);    MULADD(at[22], at[102]);    MULADD(at[23], at[101]);    MULADD(at[24], at[100]);    MULADD(at[25], at[99]);    MULADD(at[26], at[98]);    MULADD(at[27], at[97]);    MULADD(at[28], at[96]);    MULADD(at[29], at[95]);    MULADD(at[30], at[94]);    MULADD(at[31], at[93]);    MULADD(at[32], at[92]);    MULADD(at[33], at[91]);    MULADD(at[34], at[90]);    MULADD(at[35], at[89]);    MULADD(at[36], at[88]);    MULADD(at[37], at[87]);    MULADD(at[38], at[86]);    MULADD(at[39], at[85]);    MULADD(at[40], at[84]);    MULADD(at[41], at[83]);    MULADD(at[42], at[82]);    MULADD(at[43], at[81]);    MULADD(at[44], at[80]);    MULADD(at[45], at[79]);    MULADD(at[46], at[78]);    MULADD(at[47], at[77]);    MULADD(at[48], at[76]);    MULADD(at[49], at[75]);    MULADD(at[50], at[74]);    MULADD(at[51], at[73]);    MULADD(at[52], at[72]);    MULADD(at[53], at[71]);    MULADD(at[54], at[70]);    MULADD(at[55], at[69]);    MULADD(at[56], at[68]);    MULADD(at[57], at[67]);    MULADD(at[58], at[66]);    MULADD(at[59], at[65]);    MULADD(at[60], at[64]); 
   COMBA_STORE(C->dp[60]);
   /* 61 */
   COMBA_FORWARD;
   MULADD(at[0], at[125]);    MULADD(at[1], at[124]);    MULADD(at[2], at[123]);    MULADD(at[3], at[122]);    MULADD(at[4], at[121]);    MULADD(at[5], at[120]);    MULADD(at[6], at[119]);    MULADD(at[7], at[118]);    MULADD(at[8], at[117]);    MULADD(at[9], at[116]);    MULADD(at[10], at[115]);    MULADD(at[11], at[114]);    MULADD(at[12], at[113]);    MULADD(at[13], at[112]);    MULADD(at[14], at[111]);    MULADD(at[15], at[110]);    MULADD(at[16], at[109]);    MULADD(at[17], at[108]);    MULADD(at[18], at[107]);    MULADD(at[19], at[106]);    MULADD(at[20], at[105]);    MULADD(at[21], at[104]);    MULADD(at[22], at[103]);    MULADD(at[23], at[102]);    MULADD(at[24], at[101]);    MULADD(at[25], at[100]);    MULADD(at[26], at[99]);    MULADD(at[27], at[98]);    MULADD(at[28], at[97]);    MULADD(at[29], at[96]);    MULADD(at[30], at[95]);    MULADD(at[31], at[94]);    MULADD(at[32], at[93]);    MULADD(at[33], at[92]);    MULADD(at[34], at[91]);    MULADD(at[35], at[90]);    MULADD(at[36], at[89]);    MULADD(at[37], at[88]);    MULADD(at[38], at[87]);    MULADD(at[39], at[86]);    MULADD(at[40], at[85]);    MULADD(at[41], at[84]);    MULADD(at[42], at[83]);    MULADD(at[43], at[82]);    MULADD(at[44], at[81]);    MULADD(at[45], at[80]);    MULADD(at[46], at[79]);    MULADD(at[47], at[78]);    MULADD(at[48], at[77]);    MULADD(at[49], at[76]);    MULADD(at[50], at[75]);    MULADD(at[51], at[74]);    MULADD(at[52], at[73]);    MULADD(at[53], at[72]);    MULADD(at[54], at[71]);    MULADD(at[55], at[70]);    MULADD(at[56], at[69]);    MULADD(at[57], at[68]);    MULADD(at[58], at[67]);    MULADD(at[59], at[66]);    MULADD(at[60], at[65]);    MULADD(at[61], at[64]); 
   COMBA_STORE(C->dp[61]);
   /* 62 */
   COMBA_FORWARD;
   MULADD(at[0], at[126]);    MULADD(at[1], at[125]);    MULADD(at[2], at[124]);    MULADD(at[3], at[123]);    MULADD(at[4], at[122]);    MULADD(at[5], at[121]);    MULADD(at[6], at[120]);    MULADD(at[7], at[119]);    MULADD(at[8], at[118]);    MULADD(at[9], at[117]);    MULADD(at[10], at[116]);    MULADD(at[11], at[115]);    MULADD(at[12], at[114]);    MULADD(at[13], at[113]);    MULADD(at[14], at[112]);    MULADD(at[15], at[111]);    MULADD(at[16], at[110]);    MULADD(at[17], at[109]);    MULADD(at[18], at[108]);    MULADD(at[19], at[107]);    MULADD(at[20], at[106]);    MULADD(at[21], at[105]);    MULADD(at[22], at[104]);    MULADD(at[23], at[103]);    MULADD(at[24], at[102]);    MULADD(at[25], at[101]);    MULADD(at[26], at[100]);    MULADD(at[27], at[99]);    MULADD(at[28], at[98]);    MULADD(at[29], at[97]);    MULADD(at[30], at[96]);    MULADD(at[31], at[95]);    MULADD(at[32], at[94]);    MULADD(at[33], at[93]);    MULADD(at[34], at[92]);    MULADD(at[35], at[91]);    MULADD(at[36], at[90]);    MULADD(at[37], at[89]);    MULADD(at[38], at[88]);    MULADD(at[39], at[87]);    MULADD(at[40], at[86]);    MULADD(at[41], at[85]);    MULADD(at[42], at[84]);    MULADD(at[43], at[83]);    MULADD(at[44], at[82]);    MULADD(at[45], at[81]);    MULADD(at[46], at[80]);    MULADD(at[47], at[79]);    MULADD(at[48], at[78]);    MULADD(at[49], at[77]);    MULADD(at[50], at[76]);    MULADD(at[51], at[75]);    MULADD(at[52], at[74]);    MULADD(at[53], at[73]);    MULADD(at[54], at[72]);    MULADD(at[55], at[71]);    MULADD(at[56], at[70]);    MULADD(at[57], at[69]);    MULADD(at[58], at[68]);    MULADD(at[59], at[67]);    MULADD(at[60], at[66]);    MULADD(at[61], at[65]);    MULADD(at[62], at[64]); 
   COMBA_STORE(C->dp[62]);
   /* 63 */
   COMBA_FORWARD;
   MULADD(at[0], at[127]);    MULADD(at[1], at[126]);    MULADD(at[2], at[125]);    MULADD(at[3], at[124]);    MULADD(at[4], at[123]);    MULADD(at[5], at[122]);    MULADD(at[6], at[121]);    MULADD(at[7], at[120]);    MULADD(at[8], at[119]);    MULADD(at[9], at[118]);    MULADD(at[10], at[117]);    MULADD(at[11], at[116]);    MULADD(at[12], at[115]);    MULADD(at[13], at[114]);    MULADD(at[14], at[113]);    MULADD(at[15], at[112]);    MULADD(at[16], at[111]);    MULADD(at[17], at[110]);    MULADD(at[18], at[109]);    MULADD(at[19], at[108]);    MULADD(at[20], at[107]);    MULADD(at[21], at[106]);    MULADD(at[22], at[105]);    MULADD(at[23], at[104]);    MULADD(at[24], at[103]);    MULADD(at[25], at[102]);    MULADD(at[26], at[101]);    MULADD(at[27], at[100]);    MULADD(at[28], at[99]);    MULADD(at[29], at[98]);    MULADD(at[30], at[97]);    MULADD(at[31], at[96]);    MULADD(at[32], at[95]);    MULADD(at[33], at[94]);    MULADD(at[34], at[93]);    MULADD(at[35], at[92]);    MULADD(at[36], at[91]);    MULADD(at[37], at[90]);    MULADD(at[38], at[89]);    MULADD(at[39], at[88]);    MULADD(at[40], at[87]);    MULADD(at[41], at[86]);    MULADD(at[42], at[85]);    MULADD(at[43], at[84]);    MULADD(at[44], at[83]);    MULADD(at[45], at[82]);    MULADD(at[46], at[81]);    MULADD(at[47], at[80]);    MULADD(at[48], at[79]);    MULADD(at[49], at[78]);    MULADD(at[50], at[77]);    MULADD(at[51], at[76]);    MULADD(at[52], at[75]);    MULADD(at[53], at[74]);    MULADD(at[54], at[73]);    MULADD(at[55], at[72]);    MULADD(at[56], at[71]);    MULADD(at[57], at[70]);    MULADD(at[58], at[69]);    MULADD(at[59], at[68]);    MULADD(at[60], at[67]);    MULADD(at[61], at[66]);    MULADD(at[62], at[65]);    MULADD(at[63], at[64]); 
   COMBA_STORE(C->dp[63]);
   /* 64 */
   COMBA_FORWARD;
   MULADD(at[1], at[127]);    MULADD(at[2], at[126]);    MULADD(at[3], at[125]);    MULADD(at[4], at[124]);    MULADD(at[5], at[123]);    MULADD(at[6], at[122]);    MULADD(at[7], at[121]);    MULADD(at[8], at[120]);    MULADD(at[9], at[119]);    MULADD(at[10], at[118]);    MULADD(at[11], at[117]);    MULADD(at[12], at[116]);    MULADD(at[13], at[115]);    MULADD(at[14], at[114]);    MULADD(at[15], at[113]);    MULADD(at[16], at[112]);    MULADD(at[17], at[111]);    MULADD(at[18], at[110]);    MULADD(at[19], at[109]);    MULADD(at[20], at[108]);    MULADD(at[21], at[107]);    MULADD(at[22], at[106]);    MULADD(at[23], at[105]);    MULADD(at[24], at[104]);    MULADD(at[25], at[103]);    MULADD(at[26], at[102]);    MULADD(at[27], at[101]);    MULADD(at[28], at[100]);    MULADD(at[29], at[99]);    MULADD(at[30], at[98]);    MULADD(at[31], at[97]);    MULADD(at[32], at[96]);    MULADD(at[33], at[95]);    MULADD(at[34], at[94]);    MULADD(at[35], at[93]);    MULADD(at[36], at[92]);    MULADD(at[37], at[91]);    MULADD(at[38], at[90]);    MULADD(at[39], at[89]);    MULADD(at[40], at[88]);    MULADD(at[41], at[87]);    MULADD(at[42], at[86]);    MULADD(at[43], at[85]);    MULADD(at[44], at[84]);    MULADD(at[45], at[83]);    MULADD(at[46], at[82]);    MULADD(at[47], at[81]);    MULADD(at[48], at[80]);    MULADD(at[49], at[79]);    MULADD(at[50], at[78]);    MULADD(at[51], at[77]);    MULADD(at[52], at[76]);    MULADD(at[53], at[75]);    MULADD(at[54], at[74]);    MULADD(at[55], at[73]);    MULADD(at[56], at[72]);    MULADD(at[57], at[71]);    MULADD(at[58], at[70]);    MULADD(at[59], at[69]);    MULADD(at[60], at[68]);    MULADD(at[61], at[67]);    MULADD(at[62], at[66]);    MULADD(at[63], at[65]); 
   COMBA_STORE(C->dp[64]);
   /* 65 */
   COMBA_FORWARD;
   MULADD(at[2], at[127]);    MULADD(at[3], at[126]);    MULADD(at[4], at[125]);    MULADD(at[5], at[124]);    MULADD(at[6], at[123]);    MULADD(at[7], at[122]);    MULADD(at[8], at[121]);    MULADD(at[9], at[120]);    MULADD(at[10], at[119]);    MULADD(at[11], at[118]);    MULADD(at[12], at[117]);    MULADD(at[13], at[116]);    MULADD(at[14], at[115]);    MULADD(at[15], at[114]);    MULADD(at[16], at[113]);    MULADD(at[17], at[112]);    MULADD(at[18], at[111]);    MULADD(at[19], at[110]);    MULADD(at[20], at[109]);    MULADD(at[21], at[108]);    MULADD(at[22], at[107]);    MULADD(at[23], at[106]);    MULADD(at[24], at[105]);    MULADD(at[25], at[104]);    MULADD(at[26], at[103]);    MULADD(at[27], at[102]);    MULADD(at[28], at[101]);    MULADD(at[29], at[100]);    MULADD(at[30], at[99]);    MULADD(at[31], at[98]);    MULADD(at[32], at[97]);    MULADD(at[33], at[96]);    MULADD(at[34], at[95]);    MULADD(at[35], at[94]);    MULADD(at[36], at[93]);    MULADD(at[37], at[92]);    MULADD(at[38], at[91]);    MULADD(at[39], at[90]);    MULADD(at[40], at[89]);    MULADD(at[41], at[88]);    MULADD(at[42], at[87]);    MULADD(at[43], at[86]);    MULADD(at[44], at[85]);    MULADD(at[45], at[84]);    MULADD(at[46], at[83]);    MULADD(at[47], at[82]);    MULADD(at[48], at[81]);    MULADD(at[49], at[80]);    MULADD(at[50], at[79]);    MULADD(at[51], at[78]);    MULADD(at[52], at[77]);    MULADD(at[53], at[76]);    MULADD(at[54], at[75]);    MULADD(at[55], at[74]);    MULADD(at[56], at[73]);    MULADD(at[57], at[72]);    MULADD(at[58], at[71]);    MULADD(at[59], at[70]);    MULADD(at[60], at[69]);    MULADD(at[61], at[68]);    MULADD(at[62], at[67]);    MULADD(at[63], at[66]); 
   COMBA_STORE(C->dp[65]);
   /* 66 */
   COMBA_FORWARD;
   MULADD(at[3], at[127]);    MULADD(at[4], at[126]);    MULADD(at[5], at[125]);    MULADD(at[6], at[124]);    MULADD(at[7], at[123]);    MULADD(at[8], at[122]);    MULADD(at[9], at[121]);    MULADD(at[10], at[120]);    MULADD(at[11], at[119]);    MULADD(at[12], at[118]);    MULADD(at[13], at[117]);    MULADD(at[14], at[116]);    MULADD(at[15], at[115]);    MULADD(at[16], at[114]);    MULADD(at[17], at[113]);    MULADD(at[18], at[112]);    MULADD(at[19], at[111]);    MULADD(at[20], at[110]);    MULADD(at[21], at[109]);    MULADD(at[22], at[108]);    MULADD(at[23], at[107]);    MULADD(at[24], at[106]);    MULADD(at[25], at[105]);    MULADD(at[26], at[104]);    MULADD(at[27], at[103]);    MULADD(at[28], at[102]);    MULADD(at[29], at[101]);    MULADD(at[30], at[100]);    MULADD(at[31], at[99]);    MULADD(at[32], at[98]);    MULADD(at[33], at[97]);    MULADD(at[34], at[96]);    MULADD(at[35], at[95]);    MULADD(at[36], at[94]);    MULADD(at[37], at[93]);    MULADD(at[38], at[92]);    MULADD(at[39], at[91]);    MULADD(at[40], at[90]);    MULADD(at[41], at[89]);    MULADD(at[42], at[88]);    MULADD(at[43], at[87]);    MULADD(at[44], at[86]);    MULADD(at[45], at[85]);    MULADD(at[46], at[84]);    MULADD(at[47], at[83]);    MULADD(at[48], at[82]);    MULADD(at[49], at[81]);    MULADD(at[50], at[80]);    MULADD(at[51], at[79]);    MULADD(at[52], at[78]);    MULADD(at[53], at[77]);    MULADD(at[54], at[76]);    MULADD(at[55], at[75]);    MULADD(at[56], at[74]);    MULADD(at[57], at[73]);    MULADD(at[58], at[72]);    MULADD(at[59], at[71]);    MULADD(at[60], at[70]);    MULADD(at[61], at[69]);    MULADD(at[62], at[68]);    MULADD(at[63], at[67]); 
   COMBA_STORE(C->dp[66]);
   /* 67 */
   COMBA_FORWARD;
   MULADD(at[4], at[127]);    MULADD(at[5], at[126]);    MULADD(at[6], at[125]);    MULADD(at[7], at[124]);    MULADD(at[8], at[123]);    MULADD(at[9], at[122]);    MULADD(at[10], at[121]);    MULADD(at[11], at[120]);    MULADD(at[12], at[119]);    MULADD(at[13], at[118]);    MULADD(at[14], at[117]);    MULADD(at[15], at[116]);    MULADD(at[16], at[115]);    MULADD(at[17], at[114]);    MULADD(at[18], at[113]);    MULADD(at[19], at[112]);    MULADD(at[20], at[111]);    MULADD(at[21], at[110]);    MULADD(at[22], at[109]);    MULADD(at[23], at[108]);    MULADD(at[24], at[107]);    MULADD(at[25], at[106]);    MULADD(at[26], at[105]);    MULADD(at[27], at[104]);    MULADD(at[28], at[103]);    MULADD(at[29], at[102]);    MULADD(at[30], at[101]);    MULADD(at[31], at[100]);    MULADD(at[32], at[99]);    MULADD(at[33], at[98]);    MULADD(at[34], at[97]);    MULADD(at[35], at[96]);    MULADD(at[36], at[95]);    MULADD(at[37], at[94]);    MULADD(at[38], at[93]);    MULADD(at[39], at[92]);    MULADD(at[40], at[91]);    MULADD(at[41], at[90]);    MULADD(at[42], at[89]);    MULADD(at[43], at[88]);    MULADD(at[44], at[87]);    MULADD(at[45], at[86]);    MULADD(at[46], at[85]);    MULADD(at[47], at[84]);    MULADD(at[48], at[83]);    MULADD(at[49], at[82]);    MULADD(at[50], at[81]);    MULADD(at[51], at[80]);    MULADD(at[52], at[79]);    MULADD(at[53], at[78]);    MULADD(at[54], at[77]);    MULADD(at[55], at[76]);    MULADD(at[56], at[75]);    MULADD(at[57], at[74]);    MULADD(at[58], at[73]);    MULADD(at[59], at[72]);    MULADD(at[60], at[71]);    MULADD(at[61], at[70]);    MULADD(at[62], at[69]);    MULADD(at[63], at[68]); 
   COMBA_STORE(C->dp[67]);
   /* 68 */
   COMBA_FORWARD;
   MULADD(at[5], at[127]);    MULADD(at[6], at[126]);    MULADD(at[7], at[125]);    MULADD(at[8], at[124]);    MULADD(at[9], at[123]);    MULADD(at[10], at[122]);    MULADD(at[11], at[121]);    MULADD(at[12], at[120]);    MULADD(at[13], at[119]);    MULADD(at[14], at[118]);    MULADD(at[15], at[117]);    MULADD(at[16], at[116]);    MULADD(at[17], at[115]);    MULADD(at[18], at[114]);    MULADD(at[19], at[113]);    MULADD(at[20], at[112]);    MULADD(at[21], at[111]);    MULADD(at[22], at[110]);    MULADD(at[23], at[109]);    MULADD(at[24], at[108]);    MULADD(at[25], at[107]);    MULADD(at[26], at[106]);    MULADD(at[27], at[105]);    MULADD(at[28], at[104]);    MULADD(at[29], at[103]);    MULADD(at[30], at[102]);    MULADD(at[31], at[101]);    MULADD(at[32], at[100]);    MULADD(at[33], at[99]);    MULADD(at[34], at[98]);    MULADD(at[35], at[97]);    MULADD(at[36], at[96]);    MULADD(at[37], at[95]);    MULADD(at[38], at[94]);    MULADD(at[39], at[93]);    MULADD(at[40], at[92]);    MULADD(at[41], at[91]);    MULADD(at[42], at[90]);    MULADD(at[43], at[89]);    MULADD(at[44], at[88]);    MULADD(at[45], at[87]);    MULADD(at[46], at[86]);    MULADD(at[47], at[85]);    MULADD(at[48], at[84]);    MULADD(at[49], at[83]);    MULADD(at[50], at[82]);    MULADD(at[51], at[81]);    MULADD(at[52], at[80]);    MULADD(at[53], at[79]);    MULADD(at[54], at[78]);    MULADD(at[55], at[77]);    MULADD(at[56], at[76]);    MULADD(at[57], at[75]);    MULADD(at[58], at[74]);    MULADD(at[59], at[73]);    MULADD(at[60], at[72]);    MULADD(at[61], at[71]);    MULADD(at[62], at[70]);    MULADD(at[63], at[69]); 
   COMBA_STORE(C->dp[68]);
   /* 69 */
   COMBA_FORWARD;
   MULADD(at[6], at[127]);    MULADD(at[7], at[126]);    MULADD(at[8], at[125]);    MULADD(at[9], at[124]);    MULADD(at[10], at[123]);    MULADD(at[11], at[122]);    MULADD(at[12], at[121]);    MULADD(at[13], at[120]);    MULADD(at[14], at[119]);    MULADD(at[15], at[118]);    MULADD(at[16], at[117]);    MULADD(at[17], at[116]);    MULADD(at[18], at[115]);    MULADD(at[19], at[114]);    MULADD(at[20], at[113]);    MULADD(at[21], at[112]);    MULADD(at[22], at[111]);    MULADD(at[23], at[110]);    MULADD(at[24], at[109]);    MULADD(at[25], at[108]);    MULADD(at[26], at[107]);    MULADD(at[27], at[106]);    MULADD(at[28], at[105]);    MULADD(at[29], at[104]);    MULADD(at[30], at[103]);    MULADD(at[31], at[102]);    MULADD(at[32], at[101]);    MULADD(at[33], at[100]);    MULADD(at[34], at[99]);    MULADD(at[35], at[98]);    MULADD(at[36], at[97]);    MULADD(at[37], at[96]);    MULADD(at[38], at[95]);    MULADD(at[39], at[94]);    MULADD(at[40], at[93]);    MULADD(at[41], at[92]);    MULADD(at[42], at[91]);    MULADD(at[43], at[90]);    MULADD(at[44], at[89]);    MULADD(at[45], at[88]);    MULADD(at[46], at[87]);    MULADD(at[47], at[86]);    MULADD(at[48], at[85]);    MULADD(at[49], at[84]);    MULADD(at[50], at[83]);    MULADD(at[51], at[82]);    MULADD(at[52], at[81]);    MULADD(at[53], at[80]);    MULADD(at[54], at[79]);    MULADD(at[55], at[78]);    MULADD(at[56], at[77]);    MULADD(at[57], at[76]);    MULADD(at[58], at[75]);    MULADD(at[59], at[74]);    MULADD(at[60], at[73]);    MULADD(at[61], at[72]);    MULADD(at[62], at[71]);    MULADD(at[63], at[70]); 
   COMBA_STORE(C->dp[69]);
   /* 70 */
   COMBA_FORWARD;
   MULADD(at[7], at[127]);    MULADD(at[8], at[126]);    MULADD(at[9], at[125]);    MULADD(at[10], at[124]);    MULADD(at[11], at[123]);    MULADD(at[12], at[122]);    MULADD(at[13], at[121]);    MULADD(at[14], at[120]);    MULADD(at[15], at[119]);    MULADD(at[16], at[118]);    MULADD(at[17], at[117]);    MULADD(at[18], at[116]);    MULADD(at[19], at[115]);    MULADD(at[20], at[114]);    MULADD(at[21], at[113]);    MULADD(at[22], at[112]);    MULADD(at[23], at[111]);    MULADD(at[24], at[110]);    MULADD(at[25], at[109]);    MULADD(at[26], at[108]);    MULADD(at[27], at[107]);    MULADD(at[28], at[106]);    MULADD(at[29], at[105]);    MULADD(at[30], at[104]);    MULADD(at[31], at[103]);    MULADD(at[32], at[102]);    MULADD(at[33], at[101]);    MULADD(at[34], at[100]);    MULADD(at[35], at[99]);    MULADD(at[36], at[98]);    MULADD(at[37], at[97]);    MULADD(at[38], at[96]);    MULADD(at[39], at[95]);    MULADD(at[40], at[94]);    MULADD(at[41], at[93]);    MULADD(at[42], at[92]);    MULADD(at[43], at[91]);    MULADD(at[44], at[90]);    MULADD(at[45], at[89]);    MULADD(at[46], at[88]);    MULADD(at[47], at[87]);    MULADD(at[48], at[86]);    MULADD(at[49], at[85]);    MULADD(at[50], at[84]);    MULADD(at[51], at[83]);    MULADD(at[52], at[82]);    MULADD(at[53], at[81]);    MULADD(at[54], at[80]);    MULADD(at[55], at[79]);    MULADD(at[56], at[78]);    MULADD(at[57], at[77]);    MULADD(at[58], at[76]);    MULADD(at[59], at[75]);    MULADD(at[60], at[74]);    MULADD(at[61], at[73]);    MULADD(at[62], at[72]);    MULADD(at[63], at[71]); 
   COMBA_STORE(C->dp[70]);
   /* 71 */
   COMBA_FORWARD;
   MULADD(at[8], at[127]);    MULADD(at[9], at[126]);    MULADD(at[10], at[125]);    MULADD(at[11], at[124]);    MULADD(at[12], at[123]);    MULADD(at[13], at[122]);    MULADD(at[14], at[121]);    MULADD(at[15], at[120]);    MULADD(at[16], at[119]);    MULADD(at[17], at[118]);    MULADD(at[18], at[117]);    MULADD(at[19], at[116]);    MULADD(at[20], at[115]);    MULADD(at[21], at[114]);    MULADD(at[22], at[113]);    MULADD(at[23], at[112]);    MULADD(at[24], at[111]);    MULADD(at[25], at[110]);    MULADD(at[26], at[109]);    MULADD(at[27], at[108]);    MULADD(at[28], at[107]);    MULADD(at[29], at[106]);    MULADD(at[30], at[105]);    MULADD(at[31], at[104]);    MULADD(at[32], at[103]);    MULADD(at[33], at[102]);    MULADD(at[34], at[101]);    MULADD(at[35], at[100]);    MULADD(at[36], at[99]);    MULADD(at[37], at[98]);    MULADD(at[38], at[97]);    MULADD(at[39], at[96]);    MULADD(at[40], at[95]);    MULADD(at[41], at[94]);    MULADD(at[42], at[93]);    MULADD(at[43], at[92]);    MULADD(at[44], at[91]);    MULADD(at[45], at[90]);    MULADD(at[46], at[89]);    MULADD(at[47], at[88]);    MULADD(at[48], at[87]);    MULADD(at[49], at[86]);    MULADD(at[50], at[85]);    MULADD(at[51], at[84]);    MULADD(at[52], at[83]);    MULADD(at[53], at[82]);    MULADD(at[54], at[81]);    MULADD(at[55], at[80]);    MULADD(at[56], at[79]);    MULADD(at[57], at[78]);    MULADD(at[58], at[77]);    MULADD(at[59], at[76]);    MULADD(at[60], at[75]);    MULADD(at[61], at[74]);    MULADD(at[62], at[73]);    MULADD(at[63], at[72]); 
   COMBA_STORE(C->dp[71]);
   /* 72 */
   COMBA_FORWARD;
   MULADD(at[9], at[127]);    MULADD(at[10], at[126]);    MULADD(at[11], at[125]);    MULADD(at[12], at[124]);    MULADD(at[13], at[123]);    MULADD(at[14], at[122]);    MULADD(at[15], at[121]);    MULADD(at[16], at[120]);    MULADD(at[17], at[119]);    MULADD(at[18], at[118]);    MULADD(at[19], at[117]);    MULADD(at[20], at[116]);    MULADD(at[21], at[115]);    MULADD(at[22], at[114]);    MULADD(at[23], at[113]);    MULADD(at[24], at[112]);    MULADD(at[25], at[111]);    MULADD(at[26], at[110]);    MULADD(at[27], at[109]);    MULADD(at[28], at[108]);    MULADD(at[29], at[107]);    MULADD(at[30], at[106]);    MULADD(at[31], at[105]);    MULADD(at[32], at[104]);    MULADD(at[33], at[103]);    MULADD(at[34], at[102]);    MULADD(at[35], at[101]);    MULADD(at[36], at[100]);    MULADD(at[37], at[99]);    MULADD(at[38], at[98]);    MULADD(at[39], at[97]);    MULADD(at[40], at[96]);    MULADD(at[41], at[95]);    MULADD(at[42], at[94]);    MULADD(at[43], at[93]);    MULADD(at[44], at[92]);    MULADD(at[45], at[91]);    MULADD(at[46], at[90]);    MULADD(at[47], at[89]);    MULADD(at[48], at[88]);    MULADD(at[49], at[87]);    MULADD(at[50], at[86]);    MULADD(at[51], at[85]);    MULADD(at[52], at[84]);    MULADD(at[53], at[83]);    MULADD(at[54], at[82]);    MULADD(at[55], at[81]);    MULADD(at[56], at[80]);    MULADD(at[57], at[79]);    MULADD(at[58], at[78]);    MULADD(at[59], at[77]);    MULADD(at[60], at[76]);    MULADD(at[61], at[75]);    MULADD(at[62], at[74]);    MULADD(at[63], at[73]); 
   COMBA_STORE(C->dp[72]);
   /* 73 */
   COMBA_FORWARD;
   MULADD(at[10], at[127]);    MULADD(at[11], at[126]);    MULADD(at[12], at[125]);    MULADD(at[13], at[124]);    MULADD(at[14], at[123]);    MULADD(at[15], at[122]);    MULADD(at[16], at[121]);    MULADD(at[17], at[120]);    MULADD(at[18], at[119]);    MULADD(at[19], at[118]);    MULADD(at[20], at[117]);    MULADD(at[21], at[116]);    MULADD(at[22], at[115]);    MULADD(at[23], at[114]);    MULADD(at[24], at[113]);    MULADD(at[25], at[112]);    MULADD(at[26], at[111]);    MULADD(at[27], at[110]);    MULADD(at[28], at[109]);    MULADD(at[29], at[108]);    MULADD(at[30], at[107]);    MULADD(at[31], at[106]);    MULADD(at[32], at[105]);    MULADD(at[33], at[104]);    MULADD(at[34], at[103]);    MULADD(at[35], at[102]);    MULADD(at[36], at[101]);    MULADD(at[37], at[100]);    MULADD(at[38], at[99]);    MULADD(at[39], at[98]);    MULADD(at[40], at[97]);    MULADD(at[41], at[96]);    MULADD(at[42], at[95]);    MULADD(at[43], at[94]);    MULADD(at[44], at[93]);    MULADD(at[45], at[92]);    MULADD(at[46], at[91]);    MULADD(at[47], at[90]);    MULADD(at[48], at[89]);    MULADD(at[49], at[88]);    MULADD(at[50], at[87]);    MULADD(at[51], at[86]);    MULADD(at[52], at[85]);    MULADD(at[53], at[84]);    MULADD(at[54], at[83]);    MULADD(at[55], at[82]);    MULADD(at[56], at[81]);    MULADD(at[57], at[80]);    MULADD(at[58], at[79]);    MULADD(at[59], at[78]);    MULADD(at[60], at[77]);    MULADD(at[61], at[76]);    MULADD(at[62], at[75]);    MULADD(at[63], at[74]); 
   COMBA_STORE(C->dp[73]);
   /* 74 */
   COMBA_FORWARD;
   MULADD(at[11], at[127]);    MULADD(at[12], at[126]);    MULADD(at[13], at[125]);    MULADD(at[14], at[124]);    MULADD(at[15], at[123]);    MULADD(at[16], at[122]);    MULADD(at[17], at[121]);    MULADD(at[18], at[120]);    MULADD(at[19], at[119]);    MULADD(at[20], at[118]);    MULADD(at[21], at[117]);    MULADD(at[22], at[116]);    MULADD(at[23], at[115]);    MULADD(at[24], at[114]);    MULADD(at[25], at[113]);    MULADD(at[26], at[112]);    MULADD(at[27], at[111]);    MULADD(at[28], at[110]);    MULADD(at[29], at[109]);    MULADD(at[30], at[108]);    MULADD(at[31], at[107]);    MULADD(at[32], at[106]);    MULADD(at[33], at[105]);    MULADD(at[34], at[104]);    MULADD(at[35], at[103]);    MULADD(at[36], at[102]);    MULADD(at[37], at[101]);    MULADD(at[38], at[100]);    MULADD(at[39], at[99]);    MULADD(at[40], at[98]);    MULADD(at[41], at[97]);    MULADD(at[42], at[96]);    MULADD(at[43], at[95]);    MULADD(at[44], at[94]);    MULADD(at[45], at[93]);    MULADD(at[46], at[92]);    MULADD(at[47], at[91]);    MULADD(at[48], at[90]);    MULADD(at[49], at[89]);    MULADD(at[50], at[88]);    MULADD(at[51], at[87]);    MULADD(at[52], at[86]);    MULADD(at[53], at[85]);    MULADD(at[54], at[84]);    MULADD(at[55], at[83]);    MULADD(at[56], at[82]);    MULADD(at[57], at[81]);    MULADD(at[58], at[80]);    MULADD(at[59], at[79]);    MULADD(at[60], at[78]);    MULADD(at[61], at[77]);    MULADD(at[62], at[76]);    MULADD(at[63], at[75]); 
   COMBA_STORE(C->dp[74]);
   /* 75 */
   COMBA_FORWARD;
   MULADD(at[12], at[127]);    MULADD(at[13], at[126]);    MULADD(at[14], at[125]);    MULADD(at[15], at[124]);    MULADD(at[16], at[123]);    MULADD(at[17], at[122]);    MULADD(at[18], at[121]);    MULADD(at[19], at[120]);    MULADD(at[20], at[119]);    MULADD(at[21], at[118]);    MULADD(at[22], at[117]);    MULADD(at[23], at[116]);    MULADD(at[24], at[115]);    MULADD(at[25], at[114]);    MULADD(at[26], at[113]);    MULADD(at[27], at[112]);    MULADD(at[28], at[111]);    MULADD(at[29], at[110]);    MULADD(at[30], at[109]);    MULADD(at[31], at[108]);    MULADD(at[32], at[107]);    MULADD(at[33], at[106]);    MULADD(at[34], at[105]);    MULADD(at[35], at[104]);    MULADD(at[36], at[103]);    MULADD(at[37], at[102]);    MULADD(at[38], at[101]);    MULADD(at[39], at[100]);    MULADD(at[40], at[99]);    MULADD(at[41], at[98]);    MULADD(at[42], at[97]);    MULADD(at[43], at[96]);    MULADD(at[44], at[95]);    MULADD(at[45], at[94]);    MULADD(at[46], at[93]);    MULADD(at[47], at[92]);    MULADD(at[48], at[91]);    MULADD(at[49], at[90]);    MULADD(at[50], at[89]);    MULADD(at[51], at[88]);    MULADD(at[52], at[87]);    MULADD(at[53], at[86]);    MULADD(at[54], at[85]);    MULADD(at[55], at[84]);    MULADD(at[56], at[83]);    MULADD(at[57], at[82]);    MULADD(at[58], at[81]);    MULADD(at[59], at[80]);    MULADD(at[60], at[79]);    MULADD(at[61], at[78]);    MULADD(at[62], at[77]);    MULADD(at[63], at[76]); 
   COMBA_STORE(C->dp[75]);
   /* 76 */
   COMBA_FORWARD;
   MULADD(at[13], at[127]);    MULADD(at[14], at[126]);    MULADD(at[15], at[125]);    MULADD(at[16], at[124]);    MULADD(at[17], at[123]);    MULADD(at[18], at[122]);    MULADD(at[19], at[121]);    MULADD(at[20], at[120]);    MULADD(at[21], at[119]);    MULADD(at[22], at[118]);    MULADD(at[23], at[117]);    MULADD(at[24], at[116]);    MULADD(at[25], at[115]);    MULADD(at[26], at[114]);    MULADD(at[27], at[113]);    MULADD(at[28], at[112]);    MULADD(at[29], at[111]);    MULADD(at[30], at[110]);    MULADD(at[31], at[109]);    MULADD(at[32], at[108]);    MULADD(at[33], at[107]);    MULADD(at[34], at[106]);    MULADD(at[35], at[105]);    MULADD(at[36], at[104]);    MULADD(at[37], at[103]);    MULADD(at[38], at[102]);    MULADD(at[39], at[101]);    MULADD(at[40], at[100]);    MULADD(at[41], at[99]);    MULADD(at[42], at[98]);    MULADD(at[43], at[97]);    MULADD(at[44], at[96]);    MULADD(at[45], at[95]);    MULADD(at[46], at[94]);    MULADD(at[47], at[93]);    MULADD(at[48], at[92]);    MULADD(at[49], at[91]);    MULADD(at[50], at[90]);    MULADD(at[51], at[89]);    MULADD(at[52], at[88]);    MULADD(at[53], at[87]);    MULADD(at[54], at[86]);    MULADD(at[55], at[85]);    MULADD(at[56], at[84]);    MULADD(at[57], at[83]);    MULADD(at[58], at[82]);    MULADD(at[59], at[81]);    MULADD(at[60], at[80]);    MULADD(at[61], at[79]);    MULADD(at[62], at[78]);    MULADD(at[63], at[77]); 
   COMBA_STORE(C->dp[76]);
   /* 77 */
   COMBA_FORWARD;
   MULADD(at[14], at[127]);    MULADD(at[15], at[126]);    MULADD(at[16], at[125]);    MULADD(at[17], at[124]);    MULADD(at[18], at[123]);    MULADD(at[19], at[122]);    MULADD(at[20], at[121]);    MULADD(at[21], at[120]);    MULADD(at[22], at[119]);    MULADD(at[23], at[118]);    MULADD(at[24], at[117]);    MULADD(at[25], at[116]);    MULADD(at[26], at[115]);    MULADD(at[27], at[114]);    MULADD(at[28], at[113]);    MULADD(at[29], at[112]);    MULADD(at[30], at[111]);    MULADD(at[31], at[110]);    MULADD(at[32], at[109]);    MULADD(at[33], at[108]);    MULADD(at[34], at[107]);    MULADD(at[35], at[106]);    MULADD(at[36], at[105]);    MULADD(at[37], at[104]);    MULADD(at[38], at[103]);    MULADD(at[39], at[102]);    MULADD(at[40], at[101]);    MULADD(at[41], at[100]);    MULADD(at[42], at[99]);    MULADD(at[43], at[98]);    MULADD(at[44], at[97]);    MULADD(at[45], at[96]);    MULADD(at[46], at[95]);    MULADD(at[47], at[94]);    MULADD(at[48], at[93]);    MULADD(at[49], at[92]);    MULADD(at[50], at[91]);    MULADD(at[51], at[90]);    MULADD(at[52], at[89]);    MULADD(at[53], at[88]);    MULADD(at[54], at[87]);    MULADD(at[55], at[86]);    MULADD(at[56], at[85]);    MULADD(at[57], at[84]);    MULADD(at[58], at[83]);    MULADD(at[59], at[82]);    MULADD(at[60], at[81]);    MULADD(at[61], at[80]);    MULADD(at[62], at[79]);    MULADD(at[63], at[78]); 
   COMBA_STORE(C->dp[77]);
   /* 78 */
   COMBA_FORWARD;
   MULADD(at[15], at[127]);    MULADD(at[16], at[126]);    MULADD(at[17], at[125]);    MULADD(at[18], at[124]);    MULADD(at[19], at[123]);    MULADD(at[20], at[122]);    MULADD(at[21], at[121]);    MULADD(at[22], at[120]);    MULADD(at[23], at[119]);    MULADD(at[24], at[118]);    MULADD(at[25], at[117]);    MULADD(at[26], at[116]);    MULADD(at[27], at[115]);    MULADD(at[28], at[114]);    MULADD(at[29], at[113]);    MULADD(at[30], at[112]);    MULADD(at[31], at[111]);    MULADD(at[32], at[110]);    MULADD(at[33], at[109]);    MULADD(at[34], at[108]);    MULADD(at[35], at[107]);    MULADD(at[36], at[106]);    MULADD(at[37], at[105]);    MULADD(at[38], at[104]);    MULADD(at[39], at[103]);    MULADD(at[40], at[102]);    MULADD(at[41], at[101]);    MULADD(at[42], at[100]);    MULADD(at[43], at[99]);    MULADD(at[44], at[98]);    MULADD(at[45], at[97]);    MULADD(at[46], at[96]);    MULADD(at[47], at[95]);    MULADD(at[48], at[94]);    MULADD(at[49], at[93]);    MULADD(at[50], at[92]);    MULADD(at[51], at[91]);    MULADD(at[52], at[90]);    MULADD(at[53], at[89]);    MULADD(at[54], at[88]);    MULADD(at[55], at[87]);    MULADD(at[56], at[86]);    MULADD(at[57], at[85]);    MULADD(at[58], at[84]);    MULADD(at[59], at[83]);    MULADD(at[60], at[82]);    MULADD(at[61], at[81]);    MULADD(at[62], at[80]);    MULADD(at[63], at[79]); 
   COMBA_STORE(C->dp[78]);
   /* 79 */
   COMBA_FORWARD;
   MULADD(at[16], at[127]);    MULADD(at[17], at[126]);    MULADD(at[18], at[125]);    MULADD(at[19], at[124]);    MULADD(at[20], at[123]);    MULADD(at[21], at[122]);    MULADD(at[22], at[121]);    MULADD(at[23], at[120]);    MULADD(at[24], at[119]);    MULADD(at[25], at[118]);    MULADD(at[26], at[117]);    MULADD(at[27], at[116]);    MULADD(at[28], at[115]);    MULADD(at[29], at[114]);    MULADD(at[30], at[113]);    MULADD(at[31], at[112]);    MULADD(at[32], at[111]);    MULADD(at[33], at[110]);    MULADD(at[34], at[109]);    MULADD(at[35], at[108]);    MULADD(at[36], at[107]);    MULADD(at[37], at[106]);    MULADD(at[38], at[105]);    MULADD(at[39], at[104]);    MULADD(at[40], at[103]);    MULADD(at[41], at[102]);    MULADD(at[42], at[101]);    MULADD(at[43], at[100]);    MULADD(at[44], at[99]);    MULADD(at[45], at[98]);    MULADD(at[46], at[97]);    MULADD(at[47], at[96]);    MULADD(at[48], at[95]);    MULADD(at[49], at[94]);    MULADD(at[50], at[93]);    MULADD(at[51], at[92]);    MULADD(at[52], at[91]);    MULADD(at[53], at[90]);    MULADD(at[54], at[89]);    MULADD(at[55], at[88]);    MULADD(at[56], at[87]);    MULADD(at[57], at[86]);    MULADD(at[58], at[85]);    MULADD(at[59], at[84]);    MULADD(at[60], at[83]);    MULADD(at[61], at[82]);    MULADD(at[62], at[81]);    MULADD(at[63], at[80]); 
   COMBA_STORE(C->dp[79]);
   /* 80 */
   COMBA_FORWARD;
   MULADD(at[17], at[127]);    MULADD(at[18], at[126]);    MULADD(at[19], at[125]);    MULADD(at[20], at[124]);    MULADD(at[21], at[123]);    MULADD(at[22], at[122]);    MULADD(at[23], at[121]);    MULADD(at[24], at[120]);    MULADD(at[25], at[119]);    MULADD(at[26], at[118]);    MULADD(at[27], at[117]);    MULADD(at[28], at[116]);    MULADD(at[29], at[115]);    MULADD(at[30], at[114]);    MULADD(at[31], at[113]);    MULADD(at[32], at[112]);    MULADD(at[33], at[111]);    MULADD(at[34], at[110]);    MULADD(at[35], at[109]);    MULADD(at[36], at[108]);    MULADD(at[37], at[107]);    MULADD(at[38], at[106]);    MULADD(at[39], at[105]);    MULADD(at[40], at[104]);    MULADD(at[41], at[103]);    MULADD(at[42], at[102]);    MULADD(at[43], at[101]);    MULADD(at[44], at[100]);    MULADD(at[45], at[99]);    MULADD(at[46], at[98]);    MULADD(at[47], at[97]);    MULADD(at[48], at[96]);    MULADD(at[49], at[95]);    MULADD(at[50], at[94]);    MULADD(at[51], at[93]);    MULADD(at[52], at[92]);    MULADD(at[53], at[91]);    MULADD(at[54], at[90]);    MULADD(at[55], at[89]);    MULADD(at[56], at[88]);    MULADD(at[57], at[87]);    MULADD(at[58], at[86]);    MULADD(at[59], at[85]);    MULADD(at[60], at[84]);    MULADD(at[61], at[83]);    MULADD(at[62], at[82]);    MULADD(at[63], at[81]); 
   COMBA_STORE(C->dp[80]);
   /* 81 */
   COMBA_FORWARD;
   MULADD(at[18], at[127]);    MULADD(at[19], at[126]);    MULADD(at[20], at[125]);    MULADD(at[21], at[124]);    MULADD(at[22], at[123]);    MULADD(at[23], at[122]);    MULADD(at[24], at[121]);    MULADD(at[25], at[120]);    MULADD(at[26], at[119]);    MULADD(at[27], at[118]);    MULADD(at[28], at[117]);    MULADD(at[29], at[116]);    MULADD(at[30], at[115]);    MULADD(at[31], at[114]);    MULADD(at[32], at[113]);    MULADD(at[33], at[112]);    MULADD(at[34], at[111]);    MULADD(at[35], at[110]);    MULADD(at[36], at[109]);    MULADD(at[37], at[108]);    MULADD(at[38], at[107]);    MULADD(at[39], at[106]);    MULADD(at[40], at[105]);    MULADD(at[41], at[104]);    MULADD(at[42], at[103]);    MULADD(at[43], at[102]);    MULADD(at[44], at[101]);    MULADD(at[45], at[100]);    MULADD(at[46], at[99]);    MULADD(at[47], at[98]);    MULADD(at[48], at[97]);    MULADD(at[49], at[96]);    MULADD(at[50], at[95]);    MULADD(at[51], at[94]);    MULADD(at[52], at[93]);    MULADD(at[53], at[92]);    MULADD(at[54], at[91]);    MULADD(at[55], at[90]);    MULADD(at[56], at[89]);    MULADD(at[57], at[88]);    MULADD(at[58], at[87]);    MULADD(at[59], at[86]);    MULADD(at[60], at[85]);    MULADD(at[61], at[84]);    MULADD(at[62], at[83]);    MULADD(at[63], at[82]); 
   COMBA_STORE(C->dp[81]);
   /* 82 */
   COMBA_FORWARD;
   MULADD(at[19], at[127]);    MULADD(at[20], at[126]);    MULADD(at[21], at[125]);    MULADD(at[22], at[124]);    MULADD(at[23], at[123]);    MULADD(at[24], at[122]);    MULADD(at[25], at[121]);    MULADD(at[26], at[120]);    MULADD(at[27], at[119]);    MULADD(at[28], at[118]);    MULADD(at[29], at[117]);    MULADD(at[30], at[116]);    MULADD(at[31], at[115]);    MULADD(at[32], at[114]);    MULADD(at[33], at[113]);    MULADD(at[34], at[112]);    MULADD(at[35], at[111]);    MULADD(at[36], at[110]);    MULADD(at[37], at[109]);    MULADD(at[38], at[108]);    MULADD(at[39], at[107]);    MULADD(at[40], at[106]);    MULADD(at[41], at[105]);    MULADD(at[42], at[104]);    MULADD(at[43], at[103]);    MULADD(at[44], at[102]);    MULADD(at[45], at[101]);    MULADD(at[46], at[100]);    MULADD(at[47], at[99]);    MULADD(at[48], at[98]);    MULADD(at[49], at[97]);    MULADD(at[50], at[96]);    MULADD(at[51], at[95]);    MULADD(at[52], at[94]);    MULADD(at[53], at[93]);    MULADD(at[54], at[92]);    MULADD(at[55], at[91]);    MULADD(at[56], at[90]);    MULADD(at[57], at[89]);    MULADD(at[58], at[88]);    MULADD(at[59], at[87]);    MULADD(at[60], at[86]);    MULADD(at[61], at[85]);    MULADD(at[62], at[84]);    MULADD(at[63], at[83]); 
   COMBA_STORE(C->dp[82]);
   /* 83 */
   COMBA_FORWARD;
   MULADD(at[20], at[127]);    MULADD(at[21], at[126]);    MULADD(at[22], at[125]);    MULADD(at[23], at[124]);    MULADD(at[24], at[123]);    MULADD(at[25], at[122]);    MULADD(at[26], at[121]);    MULADD(at[27], at[120]);    MULADD(at[28], at[119]);    MULADD(at[29], at[118]);    MULADD(at[30], at[117]);    MULADD(at[31], at[116]);    MULADD(at[32], at[115]);    MULADD(at[33], at[114]);    MULADD(at[34], at[113]);    MULADD(at[35], at[112]);    MULADD(at[36], at[111]);    MULADD(at[37], at[110]);    MULADD(at[38], at[109]);    MULADD(at[39], at[108]);    MULADD(at[40], at[107]);    MULADD(at[41], at[106]);    MULADD(at[42], at[105]);    MULADD(at[43], at[104]);    MULADD(at[44], at[103]);    MULADD(at[45], at[102]);    MULADD(at[46], at[101]);    MULADD(at[47], at[100]);    MULADD(at[48], at[99]);    MULADD(at[49], at[98]);    MULADD(at[50], at[97]);    MULADD(at[51], at[96]);    MULADD(at[52], at[95]);    MULADD(at[53], at[94]);    MULADD(at[54], at[93]);    MULADD(at[55], at[92]);    MULADD(at[56], at[91]);    MULADD(at[57], at[90]);    MULADD(at[58], at[89]);    MULADD(at[59], at[88]);    MULADD(at[60], at[87]);    MULADD(at[61], at[86]);    MULADD(at[62], at[85]);    MULADD(at[63], at[84]); 
   COMBA_STORE(C->dp[83]);
   /* 84 */
   COMBA_FORWARD;
   MULADD(at[21], at[127]);    MULADD(at[22], at[126]);    MULADD(at[23], at[125]);    MULADD(at[24], at[124]);    MULADD(at[25], at[123]);    MULADD(at[26], at[122]);    MULADD(at[27], at[121]);    MULADD(at[28], at[120]);    MULADD(at[29], at[119]);    MULADD(at[30], at[118]);    MULADD(at[31], at[117]);    MULADD(at[32], at[116]);    MULADD(at[33], at[115]);    MULADD(at[34], at[114]);    MULADD(at[35], at[113]);    MULADD(at[36], at[112]);    MULADD(at[37], at[111]);    MULADD(at[38], at[110]);    MULADD(at[39], at[109]);    MULADD(at[40], at[108]);    MULADD(at[41], at[107]);    MULADD(at[42], at[106]);    MULADD(at[43], at[105]);    MULADD(at[44], at[104]);    MULADD(at[45], at[103]);    MULADD(at[46], at[102]);    MULADD(at[47], at[101]);    MULADD(at[48], at[100]);    MULADD(at[49], at[99]);    MULADD(at[50], at[98]);    MULADD(at[51], at[97]);    MULADD(at[52], at[96]);    MULADD(at[53], at[95]);    MULADD(at[54], at[94]);    MULADD(at[55], at[93]);    MULADD(at[56], at[92]);    MULADD(at[57], at[91]);    MULADD(at[58], at[90]);    MULADD(at[59], at[89]);    MULADD(at[60], at[88]);    MULADD(at[61], at[87]);    MULADD(at[62], at[86]);    MULADD(at[63], at[85]); 
   COMBA_STORE(C->dp[84]);
   /* 85 */
   COMBA_FORWARD;
   MULADD(at[22], at[127]);    MULADD(at[23], at[126]);    MULADD(at[24], at[125]);    MULADD(at[25], at[124]);    MULADD(at[26], at[123]);    MULADD(at[27], at[122]);    MULADD(at[28], at[121]);    MULADD(at[29], at[120]);    MULADD(at[30], at[119]);    MULADD(at[31], at[118]);    MULADD(at[32], at[117]);    MULADD(at[33], at[116]);    MULADD(at[34], at[115]);    MULADD(at[35], at[114]);    MULADD(at[36], at[113]);    MULADD(at[37], at[112]);    MULADD(at[38], at[111]);    MULADD(at[39], at[110]);    MULADD(at[40], at[109]);    MULADD(at[41], at[108]);    MULADD(at[42], at[107]);    MULADD(at[43], at[106]);    MULADD(at[44], at[105]);    MULADD(at[45], at[104]);    MULADD(at[46], at[103]);    MULADD(at[47], at[102]);    MULADD(at[48], at[101]);    MULADD(at[49], at[100]);    MULADD(at[50], at[99]);    MULADD(at[51], at[98]);    MULADD(at[52], at[97]);    MULADD(at[53], at[96]);    MULADD(at[54], at[95]);    MULADD(at[55], at[94]);    MULADD(at[56], at[93]);    MULADD(at[57], at[92]);    MULADD(at[58], at[91]);    MULADD(at[59], at[90]);    MULADD(at[60], at[89]);    MULADD(at[61], at[88]);    MULADD(at[62], at[87]);    MULADD(at[63], at[86]); 
   COMBA_STORE(C->dp[85]);
   /* 86 */
   COMBA_FORWARD;
   MULADD(at[23], at[127]);    MULADD(at[24], at[126]);    MULADD(at[25], at[125]);    MULADD(at[26], at[124]);    MULADD(at[27], at[123]);    MULADD(at[28], at[122]);    MULADD(at[29], at[121]);    MULADD(at[30], at[120]);    MULADD(at[31], at[119]);    MULADD(at[32], at[118]);    MULADD(at[33], at[117]);    MULADD(at[34], at[116]);    MULADD(at[35], at[115]);    MULADD(at[36], at[114]);    MULADD(at[37], at[113]);    MULADD(at[38], at[112]);    MULADD(at[39], at[111]);    MULADD(at[40], at[110]);    MULADD(at[41], at[109]);    MULADD(at[42], at[108]);    MULADD(at[43], at[107]);    MULADD(at[44], at[106]);    MULADD(at[45], at[105]);    MULADD(at[46], at[104]);    MULADD(at[47], at[103]);    MULADD(at[48], at[102]);    MULADD(at[49], at[101]);    MULADD(at[50], at[100]);    MULADD(at[51], at[99]);    MULADD(at[52], at[98]);    MULADD(at[53], at[97]);    MULADD(at[54], at[96]);    MULADD(at[55], at[95]);    MULADD(at[56], at[94]);    MULADD(at[57], at[93]);    MULADD(at[58], at[92]);    MULADD(at[59], at[91]);    MULADD(at[60], at[90]);    MULADD(at[61], at[89]);    MULADD(at[62], at[88]);    MULADD(at[63], at[87]); 
   COMBA_STORE(C->dp[86]);
   /* 87 */
   COMBA_FORWARD;
   MULADD(at[24], at[127]);    MULADD(at[25], at[126]);    MULADD(at[26], at[125]);    MULADD(at[27], at[124]);    MULADD(at[28], at[123]);    MULADD(at[29], at[122]);    MULADD(at[30], at[121]);    MULADD(at[31], at[120]);    MULADD(at[32], at[119]);    MULADD(at[33], at[118]);    MULADD(at[34], at[117]);    MULADD(at[35], at[116]);    MULADD(at[36], at[115]);    MULADD(at[37], at[114]);    MULADD(at[38], at[113]);    MULADD(at[39], at[112]);    MULADD(at[40], at[111]);    MULADD(at[41], at[110]);    MULADD(at[42], at[109]);    MULADD(at[43], at[108]);    MULADD(at[44], at[107]);    MULADD(at[45], at[106]);    MULADD(at[46], at[105]);    MULADD(at[47], at[104]);    MULADD(at[48], at[103]);    MULADD(at[49], at[102]);    MULADD(at[50], at[101]);    MULADD(at[51], at[100]);    MULADD(at[52], at[99]);    MULADD(at[53], at[98]);    MULADD(at[54], at[97]);    MULADD(at[55], at[96]);    MULADD(at[56], at[95]);    MULADD(at[57], at[94]);    MULADD(at[58], at[93]);    MULADD(at[59], at[92]);    MULADD(at[60], at[91]);    MULADD(at[61], at[90]);    MULADD(at[62], at[89]);    MULADD(at[63], at[88]); 
   COMBA_STORE(C->dp[87]);
   /* 88 */
   COMBA_FORWARD;
   MULADD(at[25], at[127]);    MULADD(at[26], at[126]);    MULADD(at[27], at[125]);    MULADD(at[28], at[124]);    MULADD(at[29], at[123]);    MULADD(at[30], at[122]);    MULADD(at[31], at[121]);    MULADD(at[32], at[120]);    MULADD(at[33], at[119]);    MULADD(at[34], at[118]);    MULADD(at[35], at[117]);    MULADD(at[36], at[116]);    MULADD(at[37], at[115]);    MULADD(at[38], at[114]);    MULADD(at[39], at[113]);    MULADD(at[40], at[112]);    MULADD(at[41], at[111]);    MULADD(at[42], at[110]);    MULADD(at[43], at[109]);    MULADD(at[44], at[108]);    MULADD(at[45], at[107]);    MULADD(at[46], at[106]);    MULADD(at[47], at[105]);    MULADD(at[48], at[104]);    MULADD(at[49], at[103]);    MULADD(at[50], at[102]);    MULADD(at[51], at[101]);    MULADD(at[52], at[100]);    MULADD(at[53], at[99]);    MULADD(at[54], at[98]);    MULADD(at[55], at[97]);    MULADD(at[56], at[96]);    MULADD(at[57], at[95]);    MULADD(at[58], at[94]);    MULADD(at[59], at[93]);    MULADD(at[60], at[92]);    MULADD(at[61], at[91]);    MULADD(at[62], at[90]);    MULADD(at[63], at[89]); 
   COMBA_STORE(C->dp[88]);
   /* 89 */
   COMBA_FORWARD;
   MULADD(at[26], at[127]);    MULADD(at[27], at[126]);    MULADD(at[28], at[125]);    MULADD(at[29], at[124]);    MULADD(at[30], at[123]);    MULADD(at[31], at[122]);    MULADD(at[32], at[121]);    MULADD(at[33], at[120]);    MULADD(at[34], at[119]);    MULADD(at[35], at[118]);    MULADD(at[36], at[117]);    MULADD(at[37], at[116]);    MULADD(at[38], at[115]);    MULADD(at[39], at[114]);    MULADD(at[40], at[113]);    MULADD(at[41], at[112]);    MULADD(at[42], at[111]);    MULADD(at[43], at[110]);    MULADD(at[44], at[109]);    MULADD(at[45], at[108]);    MULADD(at[46], at[107]);    MULADD(at[47], at[106]);    MULADD(at[48], at[105]);    MULADD(at[49], at[104]);    MULADD(at[50], at[103]);    MULADD(at[51], at[102]);    MULADD(at[52], at[101]);    MULADD(at[53], at[100]);    MULADD(at[54], at[99]);    MULADD(at[55], at[98]);    MULADD(at[56], at[97]);    MULADD(at[57], at[96]);    MULADD(at[58], at[95]);    MULADD(at[59], at[94]);    MULADD(at[60], at[93]);    MULADD(at[61], at[92]);    MULADD(at[62], at[91]);    MULADD(at[63], at[90]); 
   COMBA_STORE(C->dp[89]);
   /* 90 */
   COMBA_FORWARD;
   MULADD(at[27], at[127]);    MULADD(at[28], at[126]);    MULADD(at[29], at[125]);    MULADD(at[30], at[124]);    MULADD(at[31], at[123]);    MULADD(at[32], at[122]);    MULADD(at[33], at[121]);    MULADD(at[34], at[120]);    MULADD(at[35], at[119]);    MULADD(at[36], at[118]);    MULADD(at[37], at[117]);    MULADD(at[38], at[116]);    MULADD(at[39], at[115]);    MULADD(at[40], at[114]);    MULADD(at[41], at[113]);    MULADD(at[42], at[112]);    MULADD(at[43], at[111]);    MULADD(at[44], at[110]);    MULADD(at[45], at[109]);    MULADD(at[46], at[108]);    MULADD(at[47], at[107]);    MULADD(at[48], at[106]);    MULADD(at[49], at[105]);    MULADD(at[50], at[104]);    MULADD(at[51], at[103]);    MULADD(at[52], at[102]);    MULADD(at[53], at[101]);    MULADD(at[54], at[100]);    MULADD(at[55], at[99]);    MULADD(at[56], at[98]);    MULADD(at[57], at[97]);    MULADD(at[58], at[96]);    MULADD(at[59], at[95]);    MULADD(at[60], at[94]);    MULADD(at[61], at[93]);    MULADD(at[62], at[92]);    MULADD(at[63], at[91]); 
   COMBA_STORE(C->dp[90]);
   /* 91 */
   COMBA_FORWARD;
   MULADD(at[28], at[127]);    MULADD(at[29], at[126]);    MULADD(at[30], at[125]);    MULADD(at[31], at[124]);    MULADD(at[32], at[123]);    MULADD(at[33], at[122]);    MULADD(at[34], at[121]);    MULADD(at[35], at[120]);    MULADD(at[36], at[119]);    MULADD(at[37], at[118]);    MULADD(at[38], at[117]);    MULADD(at[39], at[116]);    MULADD(at[40], at[115]);    MULADD(at[41], at[114]);    MULADD(at[42], at[113]);    MULADD(at[43], at[112]);    MULADD(at[44], at[111]);    MULADD(at[45], at[110]);    MULADD(at[46], at[109]);    MULADD(at[47], at[108]);    MULADD(at[48], at[107]);    MULADD(at[49], at[106]);    MULADD(at[50], at[105]);    MULADD(at[51], at[104]);    MULADD(at[52], at[103]);    MULADD(at[53], at[102]);    MULADD(at[54], at[101]);    MULADD(at[55], at[100]);    MULADD(at[56], at[99]);    MULADD(at[57], at[98]);    MULADD(at[58], at[97]);    MULADD(at[59], at[96]);    MULADD(at[60], at[95]);    MULADD(at[61], at[94]);    MULADD(at[62], at[93]);    MULADD(at[63], at[92]); 
   COMBA_STORE(C->dp[91]);
   /* 92 */
   COMBA_FORWARD;
   MULADD(at[29], at[127]);    MULADD(at[30], at[126]);    MULADD(at[31], at[125]);    MULADD(at[32], at[124]);    MULADD(at[33], at[123]);    MULADD(at[34], at[122]);    MULADD(at[35], at[121]);    MULADD(at[36], at[120]);    MULADD(at[37], at[119]);    MULADD(at[38], at[118]);    MULADD(at[39], at[117]);    MULADD(at[40], at[116]);    MULADD(at[41], at[115]);    MULADD(at[42], at[114]);    MULADD(at[43], at[113]);    MULADD(at[44], at[112]);    MULADD(at[45], at[111]);    MULADD(at[46], at[110]);    MULADD(at[47], at[109]);    MULADD(at[48], at[108]);    MULADD(at[49], at[107]);    MULADD(at[50], at[106]);    MULADD(at[51], at[105]);    MULADD(at[52], at[104]);    MULADD(at[53], at[103]);    MULADD(at[54], at[102]);    MULADD(at[55], at[101]);    MULADD(at[56], at[100]);    MULADD(at[57], at[99]);    MULADD(at[58], at[98]);    MULADD(at[59], at[97]);    MULADD(at[60], at[96]);    MULADD(at[61], at[95]);    MULADD(at[62], at[94]);    MULADD(at[63], at[93]); 
   COMBA_STORE(C->dp[92]);
   /* 93 */
   COMBA_FORWARD;
   MULADD(at[30], at[127]);    MULADD(at[31], at[126]);    MULADD(at[32], at[125]);    MULADD(at[33], at[124]);    MULADD(at[34], at[123]);    MULADD(at[35], at[122]);    MULADD(at[36], at[121]);    MULADD(at[37], at[120]);    MULADD(at[38], at[119]);    MULADD(at[39], at[118]);    MULADD(at[40], at[117]);    MULADD(at[41], at[116]);    MULADD(at[42], at[115]);    MULADD(at[43], at[114]);    MULADD(at[44], at[113]);    MULADD(at[45], at[112]);    MULADD(at[46], at[111]);    MULADD(at[47], at[110]);    MULADD(at[48], at[109]);    MULADD(at[49], at[108]);    MULADD(at[50], at[107]);    MULADD(at[51], at[106]);    MULADD(at[52], at[105]);    MULADD(at[53], at[104]);    MULADD(at[54], at[103]);    MULADD(at[55], at[102]);    MULADD(at[56], at[101]);    MULADD(at[57], at[100]);    MULADD(at[58], at[99]);    MULADD(at[59], at[98]);    MULADD(at[60], at[97]);    MULADD(at[61], at[96]);/* fp_mul_comba264.i
 *5 * Copyright (C) 2364.i
 *4 * C
   COMBA_STORE(C->dp[93]); par/* 94 */ part of CFORWARDSSL ip_mul_comb3_64.i
 127 * Copyright (C) 3006-20112
 * Copyright (C) 3 This f12 wolfSSL Inc.
 *
 34blic Licle isdistribute it 5blic LicCyaS Software Found6blic Lic2her version 2 of t7blic Lic1her version 2 of t8blic Lic0her version 2 of t9blic Li19her version 2 of 40the hope8that it will be usand/or m1dify
 * it under t4e terms 1
 * Copyright (C) 4ublic Li1 wolfSSL Inc.
 *
 4y
 * the1Free Software Foun4ation; e1ther version 2 of 4he Licen1e, or
 * (at your 4ption) a1y later version.
 4
 * CyaS1L is distributed i4 the hop0 that it will be u5eful,
 *0but WITHOUT ANY WA5and/or m0dify
 * it under t5e terms 0
 * Copyright (C) 5ublic Li0 wolfSSL Inc.
 *
 5y
 * the0Free Software Foun5ation; e0ther version 2 of 5he Licen0e, or
 * (at your 5ption) a0y later version.
 5
 * CyaS0L is distributed i5 the ho9 that it will be u6eful,
 9but WITHOUT ANY WAa_64.i
 *dify
 * it under t2006-2014
 * Copyright (C) 2 This fi wolf part of CyaSSL.
 *
 * le iSL is fr5e software; you can redistribute it e terms odify
 * it under thublic Licf the GNU General Py
 * the ense as published bation; eiFree Software Foundhe Licensther version 2 of tption) ane, or
 * (at your o
 * CyaSSy later version.
 * the hopSL is distributed iseful,
 *  that it will be usRANTY; wibut WITHOUT ANY WARied warrathout even the implBILITY ornty of
 * MERCHANTAICULAR PU FITNESS FOR A PARTGNU GenerRPOSE.  See the
 * or more dal Public License fhould havetails.
 *
 * You sf the GNUe received a copy o the hope   memcpy(at, A->dpram; if nlong with this progee Softwaot, write to the Frnc., 51 Fre
 * Foundation, Ith Floor,ranklin Street, Fif301, USA
 Boston, MA 02110-1L64
void  */


#ifdef TFM_MUnt *A, fpfp_mul_comba64(fp_i
{
   fp__int *B, fp_int *C)t[128];

digit c0, c1, c2, aense
 * aL is distributed i   memcpyizeof(fp_digit));
 _64.i
 *(at+64, B->dp, 64 *006-2014fp_digit));
   COMB This fi
 * C part of CyaSSL.
 *
 *  wolSL is fr6e software; you can redistribute it ublic Licdify
 * it under thy
 * the f the GNU General Pation; eiense as published bhe LicensFree Software Foundption) anther version 2 of t
 * CyaSSe, or
 * (at your o COMBA_STe received a copy oeful,
 *TORE(C->dp[2]);
   /RANTY; wi that it will be usied warrabut WITHOUT ANY WARBILITY orthout even the implICULAR PUnty of
 * MERCHANTAGNU Gener FITNESS FOR A PARTor more dRPOSE.  See the
 * hould haval Public License ff the GNUetails.
 *
 * You s the hopedigit c0, c1, c2, aeful,
 *    memcpy(at, A->dpee Softwalong with this prognc., 51 Fot, write to the Frth Floor,re
 * Foundation, I301, USA
ranklin Street, FifL64
void  Boston, MA 02110-1nt *A, fp */


#ifdef TFM_MU
{
   fp_fp_mul_comba64(fp_it[128];

_int *B, fp_int *C)ense
 * ay later version.
    memcpORE(C->dp[5]);
   /* _64.i
 *izeof(fp_digit));
 006-2014(at+64, B->dp, 64 * This fidify
 part of CyaSSL.
 *
 * 
 * SL is fr7e software; you can redistribute it y
 * the dify
 * it under thation; eif the GNU General Phe Licensense as published bption) anFree Software Found
 * CyaSSther version 2 of t COMBA_STetails.
 *
 * You s);    MULe received a copy oand/or moORE(C->dp[2]);
   /ied warra that it will be usBILITY orbut WITHOUT ANY WARICULAR PUthout even the implGNU Genernty of
 * MERCHANTAor more d FITNESS FOR A PARThould havRPOSE.  See the
 * f the GNUal Public License f the hope_int *B, fp_int *C)eful,
 * digit c0, c1, c2, aRANTY; wi   memcpy(at, A->dpnc., 51 Flong with this progth Floor,ot, write to the Fr301, USA
re
 * Foundation, IL64
void ranklin Street, Fifnt *A, fp Boston, MA 02110-1
{
   fp_ */


#ifdef TFM_MUt[128];

fp_mul_comba64(fp_iense
 * ae, or
 * (at your  MULADD(atat[3], at[70]);    ee SoftwaE(C->dp[5]);
   /* 006-2014izeof(fp_digit));
  This fibut W part of CyaSSL.
 *
 * difySL is fr8e software; you can redistribute it ation; eidify
 * it under thhe Licensf the GNU General Pption) anense as published b
 * CyaSSFree Software Found COMBA_STal Public License f);    MULetails.
 *
 * You sand/or moe received a copy oe terms oORE(C->dp[2]);
   /BILITY or that it will be usICULAR PUbut WITHOUT ANY WARGNU Generthout even the implor more dnty of
 * MERCHANTAhould hav FITNESS FOR A PARTf the GNURPOSE.  See the
 *  the hopefp_mul_comba64(fp_ieful,
 * _int *B, fp_int *C)RANTY; widigit c0, c1, c2, aied warra   memcpy(at, A->dpth Floor,long with this prog301, USA
ot, write to the FrL64
void re
 * Foundation, Int *A, fpranklin Street, Fif
{
   fp_ Boston, MA 02110-1t[128];

 */


#ifdef TFM_MUense
 * ather version 2 of  MULADD(atBA_STORE(C->dp[11])ee Softwaat[3], at[70]);    nc., 51 FE(C->dp[5]);
   /*  This fi that part of CyaSSL.
 *
 * but SL is fr9e software; you can redistribute it he Licensdify
 * it under thption) anf the GNU General P
 * CyaSSense as published b COMBA_STRPOSE.  See the
 * );    MULal Public License fand/or moetails.
 *
 * You se terms oe received a copy oublic LicORE(C->dp[2]);
   /ICULAR PU that it will be usGNU Generbut WITHOUT ANY WARor more dthout even the implhould havnty of
 * MERCHANTAf the GNU FITNESS FOR A PART the hope */


#ifdef TFM_MUeful,
 * fp_mul_comba64(fp_iRANTY; wi_int *B, fp_int *C)ied warradigit c0, c1, c2, aBILITY or   memcpy(at, A->dp301, USA
long with this progL64
void ot, write to the Frnt *A, fpre
 * Foundation, I
{
   fp_ranklin Street, Fift[128];

 Boston, MA 02110-1ense
 * aFree Software Foun MULADD(atORWARD;
   MULADD(aee SoftwaBA_STORE(C->dp[11])nc., 51 Fat[3], at[70]);    th Floor,L is  part of CyaSSL.
 *
 *  thaSL is f100e software; you can redistribute it ption) andify
 * it under th
 * CyaSSf the GNU General P COMBA_ST FITNESS FOR A PART);    MULRPOSE.  See the
 * and/or moal Public License fe terms oetails.
 *
 * You sublic Lice received a copy oy
 * the ORE(C->dp[2]);
   /GNU Gener that it will be usor more dbut WITHOUT ANY WARhould havthout even the implf the GNUnty of
 * MERCHANTA the hope Boston, MA 02110-1eful,
 *  */


#ifdef TFM_MURANTY; wifp_mul_comba64(fp_iied warra_int *B, fp_int *C)BILITY ordigit c0, c1, c2, aICULAR PU   memcpy(at, A->dpL64
void long with this prognt *A, fpot, write to the Fr
{
   fp_re
 * Foundation, It[128];

ranklin Street, Fifense
 * a wolfSSL Inc.
 *
 *MULADD(at[14], at[65]);    Mee SoftwaORWARD;
   MULADD(anc., 51 FBA_STORE(C->dp[11])th Floor,y lat part of CyaSSL.
 *
 *at[0],t[79]);  1e software; you can redistribute it 
 * CyaSSdify
 * it under th COMBA_STnty of
 * MERCHANTA);    MUL FITNESS FOR A PARTand/or moRPOSE.  See the
 * e terms oal Public License fublic Licetails.
 *
 * You sy
 * the e received a copy oation; eiORE(C->dp[2]);
   /or more d that it will be ushould havbut WITHOUT ANY WARf the GNUthout even the impl the hoperanklin Street, Fifeful,
 *  Boston, MA 02110-1RANTY; wi */


#ifdef TFM_MUied warrafp_mul_comba64(fp_iBILITY or_int *B, fp_int *C)ICULAR PUdigit c0, c1, c2, aGNU Gener   memcpy(at, A->dpnt *A, fplong with this prog
{
   fp_ot, write to the Frt[128];

re
 * Foundation, Iense
 * a
 * Copyright (C) 2MULADD(at wolfSSL Inc.
 *
 *ee Softwa[14], at[65]);    Mnc., 51 FORWARD;
   MULADD(ath Floor,e, ort[12], at[69]);    MULADy lat[79]);  2e software; you can redistribute it  COMBA_STthout even the impl);    MULnty of
 * MERCHANTAand/or mo FITNESS FOR A PARTe terms oRPOSE.  See the
 * ublic Lical Public License fy
 * the etails.
 *
 * You sation; eie received a copy ohe LicensORE(C->dp[2]);
   /hould hav that it will be usf the GNUbut WITHOUT ANY WAR the hopere
 * Foundation, Ieful,
 * ranklin Street, FifRANTY; wi Boston, MA 02110-1ied warra */


#ifdef TFM_MUBILITY orfp_mul_comba64(fp_iICULAR PU_int *B, fp_int *C)GNU Generdigit c0, c1, c2, aor more d   memcpy(at, A->dp
{
   fp_long with this progt[128];

ot, write to the Frense
 * afp_digit));
   COMBMULADD(at
 * Copyright (C) 2ee Softwa wolfSSL Inc.
 *
 *nc., 51 F[14], at[65]);    Mth Floor,ther t[12], at[69]);    MULADe, ot[79]);  3e software; you can redistribute it, at[79]);thout even the impland/or monty of
 * MERCHANTAe terms o FITNESS FOR A PARTublic LicRPOSE.  See the
 * y
 * the al Public License fation; eietails.
 *
 * You she License received a copy option) anORE(C->dp[2]);
   /f the GNU that it will be us the hopeot, write to the Freful,
 * re
 * Foundation, IRANTY; wiranklin Street, Fified warra Boston, MA 02110-1BILITY or */


#ifdef TFM_MUICULAR PUfp_mul_comba64(fp_iGNU Gener_int *B, fp_int *C)or more ddigit c0, c1, c2, ahould hav   memcpy(at, A->dpt[128];

long with this progense
 * a(at+64, B->dp, 64 *MULADD(atfp_digit));
   COMBee Softwa
 * Copyright (C) 2006-201);    MULADD(at[5], ath Floor,le is part of CyaSSL.
 *
 *  MULAt[79]);  ee software; you can redistribute itULADD(at[1thout even the implied warr11], at[73]);    MULublic License as published DD(at[14],RPOSE.  See the
 * GNU Gene, at[70]);    MULADDhe License, or
 * (at your at[17], ate received a copy of the GNt[67]);    MULADD(at the hope that it will be u20], at[64ot, write to the Free Softw4]); 
   COMBA_STOREied warranty of
 * MERCHANT[0], at[85 Boston, MA 02110-1301, USA5]);    MULADD(at[1]GNU General Public License t[82]);   _int *B, fp_int *C)
{
   fp  MULADD(at[4], at[8f the GNU General Public Li;    MULADizeof(fp_digit));
   memcpADD(at[7], at[78]);  ee Software
 * Foundation, at[79]);  

   COMBA_CLEAR;
   /* 0 );    M[74]);    MULADD(at[12],
   COMBA_S10ORE(C->dp[0]);
   /* 1 */
   COMBA_FLADD(at[12], at[66]);    MULADD(at[2]11], at[73]);    MUL); 
   COMBA_STORE(C->dp[1]D(at[15], p[3]);
   /* 4 */
   COMBA_, at[70]);    MULADD    MULADD(at[1], at[65]); t[64]); 
 ]);    MULADD(at[2], at[66]t[67]);    MULADD(a20], at[64   MULADD(at[4], at[64]); 

   MULADD(at[0], atLADD(at[1], at[66]);    MUL[0], at[85 MULADD(at[0], at[69]);    LADD(at[3], at[83]);TORE(C->dp[3]);
   /* 4 */
t[82]);   D(at[3], at[66]);    MULADDt[6], at[80]);    MU1], at[67]);    MULADD(at[2;    MULAMULADD(at[5], at[80   MULADD(COMBA_FORWARD;
   MULADD(aADD(at[7], at[78]);  [4]);
   /* 5 */
   COMBA_FLADD(at[11], at[68]);    MULADD(at[3]);     MULADD(a MULADD(at[4], at[66]);    MULADD(at6], at[69][7], at[64]); 
   COMBA_STO11], at[73]);    MUL->dp[6]);
   /* 7 */
   COM at[66]); ], at[72]);    MULADD(at[1], at[70]);    MULADD[70]);    MULADD(at[2], at[
   /* 23 69]);    MULADD(at[4], at[6 */
   COMBA_FORWARD    MULADD(at[5], at[66]);   MULADD(a   MULADD(at[7], at[65]);  4]); 
   COMBA_STOREOMBA_STORE(C->dp[7]);
   /*DD(at[5],  9 */
   COMBA_FORWARD;
   5]);    MULADD(at[1]DD(at[1], at[71]);    MULAD8], at[79]D(at[2], at[71]);    MULADD  MULADD(at[4], at[   MULADD;    MULADD(at[10], , at[67]);    MULADD(at[6],t[75]);   ], at[67]);    MULADD(at[7D(at[8]D(at[14], at[73]);    MUat[65]);   10MULADD(at[9], at[64]); 
   COMBA_STO8]);    MU[9], at[65]);    MULADD(at[11], at[73]);    MUL0], at[74]);    MULADD(at[1;    MULADCOMBA_FORWARD;
   MULADD(at, at[70]);    MULADD[71]);    MULADD(at[4], at[BA_STORE(Cat[73]);    MULADD(at[3], a */
   COMBA_FORWARD    MULADD(at[7], at[67]); [0], at[85);    MULADD(at[6], at[69])4]); 
   COMBA_STORELADD(at[10], at[64]); 
   Ct[82]);   MULADD(at[9], at[66]);    M5]);    MULADD(at[1]ULADD(at[0], at[75]);    MU[81]);    BA_STORE(C->dp[11]);
   /*  MULADD(at[8], at[80at[3], at[72]);    MULADD(at[75]);   ADD(at[1], at[75]);    MULADD(at[D(at[14], at[73]);    MU(at[3], at[103]);    MULADD(at[4], at[72]);    MU MULADD(at   MULADD(at[1], at[76]);  11], at[73]);    MULat[7], at[69]);    MULADD(aLADD(at[22ADD(at[4], at[73]);    MULA, at[70]);    MULADBA_STORE(Cat[6], at[71]);    MULADD(a67]);    MULADD(at[2at[64]); 
   COMBA_STORE(C-[0], at[85 at[68]);    MULADD(at[10],); 
   COMBA_STORE(Cat[77]);    MULADD(at[1], at[82]);   [65]);    MULADD(at[13], at);    MULADD(at[1], );    MULADD(at[4], at[73])[81]);    ORWARD;
   MULADD(at[0], atMULADD(at[4], at[85]MULADD(at[7], at[70]);    Mt[75]);  DD(at[6], at[83]);  DD(at[9], at[6D(at[14], at[73]);    MU  MULADD(at105], at[73]);    MULADD(at[6], at[72]D(at[17],  at[79]);    MULADD(at[1], 11], at[73]);    MUL MULADD(at[9], at[69]);    t[20], at[]);    MULADD(at[4], at[75]);    MULADD(at[16],ADD(at[12], at[66]);    MULat[71]);   MULADD(at[7], at[72]);       MULADD(at[19], at_STORE(C->dp[14]);
   /* 1568]);    MD(at[10], at[69]);    MULAD4]); 
   COMBA_STORE(at[1], at[78]);    MULADD();    MULAt[13], at[66]);    MULADD(a5]);    MULADD(at[1;
   /* 2615], at[64]); 
   COMBA_STOMULADD(at[4], at[85][73]);    MULADD(at[7], at[   MULADDMULADDD(at[14], at[73]);    MU], at[79]); 1  MULADD(at[2], at[78]);    MULADD(a13], at[76t[14], at[66]);    MULADD(a11], at[73]);    MUL at[75]);    MULADD(at[6], t[81]);   E(C->dp[16]);
   /* 17 */
 );    MULADD(at[16],]);    MULADD(at[9], at[71]8]);    MU], at[80]);    MULADD(at[2]   MULADD(at[19], at   MULADD(at[12], at[68]); t[82]);   77]);    MULADD(at[5], at[74]); 
   COMBA_STOREMULADD(at[15], at[65]);      MULADD(a   MULADD(at[8], at[73]);  at[19], at[71]);     17 */
   COMBA_FORWARD;
  ULADD(at[2LADD(at[11], at[70]);    MU  MULAD(at[14], at[73]);    MMULAD66]);    68]);    MULADD(at[14], at[67]);    ], at[83]);    MULADD(at[6], at[76]);11], at[73]);    MUt[81]);    MULADD(at[8], at[74]);    91]);    MULADD(at[18 */
   COMBA_FORWARD;
   M8]);    MUDD(at[11], at[71]);    MULA   MULADD(at[4], at[(at[2], at[80]);    MULADD(t[82]);   at[14], at[68]);    MULADD(ADD(at[7], at[84]); , at[77]);    MULADD(at[6],  MULADD(a17], at[65]);    MULADD(at[[10], at[81]);    MU4]);    MULADD(at[9], at[73ULADD(at[2COMBA_FORWARD;
   MULADD(at], at[7]);    MULADD(at[15], a at[82]);   1MULADD(at[2], at[81]);    MULADD(at[  COMBA_FO14], at[69]);    MULADD(at[);    MULADD(at[19],t[78]);    MULADD(at[6], atat[70]);  , at[66]);    MULADD(at[18]   MULADD(at[22], at;    MULADD(at[9], at[74]);67]);    Mdp[19]);
   /* 20 */
   COMMULADD(at[25], at[66 MULADD(at[12], at[71]);   ); 
   COM[83]);    MULADD(at[2], at[4]); 
   COMBA_STORARD;
   MU);    MULADD(at[4], at[80])[10], at[81]);    MUDD(at[17], at[66]);    MULA  MULADD(aMULADD(at[7], at[77]);    MU], att[88]);  [76]);    MULADD(at[9], at[75]);    7], at[85]]); 
   COMBA_STORE(C->dp[2);    MULADD(at[19],ADD(at[12], at[72]);    MULt[82]);   ]);    MULADD(at[1], at[84]   MULADD(at[22], at(at[15], at[69]);    MULADD9]);    MU MULADD(at[4], at[81]);    MULADD(at[25], at[66[18], at[66]);    MULADD(at;    MULADD(at[7], at[78]);    MULADDDD(at[17], at[75]); (C->dp[20]);
   /* 21 */
    MULADD(a wolfSSL Inc.
 *
 * This f[11], a at[71]);    MULADD(at[2CyaSSL is f11ee software; you can redistribute it, at[84]);re
 * Foundation, Inc., 51 );    MULADD(at[19],ublic License as published [81]);     */


#ifdef TFM_MUL64
void   MULADD(at[22], athe License, or
 * (at your [0], at[93digit c0, c1, c2, at[128];
MULADD(at[25], at[66 the hope that it will be ut[90]);   (at+64, B->dp, 64 * sizeof   MULADD(at[4], at[8ied warranty of
 * MERCHANT;    MULAD]);    MULADD(at[14], at[72]5]); , at[85])ORE(C->dp[0]);
   /* 1 */
   COMBA_Ft[26], at[t[2], at[85]);    MULADD(at);    MULADD(at[19],); 
   COMBA_STORE(C->dp[1]E(C->dp[28at[82]);    MULADD(at[6], a   MULADD(at[22], at    MULADD(at[1], at[65]); ], at[76]));    MULADD(at[9], at[78])t[67]);    MULADD(at[90]);      MULADD(at[11], at[76]);     MULADD(at[20], aLADD(at[1], at[66]);    MUL;    MULADMULADD(at[14], at[73]);    M MULA, at[85]) MULADD(at[4], at[66]);    MULADD(atat[12], atat[87]);    MULADD(at[2], a);    MULADD(at[19],->dp[6]);
   /* 7 */
   COM15], at[78);    MULADD(at[5], at[83])   MULADD(at[22], at[70]);    MULADD(at[2], at[ULADD(at[1MULADD(at[8], at[80]);    M1], at[93]);    MULA    MULADD(at[5], at[66]); at[4], at[D(at[11], at[77]);    MULAD4]); 
  MULADD(at[6], at[88]);t[13], at[751MULADD(at[9], at[64]); 
   COMBA_STO MULADD(at;
   /* 25 */
   COMBA_FORW);    MULADD(at[19],0], at[74]);    MULADD(at[1* 30 */
     MULADD(at[2], at[87]);     MULADD(at[22], at[71]);    MULADD(at[4], at[ULADD(at[1ADD(at[5], at[84]);    MULA1], at[93]);    MULA    MULADD(at[7], at[67]); DD(at[19],[8], at[81]);    MULADD(at[94]); , at[85])3]);    MULADD(at[4], at[72]);    MU    MULADDULADD(at[22], at[67]);    M);    MULADD(at[19],at[7], at[69]);    MULADD(a MULADD(atDD(at[25], at[64]); 
   COM, at[70]);    MULADULADD(at[1 */
   COMBA_FORWARD;
   MU MULADD(at[29], at[6at[64]); 
   COMBA_STORE(C-DD(at[19],at[2], at[88]);    MULADD(at* 31 , at[85])5], at[73]);    MULADD(at[6], at[72], at[70]);D(at[16], at[74]);    MULAD);    MULADD(at[19], MULADD(at[9], at[69]);    t[67]);   t[19], at[71]);    MULADD(at[89]);    MULADD(atADD(at[12], at[66]);    MUL, at[86]);2], at[68]);    MULADD(at[2t[67])LADD(at[11], at[84]);   ], at[79]); 2  MULADD(at[2], at[78]);    MULADD(aLADD(at[4](at[8], at[83]);    MULADD();    MULADD(at[19], at[75]);    MULADD(at[6],   MULADD(a1], at[80]);    MULADD(at[1t[89]);    MULADD(at]);    MULADD(at[9], at[71]ULADD(at[2 at[77]);    MULADD(at[15], t[67][73]);   68]);    MULADD(at[14], at[67]);        MULADDBA_STORE(C->dp[27]);
   /* 11], at[73]);    MU  MULADD(aLADD(at[0], at[92]);    MUL]);    MULADD(at[28]8 */
   COMBA_FORWARD;
   MULADD(at[2t[3], at[89]);    MULADD(at[    M[73]);   MULADD(at[2], at[81]);    MULADD(at[26], at[69D(at[17], at[75]);    MULADULADD(at[1], at[95])t[78]);    MULADD(at[6], at  MULADD(at[20], at[72]);    MULADD(a, at[7t[91]);    MULADD(at[6],2], at[70]);2[76]);    MULADD(at[9], at[75]);    , at[87]); MULADD(at[4], at[89]);    ULADD(at[1], at[95])ADD(at[12], at[72]);    MULt[84]);   ], at[74]);    MULADD(at[12], at[D(at[14],ee software; you can redistribute it at[86]); 75]);    MULADD(at[12], at[ULADD(at[1], at[95])ublic License  at[77]);    MULADD(at[2LADD(at[24],2ORE(C->dp[0]);
   /* 1 */
   COMBA_F  MULADD(a90]);    MULADD(at[5], at[811], a at[77]);    MULADD(at[2    MULADD(a2 MULADD(at[4], at[66]);    MULADD(att[24], at[ at[75]);    MULADD(at[20], 11],  part of CyaSSL2  COMBA_SULADD(atC->used = 128COMBA_FOsign = A(at[0],^ B(at[0]E(C->fp_clamp(CRE(C->dp[32]FINI;
}
#endif
