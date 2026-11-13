/*
 * Copyright (C) 2026 xbmc4lyfe
 * SPDX-License-Identifier: RPL-1.5
 * 
 * Unless explicitly acquired and licensed from Licensor under another license,
 * the contents of this file are subject to the Reciprocal Public License
 * ("RPL") Version 1.5, or subsequent versions as allowed by the RPL, and You
 * may not copy or use this file in either source code or executable form,
 * except in compliance with the terms and conditions of the RPL.
 * 
 * All software distributed under the RPL is provided strictly on an "AS IS"
 * basis, WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESS OR IMPLIED, AND LICENSOR
 * HEREBY DISCLAIMS ALL SUCH WARRANTIES, INCLUDING WITHOUT LIMITATION, ANY
 * WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, QUIET
 * ENJOYMENT, OR NON-INFRINGEMENT. See the RPL for specific language governing
 * rights and limitations under the RPL.
 * 
 */
#include <lzma.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
int main(int argc, char **argv) {
    if (argc != 2) return 2;
    uint8_t input[65535], output[131072] = {9,20,5,0};
    for (size_t i=0; i<sizeof(input); ++i) input[i]=(uint8_t)(i*31+i/17);
    lzma_options_lzma options;
    if (lzma_lzma_preset(&options,6)) return 3;
    options.ext_flags=0;
    options.ext_size_low=(uint32_t)sizeof(input);
    options.ext_size_high=0;
    lzma_filter filters[]={{LZMA_FILTER_LZMA1EXT,&options},{LZMA_VLI_UNKNOWN,NULL}};
    if (lzma_properties_encode(&filters[0],output+4)!=LZMA_OK) return 4;
    size_t position=9;
    lzma_ret result=lzma_raw_buffer_encode(filters,NULL,input,sizeof(input),output,&position,sizeof(output));
    if (result!=LZMA_OK) return 5;
    FILE *file=fopen(argv[1],"wb");
    if (!file) return 6;
    if (fwrite(output,1,position,file)!=position || fclose(file)) return 7;
    printf("liblzma=%s input=%zu zip-payload=%zu EOS=absent\n",lzma_version_string(),sizeof(input),position);
    return 0;
}
