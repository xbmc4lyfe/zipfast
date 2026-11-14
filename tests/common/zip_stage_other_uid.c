// Copyright (C) 2026 xbmc4lyfe
// SPDX-License-Identifier: RPL-1.5
//
// Unless explicitly acquired and licensed from Licensor under another license,
// the contents of this file are subject to the Reciprocal Public License
// ("RPL") Version 1.5, or subsequent versions as allowed by the RPL, and You
// may not copy or use this file in either source code or executable form,
// except in compliance with the terms and conditions of the RPL.
//
// All software distributed under the RPL is provided strictly on an "AS IS"
// basis, WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESS OR IMPLIED, AND LICENSOR
// HEREBY DISCLAIMS ALL SUCH WARRANTIES, INCLUDING WITHOUT LIMITATION, ANY
// WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, QUIET
// ENJOYMENT, OR NON-INFRINGEMENT. See the RPL for specific language governing
// rights and limitations under the RPL.

/* Bounded Task6 fixture agent, invoked only by an explicitly qualified launcher.
 * One native open; optional one-byte retained-FD mutation; ten-second lifetime.
 * No credential changes, namespace mutation, shell or loops
 * over caller-controlled object counts. The parent attests the reported euid. */
#define _DARWIN_C_SOURCE 1
#define _POSIX_C_SOURCE 200809L
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
int main(int argc,char **argv) {
    if(argc!=3||strlen(argv[2])>=PATH_MAX)return 64;
    int flags=O_CLOEXEC|O_NOFOLLOW;
    if(strcmp(argv[1],"read")==0)flags|=O_RDONLY;
    else if(strcmp(argv[1],"write")==0||strcmp(argv[1],"retain-mutate")==0)flags|=O_RDWR;
    else if(strcmp(argv[1],"directory")==0)flags|=O_RDONLY|O_DIRECTORY;
    else return 64;
    alarm(10);
    int fd=open(argv[2],flags);int error=fd<0?errno:0;
    printf("%lu %d\n",(unsigned long)geteuid(),error);fflush(stdout);
    if(fd>=0&&strcmp(argv[1],"retain-mutate")==0) {
        char command=0;if(read(STDIN_FILENO,&command,1)!=1||command!='w'){close(fd);return 65;}
        char byte=127;int failed=pwrite(fd,&byte,1,0)!=1;
        printf("%lu %d\n",(unsigned long)geteuid(),failed?errno:0);fflush(stdout);
    }
    if(fd>=0)close(fd);
    return 0;
}
