/*
    SLAP - Squid Log Analysing Program
    Written by Martin A. COLEMAN.
    First written 2013-04-04.
    Re-written 2013-04-06.
    
    This is free and unencumbered software released into the public domain.
    See file UNLICENSE for more information.
    Credit is appreciated but not required.
    
    This depends on access.log being in default format.
    http://wiki.squid-cache.org/Features/LogFormat
    
    Compile with:
    gcc -o slap main.c
    or
    tcc -o slap main.c
*/
#include <stdio.h>
#include <string.h>
#include <stdint.h>

#define SIZE_BUFSZ 7
static char const SIZE_PREFIXES[] = "kMGTPEZY";

typedef unsigned long long bignumber;

typedef struct USERDETAILS {
    int ip;
    bignumber download;
} userdetails;

/*
taken from
http://stackoverflow.com/questions/7846495/how-to-get-file-size-properly-and-convert-it-to-mb-gb-in-cocoa
with modifications for binary conversion, which I believe is the only proper way to count data.
*/
void format_size(char buf[SIZE_BUFSZ], uint64_t sz)
{
    int pfx = 0;
    unsigned int m, n, rem, hrem;
    uint64_t a;
    if (sz <= 0) {
        memcpy(buf, "0 B", 3);
        return;
    }
    a = sz;
    if (a < 1000) {
        n = a;
        snprintf(buf, SIZE_BUFSZ, "%u B", n);
        return;
    }
    for (pfx = 0, hrem = 0; ; pfx++) {
        rem = a % 1000ULL;
        a = a / 1000ULL;
        if (!SIZE_PREFIXES[pfx + 1] || a < 1000ULL)
            break;
        hrem |= rem;
    }
    n = a;
    if (n < 10) {
        if (rem >= 950) {
            buf[0] = '1';
            buf[1] = '0';
            buf[2] = ' ';
            buf[3] = SIZE_PREFIXES[pfx];
            buf[4] = 'B';
            buf[5] = '\0';
            return;
        } else {
            m = rem / 100;
            rem = rem % 100;
            if (rem > 50 || (rem == 50 && ((m & 1) || hrem)))
                m++;
            snprintf(buf, SIZE_BUFSZ,
                     "%u.%u %cB", n, m, SIZE_PREFIXES[pfx]);
        }
    } else {
        if (rem > 500 || (rem == 500 && ((n & 1) || hrem)))
            n++;
        if (n >= 1000 && SIZE_PREFIXES[pfx + 1]) {
            buf[0] = '1';
            buf[1] = '.';
            buf[2] = '0';
            buf[3] = ' ';
            buf[4] = SIZE_PREFIXES[pfx+1];
            buf[5] = 'B';
            buf[6] = '\0';
        } else {
            snprintf(buf, SIZE_BUFSZ,
                     "%u %cB", n, SIZE_PREFIXES[pfx]);
        }
    }
}

/*
special thanks http://stackoverflow.com/questions/3898840/converting-a-number-of-bytes-into-a-file-size-in-c
I borrowed it and re-stylised it
*/
void printsize(size_t  size)
{                   
    static const char *SIZES[] = { "B", "kB", "MB", "GB" };
    size_t div = 0;
    size_t rem = 0;

    while (size >= 1024 && div < (sizeof SIZES / sizeof *SIZES))
    {
        rem = (size % 1024);
        div++;   
        size /= 1024;
    }
    printf("%.1f %s\n", (float)size + (float)rem / 1024.0, SIZES[div]);
}

int main()
{
    /* essential variables */
    FILE *fp;
    int ip1, ip2, ip3, ip4;
    unsigned long long totaldownloads=0;
    unsigned long long bytes=0;
    int i=0;
    char buffer[4096]; /* does this need to allocate more? */
    char remotehost[16];
    
    /* misc variables */
    char times[32];
    char times2[32];
    int duration=0;
    char result_codes[32];
    int codes=0;
    
    bignumber hits=0;
    bignumber misses=0;

    userdetails userip[255];
    
    /* zero out everything first */
    ip1=ip2=ip3=ip4=0;
    for(i=1; i<255;i++)
    {
        userip[i].ip=0;
        userip[i].download=0;
    }
    buffer[0]='\0';

    puts("Squid Log Analysing Program v0.3 By Martin COLEMAN. Released into the public domain. See UNLICENSE for details.");
    /* open the log */
    fp=fopen("access.log", "r");
    if(fp==NULL)
    {
        printf("Error opening access log.\n");
        return 1;
    }
    
    /* get the IP address and data use per IP address */
    while(fgets(buffer, sizeof buffer, fp) != NULL)
    {
        sscanf(buffer, "%s %s %s %s %u %[^\n]", times, times2, remotehost, result_codes, &bytes, NULL);
        sscanf(remotehost, "%d.%d.%d.%d", &ip1, &ip2, &ip3, &ip4);
        userip[ip4].ip=ip4;
        userip[ip4].download=bytes;
        if(!strstr(result_codes, "HIT")) { hits++; };
        if(!strstr(result_codes, "MISS")) { misses++; };
        // printf("IP Address: %d, Bytes: %u\n", userip[ip4].ip, userip[ip4].download); //FOR DEBUGGING
        totaldownloads=totaldownloads+userip[ip4].download;
        buffer[0]='\0';
        ip4=0;
    }
    fclose(fp);
    
    /* print out what we have */
    for(i=1; i<255;i++)
    {
        printf("IP: %d, Bytes: %d\n", i, userip[i].download);
    }
    //printf("Total Data Use: "); printsize(totaldownloads);
    printf("Total Data Use: "); format_size(totaldownloads);
    printf("Cache Hits: %lu\n", hits);
    printf("Cache Misses: %lu\n", misses);
    return 0;
}
