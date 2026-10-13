/* Writes a file, reads it back, and walks the directory it is in. */
#include <stdio.h>
#include <string.h>
#include "ff.h"

static FATFS volume;
static FIL file;
static DIR directory;
static FILINFO entry;
static char line[32];

static void report(const char *what, FRESULT result)
{
    printf("%s: %d\n", what, (int)result);
}

void main(void)
{
    UINT count;
    report("mount", f_mount(&volume, "", 1));
    report("mkdir", f_mkdir("logs"));
    report("open", f_open(&file, "logs/boot.txt", FA_WRITE | FA_CREATE_ALWAYS));
    report("write", f_write(&file, "started\r\n", 9, &count));
    report("sync", f_sync(&file));
    report("close", f_close(&file));
    report("rename", f_rename("logs/boot.txt", "logs/last.txt"));
    report("open", f_open(&file, "logs/last.txt", FA_READ));
    report("seek", f_lseek(&file, 2));
    report("read", f_read(&file, line, sizeof line - 1, &count));
    line[count] = 0;
    printf("%lu bytes, %s", (unsigned long)f_size(&file), line);
    f_close(&file);
    report("opendir", f_opendir(&directory, "logs"));
    while (f_readdir(&directory, &entry) == FR_OK && entry.fname[0])
        printf("%s %lu\n", entry.fname, (unsigned long)entry.fsize);
    f_closedir(&directory);
    report("stat", f_stat("logs", &entry));
    report("unlink", f_unlink("logs/last.txt"));
    for (;;)
        ;
}
