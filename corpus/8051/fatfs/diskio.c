/* The disk under FatFs: a few sectors of external memory. */
#include <string.h>
#include "ff.h"
#include "diskio.h"

#define SECTORS 128
#define SECTOR_SIZE 512

static BYTE disk[SECTORS / 8][SECTOR_SIZE];
static BYTE ready;

DSTATUS disk_status(BYTE drive)
{
    return drive == 0 && ready ? 0 : STA_NOINIT;
}

DSTATUS disk_initialize(BYTE drive)
{
    if (drive != 0)
        return STA_NOINIT;
    ready = 1;
    return 0;
}

/* Only the first sectors have memory behind them. The rest read as zeros. */
DRESULT disk_read(BYTE drive, BYTE *buffer, LBA_t sector, UINT count)
{
    if (drive != 0 || sector + count > SECTORS)
        return RES_PARERR;
    for (; count; count--, sector++, buffer += SECTOR_SIZE) {
        if (sector < SECTORS / 8)
            memcpy(buffer, disk[sector], SECTOR_SIZE);
        else
            memset(buffer, 0, SECTOR_SIZE);
    }
    return RES_OK;
}

DRESULT disk_write(BYTE drive, const BYTE *buffer, LBA_t sector, UINT count)
{
    if (drive != 0 || sector + count > SECTORS)
        return RES_PARERR;
    for (; count; count--, sector++, buffer += SECTOR_SIZE)
        if (sector < SECTORS / 8)
            memcpy(disk[sector], buffer, SECTOR_SIZE);
    return RES_OK;
}

DRESULT disk_ioctl(BYTE drive, BYTE command, void *buffer)
{
    if (drive != 0)
        return RES_PARERR;
    switch (command) {
    case CTRL_SYNC:
        return RES_OK;
    case GET_SECTOR_COUNT:
        *(LBA_t *)buffer = SECTORS;
        return RES_OK;
    case GET_SECTOR_SIZE:
        *(WORD *)buffer = SECTOR_SIZE;
        return RES_OK;
    case GET_BLOCK_SIZE:
        *(DWORD *)buffer = 1;
        return RES_OK;
    }
    return RES_PARERR;
}

DWORD get_fattime(void)
{
    return ((DWORD)(2026 - 1980) << 25) | ((DWORD)10 << 21) | ((DWORD)13 << 16);
}
