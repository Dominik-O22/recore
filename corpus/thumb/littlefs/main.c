/* Counts boots in a file on a flash chip, as littlefs's own example does, and lists the
   directory. The chip is a stretch of memory here. */
#include <stdio.h>
#include <string.h>
#include "lfs.h"

#define BLOCK_SIZE 512
#define BLOCKS 32

static uint8_t flash[BLOCKS][BLOCK_SIZE];

static int flash_read(const struct lfs_config *c, lfs_block_t block, lfs_off_t off, void *buffer, lfs_size_t size)
{
    (void)c;
    memcpy(buffer, &flash[block][off], size);
    return 0;
}

static int flash_prog(const struct lfs_config *c, lfs_block_t block, lfs_off_t off, const void *buffer, lfs_size_t size)
{
    (void)c;
    memcpy(&flash[block][off], buffer, size);
    return 0;
}

static int flash_erase(const struct lfs_config *c, lfs_block_t block)
{
    (void)c;
    memset(flash[block], 0xff, BLOCK_SIZE);
    return 0;
}

static int flash_sync(const struct lfs_config *c)
{
    (void)c;
    return 0;
}

static uint8_t read_buffer[64], prog_buffer[64], lookahead_buffer[16];

static const struct lfs_config config = {
    .read = flash_read,
    .prog = flash_prog,
    .erase = flash_erase,
    .sync = flash_sync,
    .read_size = 16,
    .prog_size = 16,
    .block_size = BLOCK_SIZE,
    .block_count = BLOCKS,
    .cache_size = 64,
    .lookahead_size = 16,
    .block_cycles = 500,
    .read_buffer = read_buffer,
    .prog_buffer = prog_buffer,
    .lookahead_buffer = lookahead_buffer,
};

static lfs_t lfs;
static lfs_file_t file;
static uint8_t file_buffer[64];
static const struct lfs_file_config file_config = {.buffer = file_buffer};

int main(void)
{
    uint32_t boot_count = 0;
    struct lfs_info info;
    lfs_dir_t dir;
    if (lfs_mount(&lfs, &config)) {
        lfs_format(&lfs, &config);
        lfs_mount(&lfs, &config);
    }
    for (int boot = 0; boot < 3; boot++) {
        lfs_file_opencfg(&lfs, &file, "boot_count", LFS_O_RDWR | LFS_O_CREAT, &file_config);
        lfs_file_read(&lfs, &file, &boot_count, sizeof boot_count);
        boot_count += 1;
        lfs_file_rewind(&lfs, &file);
        lfs_file_write(&lfs, &file, &boot_count, sizeof boot_count);
        lfs_file_close(&lfs, &file);
    }
    lfs_mkdir(&lfs, "logs");
    lfs_rename(&lfs, "boot_count", "logs/boots");
    lfs_dir_open(&lfs, &dir, "logs");
    while (lfs_dir_read(&lfs, &dir, &info) > 0)
        printf("%s %u %d\n", info.name, (unsigned)info.size, info.type);
    lfs_dir_close(&lfs, &dir);
    lfs_remove(&lfs, "logs/boots");
    lfs_unmount(&lfs);
    printf("boot_count: %u\n", (unsigned)boot_count);
    for (;;)
        ;
}
