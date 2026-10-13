/* The way into the bank that holds the hashes and their tests. */
#pragma codeseg BANK1

int main_md2_test(void);
int main_md5_test(void);
int main_sha1_test(void);
int main_sha256_test(void);

void run_hashes(void) __banked
{
    main_md2_test();
    main_md5_test();
    main_sha1_test();
    main_sha256_test();
}
