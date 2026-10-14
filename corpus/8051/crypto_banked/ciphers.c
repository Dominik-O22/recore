/* The way into the bank that holds the ciphers and their tests. */
#pragma codeseg BANK2

int main_arcfour_test(void);
int main_blowfish_test(void);
int main_des_test(void);
int main_rot_13_test(void);

void run_ciphers(void) __banked
{
    main_arcfour_test();
    main_blowfish_test();
    main_des_test();
    main_rot_13_test();
}
