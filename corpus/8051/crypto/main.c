/* Runs the test of each algorithm, which the build names after its file. */
int main_arcfour_test(void);
int main_blowfish_test(void);
int main_des_test(void);
int main_md2_test(void);
int main_md5_test(void);
int main_rot_13_test(void);
int main_sha1_test(void);
int main_sha256_test(void);

void main(void)
{
    main_arcfour_test();
    main_blowfish_test();
    main_des_test();
    main_md2_test();
    main_md5_test();
    main_rot_13_test();
    main_sha1_test();
    main_sha256_test();
    for (;;)
        ;
}
