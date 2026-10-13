/* Runs the tests of each bank through the function that bank exports. */
void run_hashes(void) __banked;
void run_ciphers(void) __banked;

void main(void)
{
    run_hashes();
    run_ciphers();
    for (;;)
        ;
}
