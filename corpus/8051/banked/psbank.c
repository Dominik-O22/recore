/* The register `__sdcc_banked_call` selects the bank with: here the port whose low bits drive
   the upper address lines of the code memory. */
__sfr __at (0xB1) PSBANK;
