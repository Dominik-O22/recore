/* What a Cortex-M enters: the vector table at the start of flash, the reset handler that sets up
 * memory and calls `main`, and a handler for every exception and interrupt nothing else takes. */
#include <stdint.h>

extern uint32_t _estack, _sidata, _sdata, _edata, _sbss, _ebss;
int main(void);

void Reset_Handler(void);
void Default_Handler(void);

#define HANDLER(name) void name(void) __attribute__((weak, alias("Default_Handler")))
HANDLER(NMI_Handler);
HANDLER(HardFault_Handler);
HANDLER(MemManage_Handler);
HANDLER(BusFault_Handler);
HANDLER(UsageFault_Handler);
HANDLER(SVC_Handler);
HANDLER(DebugMon_Handler);
HANDLER(PendSV_Handler);
HANDLER(SysTick_Handler);
HANDLER(WWDG_IRQHandler);
HANDLER(EXTI0_IRQHandler);
HANDLER(EXTI1_IRQHandler);
HANDLER(DMA1_IRQHandler);
HANDLER(ADC_IRQHandler);
HANDLER(TIM2_IRQHandler);
HANDLER(TIM3_IRQHandler);
HANDLER(I2C1_IRQHandler);
HANDLER(SPI1_IRQHandler);
HANDLER(USART1_IRQHandler);
HANDLER(USART2_IRQHandler);

/* The initial stack pointer, then the exceptions in the order the architecture numbers them, then
 * the interrupts of this imaginary chip. Zeros are reserved slots. */
__attribute__((section(".isr_vector"), used)) void (*const vectors[])(void) = {
    (void (*)(void))&_estack,
    Reset_Handler,
    NMI_Handler,
    HardFault_Handler,
    MemManage_Handler,
    BusFault_Handler,
    UsageFault_Handler,
    0, 0, 0, 0,
    SVC_Handler,
    DebugMon_Handler,
    0,
    PendSV_Handler,
    SysTick_Handler,
    WWDG_IRQHandler,
    EXTI0_IRQHandler,
    EXTI1_IRQHandler,
    DMA1_IRQHandler,
    ADC_IRQHandler,
    TIM2_IRQHandler,
    TIM3_IRQHandler,
    I2C1_IRQHandler,
    SPI1_IRQHandler,
    USART1_IRQHandler,
    USART2_IRQHandler,
};

void Reset_Handler(void)
{
    uint32_t *from = &_sidata, *to = &_sdata;
    while (to < &_edata)
        *to++ = *from++;
    for (to = &_sbss; to < &_ebss;)
        *to++ = 0;
    main();
    for (;;)
        ;
}

void Default_Handler(void)
{
    for (;;)
        ;
}
