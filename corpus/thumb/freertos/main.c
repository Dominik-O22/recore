/* A producer and a consumer task joined by a queue, a mutex around the console, a software timer
   that sets a bit in an event group, and a task that waits for the bit. */
#include <stdio.h>
#include "FreeRTOS.h"
#include "task.h"
#include "queue.h"
#include "semphr.h"
#include "timers.h"
#include "event_groups.h"

#define TICKED (1u << 0)

static QueueHandle_t readings;
static SemaphoreHandle_t console;
static EventGroupHandle_t events;

static void say(const char *what, unsigned value)
{
    xSemaphoreTake(console, portMAX_DELAY);
    printf("%s %u\n", what, value);
    xSemaphoreGive(console);
}

static void produce(void *parameter)
{
    unsigned value = (unsigned)(uintptr_t)parameter;
    TickType_t woken = xTaskGetTickCount();
    for (;;) {
        xQueueSend(readings, &value, portMAX_DELAY);
        value = value * 3 + 1;
        vTaskDelayUntil(&woken, pdMS_TO_TICKS(10));
    }
}

static void consume(void *parameter)
{
    unsigned value, total = 0;
    (void)parameter;
    for (;;) {
        if (xQueueReceive(readings, &value, pdMS_TO_TICKS(100)) == pdPASS) {
            total += value;
            say("received", value);
        } else {
            say("timed out after", total);
        }
    }
}

static void tick(TimerHandle_t timer)
{
    (void)timer;
    xEventGroupSetBits(events, TICKED);
}

static void watch(void *parameter)
{
    unsigned seen = 0;
    (void)parameter;
    for (;;) {
        EventBits_t bits = xEventGroupWaitBits(events, TICKED, pdTRUE, pdFALSE, portMAX_DELAY);
        if (bits & TICKED)
            say("ticks", ++seen);
        if (seen == 10)
            vTaskDelete(NULL);
    }
}

void vApplicationMallocFailedHook(void)
{
    for (;;)
        ;
}

void vApplicationStackOverflowHook(TaskHandle_t task, char *name)
{
    (void)task;
    printf("stack overflow in %s\n", name);
    for (;;)
        ;
}

int main(void)
{
    readings = xQueueCreate(4, sizeof(unsigned));
    console = xSemaphoreCreateMutex();
    events = xEventGroupCreate();
    xTaskCreate(produce, "produce", configMINIMAL_STACK_SIZE, (void *)7, 2, NULL);
    xTaskCreate(consume, "consume", configMINIMAL_STACK_SIZE * 2, NULL, 1, NULL);
    xTaskCreate(watch, "watch", configMINIMAL_STACK_SIZE * 2, NULL, 1, NULL);
    xTimerStart(xTimerCreate("tick", pdMS_TO_TICKS(50), pdTRUE, NULL, tick), 0);
    vTaskStartScheduler();
    for (;;)
        ;
}
