/* Filters a signal with an FIR filter and a biquad cascade, then takes its statistics, a matrix
   product and the magnitude of complex numbers: the parts of CMSIS-DSP a sensor node uses. */
#include <stdio.h>
#include "arm_math.h"

#define SAMPLES 32
#define TAPS 8

static float32_t signal[SAMPLES], filtered[SAMPLES], smoothed[SAMPLES];
static float32_t fir_state[SAMPLES + TAPS - 1], biquad_state[8];
static const float32_t taps[TAPS] = {0.02f, 0.06f, 0.16f, 0.26f, 0.26f, 0.16f, 0.06f, 0.02f};
static const float32_t biquad[10] = {0.2f, 0.4f, 0.2f, 0.6f, -0.3f, 0.3f, 0.3f, 0.0f, 0.4f, 0.0f};
static q15_t samples_q15[SAMPLES], filtered_q15[SAMPLES], taps_q15[TAPS], state_q15[SAMPLES + TAPS];

int main(void)
{
    arm_fir_instance_f32 fir;
    arm_biquad_casd_df1_inst_f32 cascade;
    float32_t mean, rms, deviation, largest, a[4] = {1, 2, 3, 4}, b[4] = {4, 3, 2, 1}, c[4];
    float32_t complex[8] = {1, 2, 3, 4, 5, 6, 7, 8}, magnitude[4];
    uint32_t at;
    arm_matrix_instance_f32 ma, mb, mc;
    for (int i = 0; i < SAMPLES; i++)
        signal[i] = (float32_t)((i * 7) % 13) - 6.0f;
    arm_fir_init_f32(&fir, TAPS, taps, fir_state, SAMPLES);
    arm_fir_f32(&fir, signal, filtered, SAMPLES);
    arm_biquad_cascade_df1_init_f32(&cascade, 2, biquad, biquad_state);
    arm_biquad_cascade_df1_f32(&cascade, filtered, smoothed, SAMPLES);
    arm_mean_f32(smoothed, SAMPLES, &mean);
    arm_rms_f32(smoothed, SAMPLES, &rms);
    arm_std_f32(smoothed, SAMPLES, &deviation);
    arm_max_f32(smoothed, SAMPLES, &largest, &at);
    arm_mat_init_f32(&ma, 2, 2, a);
    arm_mat_init_f32(&mb, 2, 2, b);
    arm_mat_init_f32(&mc, 2, 2, c);
    arm_mat_mult_f32(&ma, &mb, &mc);
    arm_cmplx_mag_f32(complex, magnitude, 4);
    arm_float_to_q15(signal, samples_q15, SAMPLES);
    arm_float_to_q15(taps, taps_q15, TAPS);
    arm_scale_q15(samples_q15, 0x4000, 0, filtered_q15, SAMPLES);
    arm_add_f32(filtered, smoothed, signal, SAMPLES);
    (void)state_q15;
    printf("%d %d %d %d %u %d %d\n", (int)(mean * 1000), (int)(rms * 1000), (int)(deviation * 1000), (int)(largest * 1000),
           (unsigned)at, (int)c[0], (int)(magnitude[3] * 100));
    for (;;)
        ;
}
