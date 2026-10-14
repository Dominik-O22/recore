#pragma once
#define NAN __builtin_nanf("")
#define INFINITY __builtin_inff()
#define isnan(x) __builtin_isnan(x)
float sqrtf(float);
float fabsf(float);
double fabs(double);
double sqrt(double);
