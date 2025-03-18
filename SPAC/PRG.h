#pragma once
#include "common.h"
class PRG
{
public:
	static long long pms_G[2]; // pms of PRG, key

	static void Setup(int k);
	static void Gen(const char *input, char *output);
};