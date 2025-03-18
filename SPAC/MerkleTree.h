#pragma once
#include "common.h"
class MT
{
public:
	static xmss_params params;
	static bds_state *state[2];	   // BDS
	static unsigned char *root[2]; // root
	static unsigned int *laddr;

	static void Setup(int k);
	static void Build();
	static void GetPrf(const unsigned long leaf_idx, unsigned char *out, int epoch); //
	static bool Verify(const unsigned char *root, const char *leaf_value, const int leaf_idx, const char *proof);

	static void Prepare4Build();
	static void testleftProofGen();
};