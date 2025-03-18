#pragma once
#include "common.h"
class HP
{
public:
	static int d;				   // difficulty
	static Puzzle p;			   // puzzle=(DV,cm)
	static long long solution;	   // solution
	static unsigned char *cv;	   // check-value
	static unsigned char *last_cv; // check-value

	static void Setup(int k, Aux aux);
	static void Gen(int d, char *cm, char *cv);
	static long long Solve(Puzzle *p);
	static bool Verify(Puzzle p, long long s, char *cv);

	static long long FindSalt(unsigned char *input, unsigned short *m);
};