#pragma once
#include "common.h"
class Parameter
{
public:
	static HashFunction seletedHashFunction; // select sha256/384/512
	static int n;							 // byte number of hash,32/48/64
	static int l1;							 // number of chains
	static int E;							 // number of epochs
	static long long P[128 / 64];
	static int popa_n; // number of aliveness proof in an ACS
	static int S_wk;

	// Time
	static int k;		  // security parameter
	static SetPMS SetPms; // SetPMS
	static int T_be;	  // end time of last proof
	static int T_c;		  // current time
	static Pai pai;		  // cv, root
	static int T_ps_real; // unix time
	// HPoW
	static int pms_HP;			   // pms of HP
	static int d;				   // puzzle difficulty
	static long long cv[256 / 64]; // check value
	// PRG
	static long long pms_G[128 / 64]; // pms of PRG, key
	static vector<char *> S;		  // secret seed, S0_0
	// Merkle Tree
	static int pms_MT; // pms of MT
	static int u;	   // number of leaves

	static vector<unsigned char *> ES;
	static vector<unsigned char *> IES;
	static vector<unsigned char *> CCS;
	static vector<unsigned char *> CS;
	static vector<unsigned char *> C;
	static vector<unsigned char *> SKS;
	static vector<unsigned char *> SKE;

	static int
	pow(int a, int b);
	static void Setup(int k, int difficulty, int height);

	// hash algorithm
	static void SHA256(const char *input, char *output, size_t len);
	static void SHA384(const char *input, char *output, size_t len);
	static void SHA512(const char *input, char *output, size_t len);

	// type conversion
	static void int2byte(const int IntValue, unsigned char *Chars);
	static void longlong2byte(const long long IntValue, unsigned char *Chars);
	static int byte2int(const unsigned char *Chars);
	static long long byte2longlong(const unsigned char *Chars);
	static int hex2byte(char *str, unsigned char *out, int hexlen);
	static void byte2hex(unsigned char *byteArray, char *charArray, int bytelen);

	// generate cryptographically randomness
	static void randnum(long long *out);
	static void randnum(int *out);

	static int GetTime();
};