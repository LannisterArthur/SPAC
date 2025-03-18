#pragma once
#include "common.h"
class Client
{
public:
	static unsigned char *sk;
	static state_c st;
	static alive_prf p;

	static void Setup();
	static bool ProofGen(unsigned char *sk, state_c *st_ic, int T);
	static void releaseMemory()
	{
		if (sk != nullptr)
		{
			delete[] sk;
			sk = nullptr;
		}

		if (st.cv != nullptr)
		{
			delete[] st.cv;
			st.cv = nullptr;
		}
		if (st.CCS != nullptr)
		{
			delete[] st.CCS;
			st.CCS = nullptr;
		}
		if (st.SKS != nullptr)
		{
			delete[] st.SKS;
			st.SKS = nullptr;
		}
		if (st.C != nullptr)
		{
			delete[] st.C;
			st.C = nullptr;
		}
		if (st.SKE != nullptr)
		{
			delete[] st.SKE;
			st.SKE = nullptr;
		}
		if (st.root != nullptr)
		{
			delete[] st.root;
			st.root = nullptr;
		}
		if (st.m != nullptr)
		{
			delete[] st.m;
			st.m = nullptr;
		}
		if (st.proof != nullptr)
		{
			delete[] st.proof;
			st.proof = nullptr;
		}

		if (p.Credential != nullptr)
		{
			delete[] p.Credential;
			p.Credential = nullptr;
		}
		if (p.proof != nullptr)
		{
			delete[] p.proof;
			p.proof = nullptr;
		}
		if (p.SKE != nullptr)
		{
			delete[] p.SKE;
			p.SKE = nullptr;
		}
		if (p.root != nullptr)
		{
			delete[] p.root;
			p.root = nullptr;
		}
	}
};