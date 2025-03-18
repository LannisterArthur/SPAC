#pragma once
#include "common.h"
class Auditor
{
public:
	static vector<state> st;

	static void Setup();
	static bool Audit(vector<state> *st_is, vector<state> *st_ia, int T);
	static void releaseMemory()
	{

		if (st[0].x != nullptr)
		{
			delete[] st[0].x;
			st[0].x = nullptr;
		}
		if (st[0].y != nullptr)
		{
			delete[] st[0].y;
			st[0].y = nullptr;
		}
		if (st[0].z != nullptr)
		{
			delete[] st[0].z;
			st[0].z = nullptr;
		}

		for (size_t i = 0; i < st.size(); ++i)
		{

			if (st[i].p != nullptr)
			{
				if (st[i].p->Credential != nullptr)
				{
					delete[] st[i].p->Credential;
					st[i].p->Credential = nullptr;
				}
				if (st[i].p->proof != nullptr)
				{
					delete[] st[i].p->proof;
					st[i].p->proof = nullptr;
				}
				if (st[i].p->SKE != nullptr)
				{
					delete[] st[i].p->SKE;
					st[i].p->SKE = nullptr;
				}
				if (st[i].p->root != nullptr)
				{
					delete[] st[i].p->root;
					st[i].p->root = nullptr;
				}
				delete st[i].p;
				st[i].p = nullptr;
			}
			if (st[i].cv != nullptr)
			{
				delete[] st[i].cv;
				st[i].cv = nullptr;
			}
		}
	}
};