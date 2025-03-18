#include "Parameter.h"
#include "PRG.h"
#include "HPoW.h"
#include "MerkleTree.h"
#include "Client.h"
#include "Verifier.h"
#include "Auditor.h"

long long Parameter::pms_G[128 / 64];
vector<char *> Parameter::S;
int Parameter::d;
int SetPMS::T_ps;
int SetPMS::T_a;
int SetPMS::T_ls;
Aux SetPMS::aux;
int Parameter::T_be;
int Parameter::T_c;
int Parameter::u;
long long Parameter::cv[256 / 64];
HashFunction Parameter::seletedHashFunction;
int Parameter::n;
Pai Parameter::pai;
int Parameter::T_ps_real;

int Parameter::l1;
int Parameter::E;
int Parameter::popa_n;
int Parameter::S_wk;
long long Parameter::P[128 / 64];

vector<unsigned char *> Parameter::ES;
vector<unsigned char *> Parameter::IES;
vector<unsigned char *> Parameter::CCS;
vector<unsigned char *> Parameter::CS;
vector<unsigned char *> Parameter::C;
vector<unsigned char *> Parameter::SKS;
vector<unsigned char *> Parameter::SKE;

// compute a^b
int Parameter::pow(int a, int b)
{
	int result = 1;
	for (int i = 0; i < b; i++)
		result *= a;
	return result;
}

void allocateMemory(vector<unsigned char *> &vec, int size, int n)
{
	vec.resize(size);
	for (int i = 0; i < size; i++)
		vec[i] = new unsigned char[2 * n + 1]; // 256bit(n=32)
}

void releaseMemory(vector<unsigned char *> &vec, int size, int n)
{
	for (int i = 0; i < size; ++i)
	{
		delete[] vec[i];
	}
	vec.clear();
}

void Parameter::Setup(int k, int difficulty, int height)
{
	SetPms.T_ps = 0;			  // start time of a protocol instance
	SetPms.T_a = 1;				  // time of aliveness proof
	SetPms.T_ls = pow(2, height); // life span of PoPA instance
	SetPms.aux.l0 = 1;
	SetPms.aux.w = 16;
	SetPms.aux.T_h = 1;

	T_be = 0;							 // end time of last proof
	T_c = 0;							 // current time
	l1 = 64;							 // num of leaves
	E = 2;								 // epochs
	S_wk = 7 * 64;						 // Sw,k
	popa_n = (SetPms.aux.w) * l1 - S_wk; // number of aliveness proof in an ACS

	time_t current_time;
	time(&current_time);
	T_ps_real = current_time;

	u = SetPms.T_ls / SetPms.T_a; // number of leaves/chains

	seletedHashFunction = SHA256;
	if (Parameter::seletedHashFunction == Parameter::SHA256)
		n = 256 / 8;
	else if (Parameter::seletedHashFunction == Parameter::SHA384)
		n = 384 / 8;
	else if (Parameter::seletedHashFunction == Parameter::SHA512)
		n = 512 / 8;

	for (int j = 0; j < 2; ++j)
		Parameter::randnum(&P[j]);

	// pms_G(aes key)
	Parameter::randnum(&pms_G[0]);
	Parameter::randnum(&pms_G[1]);

	PRG::Setup(k);

	// puzzle difficulty(0-256)
	d = difficulty;

	// check value
	for (int j = 0; j < 4; ++j)
		Parameter::randnum(&pai.cv[j]);

	HP::Setup(k, SetPms.aux);

	allocateMemory(ES, E + 1, n);
	allocateMemory(IES, E + 1, n);
	allocateMemory(CCS, (E + 1) * (l1 + 1), n);
	allocateMemory(CS, (E + 1) * (l1 + 1) * (SetPms.aux.w + 1), n);
	allocateMemory(C, (E + 1) * (l1 + 1) * (SetPms.aux.w + 1), n);
	allocateMemory(SKS, (E + 1) * (l1 + 1), n);
	allocateMemory(SKE, (E + 1) * (l1 + 1) * (SetPms.aux.w + 1), n);

	// random choose ES0
	long long temp_rand[256 / 64];
	unsigned char temp_ES0[256 / 8];
	for (int j = 0; j < 4; ++j)
	{
		Parameter::randnum(&temp_rand[j]);
		Parameter::longlong2byte(temp_rand[j], temp_ES0 + j * 8);
	}
	Parameter::byte2hex(temp_ES0, (char *)ES[0], 256 / 8);

	// merkle tree, bds
	MT::Setup(k);
	MT::Prepare4Build(); // compute leaf using PRG
	MT::Build();

	Client::Setup();
	Verifer::Setup();
	Auditor::Setup();

	releaseMemory(ES, E + 1, n);
	releaseMemory(IES, E + 1, n);
	releaseMemory(CCS, (E + 1) * (l1 + 1), n);
	releaseMemory(CS, (E + 1) * (l1 + 1) * (SetPms.aux.w + 1), n);
	// releaseMemory(C, (E + 1) * (l1 + 1) * (SetPms.aux.w + 1), n);
	releaseMemory(SKS, (E + 1) * (l1 + 1), n);
	// releaseMemory(SKE, (E + 1) * (l1 + 1) * (SetPms.aux.w + 1), n);
}

void Parameter::SHA256(const char *input, char *output, size_t len)
{
	sha256 sh;
	int i;
	shs256_init(&sh);
	for (i = 0; i < len; i++)
	{
		shs256_process(&sh, input[i]);
	}
	shs256_hash(&sh, output);
}

void Parameter::SHA384(const char *input, char *output, size_t len)
{
	sha384 sh;
	int i;
	shs384_init(&sh);
	for (i = 0; i < len; i++)
	{
		shs384_process(&sh, input[i]);
	}
	shs384_hash(&sh, output);
}

void Parameter::SHA512(const char *input, char *output, size_t len)
{
	sha512 sh;
	int i;
	shs512_init(&sh);
	for (i = 0; i < len; i++)
	{
		shs512_process(&sh, input[i]);
	}
	shs512_hash(&sh, output);
}

void Parameter::int2byte(const int IntValue, unsigned char *Chars)
{
	int numBytes = sizeof(int);
	for (int i = 0; i < numBytes; ++i)
	{
		Chars[i] = (IntValue >> (8 * (numBytes - 1 - i))) & 255;
	}
}

void Parameter::longlong2byte(const long long IntValue, unsigned char *Chars)
{
	int numBytes = sizeof(long long);
	for (int i = 0; i < numBytes; ++i)
	{
		Chars[i] = (IntValue >> (8 * (numBytes - 1 - i))) & 255;
	}
}

int Parameter::byte2int(const unsigned char *Chars)
{
	int result = 0;

	for (int i = 0; i < 4; ++i)
	{
		result = (result << 8) | Chars[i];
	}

	return result;
}

long long Parameter::byte2longlong(const unsigned char *Chars)
{
	long long result = 0;

	for (int i = 0; i < 8; ++i)
	{
		result = (result << 8) | Chars[i];
	}

	return result;
}

int Parameter::hex2byte(char *str, unsigned char *out, int hexlen)
{
	char *p = str;
	char high = 0, low = 0;
	int tmplen = strlen(p), cnt = 0;
	while (cnt < (hexlen / 2))
	{
		high = ((*p > '9') && ((*p <= 'F') || (*p <= 'f'))) ? *p - 48 - 7 : *p - 48;
		low = (*(++p) > '9' && ((*p <= 'F') || (*p <= 'f'))) ? *(p)-48 - 7 : *(p)-48;
		out[cnt] = ((high & 0x0f) << 4 | (low & 0x0f));
		p++;
		cnt++;
	}
	if (tmplen % 2 != 0)
		out[cnt] = ((*p > '9') && ((*p <= 'F') || (*p <= 'f'))) ? *p - 48 - 7 : *p - 48;

	return tmplen / 2 + tmplen % 2;
}

void Parameter::byte2hex(unsigned char *byteArray, char *charArray, int bytelen)
{
	int length = Parameter::n * 2;
	for (int i = 0; i < bytelen; ++i)
	{
		sprintf(charArray + i * 2, "%02X", byteArray[i]);
	}
}

void Parameter::randnum(long long *out)
{
	big w = mirvar(0), x = mirvar(0);
	char raw[16];
	csprng rng;

	expb2(64 - 1, w);
	for (int i = 0; i < 16; i++)
	{
		raw[i] = (char)((double)rand() / RAND_MAX * 256);
	}
	long tod = time(nullptr);

	strong_init(&rng, sizeof(raw), raw, tod);
	strong_bigrand(&rng, w, x);

	char b[8];
	big_to_bytes(8, x, b, FALSE);
	*out = byte2longlong((unsigned char *)b);
}

void Parameter::randnum(int *out)
{
	big w = mirvar(0), x = mirvar(0);
	char raw[16];
	csprng rng;

	expb2(32 - 1, w);
	for (int i = 0; i < 16; i++)
	{
		raw[i] = (char)((double)rand() / RAND_MAX * 256);
	}
	int tod = time(nullptr);

	strong_init(&rng, sizeof(raw), raw, tod);
	strong_bigrand(&rng, w, x);

	char b[4];
	big_to_bytes(4, x, b, FALSE);
	*out = byte2int((unsigned char *)b);
}

int Parameter::GetTime()
{
	time_t stop;
	time(&stop);
	return (int)(stop - Parameter::T_ps_real);
}
