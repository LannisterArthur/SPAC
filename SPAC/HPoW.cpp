#include "HPoW.h"
#include "Parameter.h"
int HP::d;
long long HP::solution;
Puzzle HP::p;
unsigned char *HP::cv;

void HP::Setup(int k, Aux aux)
{
	// difficulty
	d = Parameter::d;
	// DV
	memset(p.DV, 0, 256 / 8);
	// challenge-message
	const char *hexString = "e7c216e2f2e74ca420b92c6130d40d67087d323ac3cc802f2a841b0e60b56b4d";
	memcpy(p.cm, hexString, 64);
	// check value
	cv = new unsigned char[Parameter::n];
	for (unsigned int i = 0; i < 4; i++)
	{
		Parameter::longlong2byte(Parameter::pai.cv[i], cv + 8 * i);
	}
}

void HP::Gen(int d, char *cm, char *cv)
{
	memcpy(p.cm, cm, 256 / 4);
	// generate DV = sha256(cm||cv||0)
	long long cnt = 0;
	unsigned char tempdata[(256 + 256 + 64) / 8];
	Parameter::hex2byte((char *)p.cm, tempdata, 64);
	memcpy(tempdata + 256 / 8, cv, 256 / 8);
	Parameter::longlong2byte(cnt, tempdata + (256 * 2) / 8);
	Parameter::seletedHashFunction((char *)tempdata, (char *)p.DV, (256 + 256 + 64) / 8);
}

long long HP::Solve(Puzzle *p)
{
	HP::solution = 1;
	int bytes = d / 8;
	int bits = d % 8;
	int valid;
	char hash[32]; // hash result
	unsigned char data_char[32 * 2 + 1];
	unsigned char mask = 0xFF << (8 - bits);
	unsigned char s[8]; // solution,byte

	Parameter::longlong2byte(HP::solution, s);

	Parameter::hex2byte((char *)p->cm, data_char, 64);
	memcpy(data_char + 32, cv, 32);

	do
	{
		// Concatenate data and nonce
		char input[32 * 2 + 8];
		memcpy(input, data_char, 32 * 2);
		memcpy(input + 32 * 2, s, 8);

		// Compute the SHA-256 hash
		Parameter::seletedHashFunction(input, hash, 32 * 2 + 8);

		// Check if the hash meets the target difficulty
		valid = 1;
		int j;
		for (j = 0; j < bytes; j++)
		{
			if ((unsigned char)hash[j] != p->DV[j])
			{
				valid = 0;
				break;
			}
		}
		if (((unsigned char)(hash[j]) & mask) != (p->DV[j] & mask))
		{
			valid = 0;
		}

		// Increment nonce
		for (int i = 7; i >= 0; i--)
		{
			if (s[i] < 255)
			{
				s[i]++;
				break;
			}
			else
			{
				s[i] = 0;
			}
		}

		// check if nonce is used up
		if (s[0] == 0 && s[1] == 0 && s[2] == 0 && s[3] == 0 && s[4] == 0 && s[5] == 0 && s[6] == 0 && s[7] == 0)
		{
			return -1;
		}
	} while (!valid);

	// recover nonce
	for (int i = 7; i >= 0; i--)
	{
		if (s[i] != 0)
		{
			s[i]--;
			break;
		}
		else
		{
			s[i] = 255;
		}
	}
	solution = Parameter::byte2longlong(s);
	memcpy(cv, hash, Parameter::n);

	return solution;
}

bool HP::Verify(Puzzle p, long long cnt, char *cv)
{
	int bytes = d / 8;
	int bits = d % 8;
	int valid = 1;
	unsigned char mask = 0xFF << (8 - bits);
	char hash[32]; // hash result
	unsigned char data_char[32 * 2 + 1];
	unsigned char s[8]; // solution,byte

	Parameter::longlong2byte(cnt, s);

	Parameter::hex2byte((char *)p.cm, data_char, 64);
	memcpy(data_char + 32, cv, 32);

	if (cnt < Parameter::pow(2, d + 1))
	{
		// Concatenate data and nonce
		char input[32 * 2 + 8];
		memcpy(input, data_char, 32 * 2);
		memcpy(input + 32 * 2, s, 8);

		// Compute the SHA-256 hash
		Parameter::seletedHashFunction(input, hash, 32 * 2 + 8);

		int j;
		for (j = 0; j < bytes; j++)
		{
			if ((unsigned char)hash[j] != p.DV[j])
			{
				valid = 0;
				break;
			}
		}
		if (((unsigned char)(hash[j]) & mask) != (p.DV[j] & mask))
		{
			valid = 0;
		}
	}
	else
	{
		Parameter::longlong2byte(1, s);
		do
		{
			// Concatenate data and nonce
			char input[32 * 2 + 8];
			memcpy(input, data_char, 32 * 2);
			memcpy(input + 32 * 2, s, 8);

			// Compute the SHA-256 hash
			Parameter::seletedHashFunction(input, hash, 32 * 2 + 8);

			// Check if the hash meets the target difficulty
			valid = 1;
			int j;
			for (j = 0; j < bytes; j++)
			{
				if ((unsigned char)hash[j] != p.DV[j])
				{
					valid = 0;
					break;
				}
			}
			if (((unsigned char)(hash[j]) & mask) != (p.DV[j] & mask))
			{
				valid = 0;
			}

			// Increment nonce
			for (int i = 7; i >= 0; i--)
			{
				if (s[i] < 255)
				{
					s[i]++;
					break;
				}
				else
				{
					s[i] = 0;
				}
			}

			// check if nonce is used up
			if (s[0] == 0 && s[1] == 0 && s[2] == 0 && s[3] == 0 && s[4] == 0 && s[5] == 0 && s[6] == 0 && s[7] == 0)
			{
				return -1;
			}
		} while (!valid);

		// recover nonce
		for (int i = 7; i >= 0; i--)
		{
			if (s[i] != 0)
			{
				s[i]--;
				break;
			}
			else
			{
				s[i] = 255;
			}
		}
		if (cnt != Parameter::byte2longlong(s))
			valid = 0;
	}
	return valid;
}

// find salt, set m=H(input||salt)
long long HP::FindSalt(unsigned char *input, unsigned short *m)
{
	long long salt = 1, sum = 0;
	unsigned char data[32 + sizeof(long long)], hash[32];
	memcpy(data, input, 32);

	while (true)
	{
		Parameter::longlong2byte(salt, data + Parameter::n);
		Parameter::seletedHashFunction((char *)data, (char *)hash, 32 + sizeof(long long));

		sum = 0;

		for (int i = 0; i < 32; ++i)
		{
			sum += (hash[i] >> 4) + (hash[i] & 0x0F);
		}

		if (sum == Parameter::S_wk)
		{
			for (int i = 0; i < 32; i++)
			{
				m[2 * i] = hash[i] >> 4;
				m[2 * i + 1] = hash[i] & 0x0F;
			}
			return salt;
		}

		++salt;
	}
}
