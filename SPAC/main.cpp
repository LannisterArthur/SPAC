#include "Parameter.h"
#include "PRG.h"
#include "HPoW.h"
#include "MerkleTree.h"
#include "Client.h"
#include "Verifier.h"
#include "Auditor.h"

#define CALC(start, stop) ((stop.tv_sec - start.tv_sec) * 1e6 + (stop.tv_nsec - start.tv_nsec) / 1e3)

void releaseMemory()
{
	Auditor::releaseMemory();
	Client::releaseMemory();
	Verifer::releaseMemory();
}

int test_case(int difficulty)
{

	struct timespec start, stop;
	double result[4] = {0};
	double temp;
	char filename[256];
	snprintf(filename, 256, "%s%d%s%s", "popa_ots_difficulty", difficulty, "_height6", ".txt");

	/*
	 *test Setup
	 **/
	clock_gettime(CLOCK_REALTIME, &start);

	Parameter::Setup(128, difficulty, 6);

	clock_gettime(CLOCK_REALTIME, &stop);
	result[0] = CALC(start, stop);

	// write to file
	FILE *file = fopen(filename, "a");
	fprintf(file, "\n\nRuntime as follows:\n");
	fprintf(file, "runtime of Setup() is %lf us(%.2lf sec)\n", result[0], result[0] / 1e6);
	fflush(file);

	// PoPA test
	bool res = false;

	int num = Parameter::popa_n;

	for (int i = 1; i <= num; i++)
	{
		/*
		 *test ProofGen
		 **/
		int T_c = Parameter::GetTime();

		clock_gettime(CLOCK_REALTIME, &start);

		res = Client::ProofGen(Client::sk, &Client::st, T_c);

		clock_gettime(CLOCK_REALTIME, &stop);
		temp = CALC(start, stop);
		result[1] += temp;

		if (res)
			;
		else
		{
			printf("%dth ProofGen error\n", i);
			break;
		}

		/*
		 *test Verify
		 **/
		int T_r = Parameter::GetTime();
		clock_gettime(CLOCK_REALTIME, &start);

		res = Verifer::Verify(&Parameter::pai, &Verifer::st, &Client::p, T_r, true, false);

		clock_gettime(CLOCK_REALTIME, &stop);
		temp = CALC(start, stop);
		result[2] += temp;

		if (res)
			;
		else
		{
			printf("%dth Verify error\n", i);
			break;
		}
	}

	// write to file
	fprintf(file, "runtime of ProofGen() is %lf us(%.2lf sec)\n", result[1], result[1] / 1e6);
	fprintf(file, "runtime of Verify() is %lf us(%.2lf sec)\n", result[2], result[2] / 1e6);
	fflush(file);

	/*
	 *test Audit
	 **/
	int T = Parameter::GetTime();
	clock_gettime(CLOCK_REALTIME, &start);

	res = Auditor::Audit(&Verifer::st, &Auditor::st, T);

	clock_gettime(CLOCK_REALTIME, &stop);
	result[3] = CALC(start, stop);
	if (res)
		;
	else
	{
		printf("Audit error\n");
	}

	int auditnum = Auditor::st[0].z[0];

	releaseMemory();

	/*
	 *test left ProofGen
	 **/
	clock_gettime(CLOCK_REALTIME, &start);

	MT::testleftProofGen();

	clock_gettime(CLOCK_REALTIME, &stop);
	temp = CALC(start, stop);
	result[1] += temp;

	// print runtime
	printf("\n\nRuntime as follows:\n");
	printf("runtime of Setup() is %lf us(%.2lf sec)\n", result[0], result[0] / 1e6);

	printf("runtime of ProofGen() is %lf us(%.2lf sec)\n", result[1], result[1] / 1e6);

	printf("runtime of Verify() is %lf us(%.2lf sec)\n", result[2], result[2] / 1e6);

	printf("runtime of Audit() is %lf us(%.2lf sec)\n", result[3], result[3] / 1e6);

	// write to file
	fprintf(file, "runtime of Audit() is %lf us(%.2lf sec)\n", result[3], result[3] / 1e6);

	double setupAvg = result[0];
	double proofGenAvg = result[1] / num;
	double verifyAvg = result[2] / num;
	double auditAvg = result[3] * 256 / auditnum;

	printf("\n\nStatistics for test:\n");
	printf("Setup(): Avg: %lf us (%lf sec)\n", setupAvg, setupAvg / 1e6);
	printf("ProofGen(): Avg: %lf us (%lf sec)\n", proofGenAvg, proofGenAvg / 1e6);
	printf("Verify(): Avg: %lf us (%lf sec)\n", verifyAvg, verifyAvg / 1e6);
	printf("Audit():  Avg: %lf us (%lf sec)\n", auditAvg, auditAvg / 1e6);

	fprintf(file, "\n\nStatistics for tests:\n");
	fprintf(file, "Setup(): Avg: %lf us (%lf sec)\n", setupAvg, setupAvg / 1e6);
	fprintf(file, "ProofGen(): Avg: %lf us (%lf sec)\n", proofGenAvg, proofGenAvg / 1e6);
	fprintf(file, "Verify(): Avg: %lf us (%lf sec)\n", verifyAvg, verifyAvg / 1e6);
	fprintf(file, "Audit():  Avg: %lf us (%lf sec)\n", auditAvg, auditAvg / 1e6);

	fclose(file);
	return 0;
}

int main()
{
	miracl *mip = mirsys(1000, 10);
	srand((unsigned int)time(NULL));

	// set difficulty
	test_case(16);

	return 0;
}
