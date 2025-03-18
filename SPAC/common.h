#pragma once
#include <cstdio>
#include <iostream>
#include <cstring>
#include <vector>
#include <iomanip>
#include <time.h>

extern "C"
{
#include <miracl/miracl.h>
}

using namespace std;

// time
struct Aux
{
    int w;
    int l0;
    int f;   // failure-tolerant time
    int T_h; // expected running time of hash
};
struct SetPMS
{
    static int T_ps; // start time of a protocol instance
    static int T_a;  // time of aliveness proof
    static int T_ls; // life span of PoPA instance
    static Aux aux;
};

// pow
struct Puzzle
{
    unsigned char DV[256 / 8]; // byte
    unsigned char cm[256 / 4]; // challenge-message
};

// hash
typedef void (*HashFunction)(const char *, char *, size_t);

// parameter
struct Pai
{
    long long cv[256 / 64];          // check value
    unsigned char root[256 / 8 * 2]; // two trees' root
};

// bds
typedef unsigned int uint32_t;
typedef struct
{
    unsigned int n; // number of bytes of hash function output
    unsigned int tree_height;
    unsigned int bds_k;
} xmss_params;
typedef struct
{
    unsigned char h;
    unsigned long next_idx; // treehash.initialize(next_idx)
    unsigned char stackusage;
    unsigned char completed;
    unsigned char *node;
} treehash_inst;
typedef struct
{
    unsigned char *stack;
    unsigned int stackoffset; // pointer of stack
    unsigned char *stacklevels;
    unsigned char *auth;
    unsigned char *keep;
    treehash_inst *treehash;
    unsigned char *retain;
    unsigned int next_leaf;
} bds_state;

// verifier&Åauditor
typedef struct
{
    unsigned char *Credential;
    unsigned char *proof;
    long long cnt;

    unsigned char *SKE;
    unsigned char *root;
    long long salt;

} alive_prf;
typedef struct
{
    unsigned int *index;
    alive_prf *p;
    unsigned char *cv;
    int T_ack;

    unsigned int *x;
    unsigned int *y;
    unsigned short *z;

} state;

// client
typedef struct
{
    unsigned int index;
    unsigned char *cv;
    int T_be;

    unsigned int x;
    unsigned int y;
    unsigned int z;
    unsigned char *CCS;
    unsigned char *SKS;
    unsigned char *C;
    unsigned char *SKE;
    unsigned char *root;
    long long salt;
    unsigned short *m;
    unsigned char *proof;

} state_c;
