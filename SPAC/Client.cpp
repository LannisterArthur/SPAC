#include "Client.h"
#include "Parameter.h"
#include "MerkleTree.h"
#include "HPoW.h"
#include "PRG.h"

unsigned char *Client::sk;
state_c Client::st;
alive_prf Client::p;

void Client::Setup()
{
    sk = new unsigned char[2 * Parameter::n];
    st.cv = new unsigned char[Parameter::n];
    p.Credential = new unsigned char[2 * Parameter::n];

    st.index = 0;
    st.T_be = Parameter::SetPms.T_ps;
    memcpy(st.cv, HP::cv, Parameter::n);

    int w = Parameter::SetPms.aux.w;
    int n = Parameter::n;
    int E = Parameter::E;
    int L1 = Parameter::l1;

    st.proof = new unsigned char[MT::params.tree_height * MT::params.n];
    st.CCS = new unsigned char[2 * n];
    st.SKS = new unsigned char[2 * n];
    st.C = new unsigned char[w * 2 * n];
    st.SKE = new unsigned char[w * 2 * n];
    st.root = new unsigned char[n];
    st.m = new unsigned short[L1];
    p.SKE = new unsigned char[2 * n];
    p.root = nullptr;
    p.proof = nullptr;

    st.x = 1;
    st.y = 1;
    st.z = 0;

    // set CCS1,1、SKS1,1、C、SKE、root、pf
    memcpy(st.CCS, Parameter::CCS[1 * L1 + 1], 2 * n);
    memcpy(st.SKS, Parameter::SKS[1 * L1 + 1], 2 * n);
    int x = st.x, y = st.y, z = st.z;
    for (int j = 1; j <= w; j++)
    {
        memcpy(st.C + (j - 1) * 2 * n, Parameter::C[x * L1 * w + y * w + j], 2 * n);
    }
    for (int v = 0; v <= w - 1; v++)
    {
        memcpy(st.SKE + v * 2 * n, Parameter::SKE[x * L1 * w + y * w + v], 2 * n);
    }
    memcpy(st.root, Parameter::pai.root + n, n);

    // set m, salt
    st.salt = HP::FindSalt(st.root, st.m);

    // compute mt proof
    MT::GetPrf(y - 1, st.proof, x);

    // sk_ic=ES1
    memcpy(sk, Parameter::ES[1], 2 * n);
}

bool Client::ProofGen(unsigned char *sk, state_c *st_ic, int T)
{

    if (0 && (T < st_ic->T_be || T > st_ic->T_be + Parameter::SetPms.aux.f))
        return false;

    st_ic->index += 1;

    unsigned int x = st_ic->x, y = st_ic->y, z = st_ic->z;
    unsigned int w = Parameter::SetPms.aux.w, L1 = Parameter::l1;
    unsigned int n = Parameter::n;
    const unsigned short my = st_ic->m[y - 1];

    unsigned char temp_C[2 * n], temp_SKE[2 * n];
    unsigned char temp_proof[MT::params.tree_height * MT::params.n];
    long long temp_salt = st_ic->salt;

    memcpy(temp_proof, st_ic->proof, MT::params.tree_height * MT::params.n);

    // no switch task(ST0)
    if (z >= 0 && z < w - my)
    {
        z = z + 1;
        memcpy(temp_C, Parameter::C[x * L1 * w + y * w + z], 2 * n);
        memcpy(temp_SKE, Parameter::SKE[x * L1 * w + y * w + w - z], 2 * n);
    }

    // chain switch(ST1)
    else if (z == w - my && y >= 1 && y <= L1 - 1)
    {
        y = y + 1;
        z = 1;

        memcpy(temp_C, Parameter::C[x * L1 * w + y * w + 1], 2 * n);
        memcpy(temp_SKE, Parameter::SKE[x * L1 * w + y * w + w - 1], 2 * n);

        // get Merkle proof -> p.proof
        MT::GetPrf(y - 1, temp_proof, x);
    }

    // epoch switch(ST2)
    else if (z == w - my && y == L1)
    {
        x = x + 1;
        y = 1;
        z = 1;

        memcpy(temp_C, Parameter::C[x * L1 * w + y * w + 1], 2 * n);
        memcpy(temp_SKE, Parameter::SKE[x * L1 * w + y * w + w - 1], 2 * n);

        // get Merkle proof -> p.proof
        MT::GetPrf(y - 1, temp_proof, x);

        // update m
        if (x != Parameter::E)
            temp_salt = HP::FindSalt(st_ic->root, st_ic->m);
    }

    /*****generate proof*****/
    // i. set cm
    char cm[2 * n];
    memcpy(cm, Parameter::C[x * L1 * w + y * w + z], 2 * n);

    // ii.
    HP::Gen(HP::d, cm, (char *)st_ic->cv);

    // iii. compute solution and check-value
    long long cnt = HP::Solve(&HP::p);
    memcpy(st_ic->cv, HP::cv, n);

    // set p=(C SKE prf cnt root salt)
    memcpy(p.Credential, temp_C, 2 * n);
    memcpy(p.SKE, temp_SKE, 2 * n);
    p.cnt = cnt;

    if (z > 1)
    {
        p.proof = nullptr;
    }
    else
    {
        if (p.proof == nullptr)
            p.proof = new unsigned char[MT::params.tree_height * MT::params.n];
        memcpy(p.proof, temp_proof, MT::params.tree_height * MT::params.n);
    }

    if (st_ic->index % Parameter::popa_n != 0)
    {
        p.root = nullptr;
        p.salt = -1;
    }
    else
    {
        if (p.root == nullptr)
            p.root = new unsigned char[n];
        memcpy(p.root, st_ic->root, n);
        p.salt = temp_salt;
    }

    st_ic->x = x;
    st_ic->y = y;
    st_ic->z = z;

    return true;
}