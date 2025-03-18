#include "Verifier.h"
#include "Parameter.h"
#include "Client.h"
#include "MerkleTree.h"
#include "HPoW.h"
vector<state> Verifer::st;

void Verifer::Setup()
{
    st.resize(1);
    st[0].cv = new unsigned char[Parameter::n];
    st[0].index = new unsigned int[1];

    st[0].index[0] = 0;
    memcpy(st[0].cv, HP::cv, Parameter::n);
    st[0].T_ack = Parameter::SetPms.T_ps;

    st[0].x = new unsigned int[1];
    st[0].y = new unsigned int[1];

    st[0].x[0] = 0;
    st[0].y[0] = 0;

    st[0].z = new unsigned short[Parameter::l1];
    for (int i = 0; i < Parameter::l1; i++)
        st[0].z[i] = 0;
    st[0].p = nullptr;
}

bool Verifer::Verify(Pai *pai, vector<state> *st_is, alive_prf *p, int T_r, bool is_append, bool is_audit)
{

    // 1.
    if (0 && (T_r <= st_is->back().T_ack ||
              T_r >= st_is->back().T_ack + Parameter::SetPms.T_a + Parameter::SetPms.aux.f))
    {
        return false;
    }

    unsigned int n = Parameter::n, w = Parameter::SetPms.aux.w, L1 = Parameter::l1;
    unsigned int x = (*st_is)[0].x[0], y = (*st_is)[0].y[0]; // denote x^, y^
    unsigned int temp_x = 0, temp_y = 0;                     // denote x, y
    unsigned short temp_z = 0;                               // denote z^

    // VR0
    if (p->proof != nullptr && p->root == nullptr && p->salt == -1)
    {
        unsigned char temp_leaf[n], temp_hashinput[128 / 8 + 2 * n];

        // compute leaf
        for (int a = 0; a < 2; a++)
            Parameter::longlong2byte(Parameter::P[a], temp_hashinput + a * 8);
        Parameter::hex2byte((char *)p->Credential, temp_hashinput + 128 / 8, 2 * n);
        Parameter::hex2byte((char *)p->SKE, temp_hashinput + 128 / 8 + n, 2 * n);
        Parameter::seletedHashFunction((char *)temp_hashinput, (char *)temp_leaf, 128 / 8 + 2 * n);

        if (y == L1)
        {
            if (MT::Verify(p->root, (char *)temp_leaf, y - 1, (char *)p->proof) == false)
            {
                return false;
            }
        }
        else if (y >= 1 && y <= L1 - 1)
        {
            if (!is_audit)
            {
                if (MT::Verify(pai->root, (char *)temp_leaf, y, (char *)p->proof) == false)
                {
                    return false;
                }
            }
            else
            {
                if (MT::Verify(pai->root, (char *)temp_leaf, y - 1, (char *)p->proof) == false)
                {
                    return false;
                }
            }
        }

        if (y == L1)
        {
            // set x=x^+1, y=1
            temp_x = x + 1;
            temp_y = 1;
        }
        else
        {
            // set x=x^, y=y^+1
            temp_x = x;
            temp_y = y + 1;
        }

        // it also sets z=1 for pi
        temp_z = 1;

        // set cm
        unsigned char temp_cm[2 * n];
        memcpy(temp_cm, p->Credential, 2 * n);
        if (!is_audit)
        {
            HP::Gen(HP::d, (char *)temp_cm, (char *)st_is->back().cv);
            if (HP::Verify(HP::p, p->cnt, (char *)st_is->back().cv) == false)
            {
                return false;
            }
        }
        else
        {
            HP::Gen(HP::d, (char *)temp_cm, (char *)(*st_is)[st_is->size() - 2].cv);
            if (HP::Verify(HP::p, p->cnt, (char *)(*st_is)[st_is->size() - 2].cv) == false)
            {
                return false;
            }
        }
    }

    // VR1
    else if (p->root == nullptr && p->salt == -1)
    {

        unsigned char compare_SKE_hex[2 * n], compare_SKE_byte[n], temp_hashinput[128 / 8 + 2 * n];
        for (int a = 0; a < 2; a++)
            Parameter::longlong2byte(Parameter::P[a], temp_hashinput + a * 8);
        Parameter::hex2byte((char *)p->Credential, temp_hashinput + 128 / 8, 2 * n);
        Parameter::hex2byte((char *)p->SKE, temp_hashinput + 128 / 8 + n, 2 * n);
        Parameter::seletedHashFunction((char *)temp_hashinput, (char *)compare_SKE_byte, 128 / 8 + 2 * n);
        Parameter::byte2hex(compare_SKE_byte, (char *)compare_SKE_hex, n);
        if (!is_audit)
        {
            if (memcmp(compare_SKE_hex, st_is->back().p->SKE, 2 * n) != 0)
            {
                return false;
            }
        }
        else
        {
            if (memcmp(compare_SKE_hex, (*st_is)[st_is->size() - 2].p->SKE, 2 * n) != 0)
            {
                return false;
            }
        }

        // set x=x^, y=y^, z=z^[y^-1]+1
        temp_x = x;
        temp_y = y;
        temp_z = (*st_is)[0].z[y - 1] + 1;

        // examine solution
        unsigned char temp_cm[2 * n];
        memcpy(temp_cm, p->Credential, 2 * n);
        if (!is_audit)
        {
            HP::Gen(HP::d, (char *)temp_cm, (char *)st_is->back().cv);
            if (HP::Verify(HP::p, p->cnt, (char *)st_is->back().cv) == false)
            {
                return false;
            }
        }
        else
        {
            HP::Gen(HP::d, (char *)temp_cm, (char *)(*st_is)[st_is->size() - 2].cv);
            if (HP::Verify(HP::p, p->cnt, (char *)(*st_is)[st_is->size() - 2].cv) == false)
            {
                return false;
            }
        }
    }

    // VR2
    else if (y == L1 && p->root != nullptr && p->salt != -1)
    {

        unsigned char compare_SKE_hex[2 * n], compare_SKE_byte[n], temp_hashinput[128 / 8 + 2 * n];
        for (int a = 0; a < 2; a++)
            Parameter::longlong2byte(Parameter::P[a], temp_hashinput + a * 8);
        Parameter::hex2byte((char *)p->Credential, temp_hashinput + 128 / 8, 2 * n);
        Parameter::hex2byte((char *)p->SKE, temp_hashinput + 128 / 8 + n, 2 * n);
        Parameter::seletedHashFunction((char *)temp_hashinput, (char *)compare_SKE_byte, 128 / 8 + 2 * n);
        Parameter::byte2hex(compare_SKE_byte, (char *)compare_SKE_hex, n);
        if (memcmp(compare_SKE_hex, st_is->back().p->SKE, 2 * n) != 0)
        {
            return false;
        }

        // examine solution
        unsigned char temp_cm[2 * n];
        memcpy(temp_cm, p->Credential, 2 * n);
        if (!is_audit)
        {
            HP::Gen(HP::d, (char *)temp_cm, (char *)st_is->back().cv);
            if (HP::Verify(HP::p, p->cnt, (char *)st_is->back().cv) == false)
            {
                return false;
            }
        }
        else
        {
            HP::Gen(HP::d, (char *)temp_cm, (char *)(*st_is)[st_is->size() - 2].cv);
            if (HP::Verify(HP::p, p->cnt, (char *)(*st_is)[st_is->size() - 2].cv) == false)
            {
                return false;
            }
        }

        // set x=x^, y=L1, z=z^[y^-1]+1
        temp_x = x;
        temp_y = L1;
        temp_z = (*st_is)[0].z[y - 1] + 1;

        (*st_is)[0].z[y - 1] += 1;

        unsigned short temp_m[L1];
        unsigned char temp_in[n + 64 / 8], temp_out[n];
        memcpy(temp_in, p->root, n);
        Parameter::longlong2byte(p->salt, temp_in + n);
        Parameter::seletedHashFunction((char *)temp_in, (char *)temp_out, n + sizeof(long long));

        // represent as l1 base_w value
        for (int i = 0; i < n; i++)
        {
            temp_m[2 * i] = temp_out[i] >> 4;
            temp_m[2 * i + 1] = temp_out[i] & 0x0F;
        }

        // count number of calls to TH
        for (int j = 1; j <= L1; j++)
        {
            if ((*st_is)[0].z[j - 1] - 1 != w - 1 - temp_m[j - 1])
            {

                return false;
            }
        }
    }

    // pi passes the above verification
    if (is_append)
    {
        (*st_is)[0].index += 1;
        (*st_is)[0].x[0] = temp_x;
        (*st_is)[0].y[0] = temp_y;
        (*st_is)[0].z[(*st_is)[0].y[0] - 1] = temp_z;

        // append (pi, cvi, Tack)
        state temp_state;
        temp_state.cv = new unsigned char[n];
        temp_state.p = new alive_prf;
        temp_state.p->Credential = new unsigned char[2 * n];
        temp_state.p->proof = new unsigned char[MT::params.tree_height * MT::params.n + 4];
        temp_state.p->root = new unsigned char[n];
        temp_state.p->SKE = new unsigned char[2 * n];

        temp_state.T_ack = T_r;
        memcpy(temp_state.cv, Client::st.cv, Parameter::n);
        temp_state.p->cnt = p->cnt;
        memcpy(temp_state.p->Credential, p->Credential, 2 * n);

        // proof
        if (p->proof != nullptr)
            memcpy(temp_state.p->proof, p->proof, MT::params.tree_height * MT::params.n + 4);
        else
            temp_state.p->proof = nullptr;

        // root
        if (p->root != nullptr)
            memcpy(temp_state.p->root, p->root, n);
        else
            temp_state.p->root = nullptr;

        temp_state.p->salt = p->salt;
        memcpy(temp_state.p->SKE, p->SKE, 2 * n);

        st_is->push_back(temp_state);
    }
    return true;
}
