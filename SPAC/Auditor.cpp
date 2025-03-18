#include "Auditor.h"
#include "Parameter.h"
#include "MerkleTree.h"
#include "Verifier.h"
#include "HPoW.h"
vector<state> Auditor::st;

void Auditor::Setup()
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

void StateTrunc(vector<state> *stin, int j, vector<state> *stout)
{
    int size = stout->size();
    stout->resize(j + 1);
    if ((*stout)[0].index == nullptr)
        (*stout)[0].index = new unsigned int[1];
    if ((*stout)[0].x == nullptr)
        (*stout)[0].x = new unsigned int[1];
    if ((*stout)[0].y == nullptr)
        (*stout)[0].y = new unsigned int[1];
    if ((*stout)[0].z == nullptr)
        (*stout)[0].z = new unsigned short[Parameter::l1];

    (*stout)[0].index[0] = j;
    (*stout)[0].x[0] = (*stin)[0].x[0];
    (*stout)[0].y[0] = j;
    memcpy((*stout)[0].z, (*stin)[0].z, Parameter::l1);

    for (int i = size; i < j + 1; i++)
    {
        (*stout)[i].cv = new unsigned char[Parameter::n];

        if ((*stin)[i].p != nullptr)
        {
            (*stout)[i].p = new alive_prf;
            (*stout)[i].p->Credential = new unsigned char[2 * Parameter::n];
            (*stout)[i].p->SKE = new unsigned char[2 * Parameter::n];

            if ((*stin)[i].p->proof != nullptr)
                (*stout)[i].p->proof = new unsigned char[MT::params.tree_height * MT::params.n];

            if ((*stin)[i].p->root != nullptr)
                (*stout)[i].p->root = new unsigned char[MT::params.n];
        }
    }

    for (int i = 0; i < j + 1; i++)
    {
        (*stout)[i].T_ack = (*stin)[i].T_ack;
        memcpy((*stout)[i].cv, (*stin)[i].cv, Parameter::n);

        if ((*stin)[i].p != nullptr)
        {
            (*stout)[i].p->cnt = (*stin)[i].p->cnt;
            (*stout)[i].p->salt = (*stin)[i].p->salt;
            memcpy((*stout)[i].p->Credential, (*stin)[i].p->Credential, 2 * Parameter::n);
            memcpy((*stout)[i].p->SKE, (*stin)[i].p->SKE, 2 * Parameter::n);

            if ((*stin)[i].p->proof != nullptr)
                memcpy((*stout)[i].p->proof, (*stin)[i].p->proof, MT::params.tree_height * MT::params.n);
            else
                (*stout)[i].p->proof = nullptr;

            if ((*stin)[i].p->root != nullptr)
                memcpy((*stout)[i].p->root, (*stin)[i].p->root, MT::params.n);
            else
                (*stout)[i].p->root = nullptr;
        }
        else
            (*stout)[i].p = nullptr;
    }
}

bool Auditor::Audit(vector<state> *st_is, vector<state> *st_ia, int T)
{
    int i = (*st_ia)[0].index[0], j = 0;

    // i
    if (0 && T <= (*st_is)[j].T_ack)
    {
        return false;
    }

    // ii
    if (i > j)
    {
        return false;
    }

    // iii
    vector<state> tempst;
    StateTrunc(st_is, i, &tempst);
    if ((*st_ia)[0].index[0] != tempst[0].index[0])
    {
        return false;
    }
    if ((*st_ia)[0].x[0] != tempst[0].x[0])
    {
        return false;
    }
    if ((*st_ia)[0].y[0] != tempst[0].y[0])
    {
        return false;
    }
    if (i > 1)
        if (memcmp((*st_ia)[0].z, tempst[0].z, Parameter::l1) != 0)
        {
            return false;
        }

    for (int k = 0; k <= i; k++)
    {

        if (memcmp((*st_ia)[k].cv, tempst[k].cv, Parameter::n) != 0)
        {
            return false;
        }
        if (tempst[k].p != nullptr)
        {
            if ((*st_ia)[k].p->cnt != tempst[k].p->cnt)
            {
                return false;
            }
            if ((*st_ia)[k].p->salt != tempst[k].p->salt)
            {
                return false;
            }
            if (memcmp((*st_ia)[k].p->Credential, tempst[k].p->Credential, 2 * Parameter::n) != 0)
            {
                return false;
            }
            if (memcmp((*st_ia)[k].p->SKE, tempst[k].p->SKE, 2 * Parameter::n) != 0)
            {
                return false;
            }

            if (tempst[k].p->proof != nullptr)
                if (memcmp((*st_ia)[k].p->proof, tempst[k].p->proof, MT::params.tree_height * MT::params.n) != 0)
                {
                    return false;
                }

            if (tempst[k].p->root != nullptr)
                if (memcmp((*st_ia)[k].p->root, tempst[k].p->root, MT::params.tree_height * MT::params.n) != 0)
                {
                    return false;
                }
        }
    }

    // iv
    for (int v = i + 1; v <= (*st_is)[0].z[0]; v++)
    {
        StateTrunc(st_is, v, &tempst);
        if (Verifer::Verify(&Parameter::pai, &tempst, tempst.back().p, tempst.back().T_ack, false, true) == 0)
        {
            return false;
        }
    }

    // free vector
    delete[] tempst[0].index;
    delete[] tempst[0].x;
    delete[] tempst[0].y;
    delete[] tempst[0].z;
    for (size_t i = 0; i < tempst.size(); ++i)
    {
        delete[] tempst[i].cv;

        if (tempst[i].p != nullptr)
        {
            delete[] tempst[i].p->Credential;
            delete[] tempst[i].p->SKE;
            if (tempst[i].p->proof != nullptr)
                delete[] tempst[i].p->proof;
            if (tempst[i].p->root != nullptr)
                delete[] tempst[i].p->root;
            delete tempst[i].x;
        }
    }
    tempst.clear();

    // set st_ia=st_is
    int size = st_ia->size();
    st_ia->resize(j + 1);

    (*st_ia)[0].index[0] = (*st_is)[0].index[0];
    (*st_ia)[0].x[0] = (*st_is)[0].x[0];
    (*st_ia)[0].y[0] = (*st_is)[0].y[0];
    memcpy((*st_ia)[0].z, (*st_is)[0].z, Parameter::l1 * sizeof(unsigned short));

    for (int i = size; i < j + 1; i++)
    {
        (*st_ia)[i].cv = new unsigned char[Parameter::n];

        if ((*st_is)[i].p != nullptr)
        {
            (*st_ia)[i].p = new alive_prf;
            (*st_ia)[i].p->Credential = new unsigned char[2 * Parameter::n];
            (*st_ia)[i].p->SKE = new unsigned char[2 * Parameter::n];

            if ((*st_is)[i].p->proof != nullptr)
                (*st_ia)[i].p->proof = new unsigned char[MT::params.tree_height * MT::params.n];

            if ((*st_is)[i].p->root != nullptr)
                (*st_ia)[i].p->root = new unsigned char[MT::params.n];
        }
    }

    for (int i = size; i < j + 1; i++)
    {
        (*st_ia)[i].T_ack = (*st_is)[i].T_ack;
        memcpy((*st_ia)[i].cv, (*st_is)[i].cv, Parameter::n);

        if ((*st_is)[i].p != nullptr)
        {
            (*st_ia)[i].p->cnt = (*st_is)[i].p->cnt;
            (*st_ia)[i].p->salt = (*st_is)[i].p->salt;
            memcpy((*st_ia)[i].p->Credential, (*st_is)[i].p->Credential, 2 * Parameter::n);
            memcpy((*st_ia)[i].p->SKE, (*st_is)[i].p->SKE, 2 * Parameter::n);

            if ((*st_is)[i].p->proof != nullptr)
                memcpy((*st_ia)[i].p->proof, (*st_is)[i].p->proof, MT::params.tree_height * MT::params.n);
            else
                (*st_ia)[i].p->proof = nullptr;

            if ((*st_is)[i].p->root != nullptr)
                memcpy((*st_ia)[i].p->root, (*st_is)[i].p->root, MT::params.n);
            else
                (*st_ia)[i].p->root = nullptr;
        }
        else
            (*st_ia)[i].p = nullptr;
    }
    return true;
}
