#include "MerkleTree.h"
#include "Parameter.h"
#include "PRG.h"
#include "HPoW.h"

unsigned char *MT::root[2];
xmss_params MT::params;
bds_state *MT::state[2];
unsigned int *MT::laddr;

void MT::Prepare4Build()
{
    int E = Parameter::E;
    int L1 = Parameter::l1;
    int w = Parameter::SetPms.aux.w;
    int x = laddr[2]; // epoch
    for (; x <= 2; x++)
    {

        unsigned char temp[4 * params.n + 1];
        // (ESx, IESx) := G.Gen(ESx,1)
        PRG::Gen((char *)Parameter::ES[x - 1], (char *)temp);
        memcpy(Parameter::ES[x], temp, 2 * params.n);
        memcpy(Parameter::IES[x], temp + 2 * params.n, 2 * params.n);

        // (CCSx,0, SKSx,0) : = G.Gen(IESx)
        PRG::Gen((char *)Parameter::IES[x], (char *)temp);
        memcpy(Parameter::CCS[x * L1 + 0], temp, 2 * params.n);
        memcpy(Parameter::SKS[x * L1 + 0], temp + 2 * params.n, 2 * params.n);

        //{(CCSx,y, CS0x, y) : = G.Gen(CCSx, y,1)}y from [L1]
        for (int j = 1; j <= L1; j++)
        {
            PRG::Gen((char *)Parameter::CCS[x * L1 + j - 1], (char *)temp);
            memcpy(Parameter::CCS[x * L1 + j], temp, 2 * params.n);
            memcpy(Parameter::CS[x * L1 * w + j * w + 0], temp + 2 * params.n, 2 * params.n);
        }

        // {(CSz x,y, Cz x,y) := G.Gen(CSz-1 x,y )}y from [L1],z from [w]
        for (int j = 1; j <= L1; j++)
            for (int k = 1; k <= w; k++)
            {
                PRG::Gen((char *)Parameter::CS[x * L1 * w + j * w + k - 1], (char *)temp);
                memcpy(Parameter::CS[x * L1 * w + j * w + k], temp, 2 * params.n);
                memcpy(Parameter::C[x * L1 * w + j * w + k], temp + 2 * params.n, 2 * params.n);
            }

        // {(SKSx,y, SKE0 x,y) : = G.Gen(SKSx,y-1)}
        for (int j = 1; j <= L1; j++)
        {
            PRG::Gen((char *)Parameter::SKS[x * L1 + j - 1], (char *)temp);
            memcpy(Parameter::SKS[x * L1 + j], temp, 2 * params.n);
            memcpy(Parameter::SKE[x * L1 * w + j * w + 0], temp + 2 * params.n, 2 * params.n);
        }

        // SKEz x,y : =TH(P, Cw-z+1 x,y, SKEz-1 x,y);
        unsigned char temp_in[2 * 2 * params.n], in[128 / 8 + 2 * params.n], out[params.n];
        for (int a = 0; a < 4; a++)
            Parameter::longlong2byte(Parameter::P[a], in + a * 8);
        for (int j = 1; j <= L1; j++)
            for (int k = 1; k <= w - 1; k++)
            {
                memcpy(temp_in, Parameter::C[x * L1 * w + j * w + (w - k + 1)], 2 * params.n);
                memcpy(temp_in + 2 * params.n, Parameter::SKE[x * L1 * w + j * w + (k - 1)], 2 * params.n);
                Parameter::hex2byte((char *)temp_in, in + 128 / 8, 2 * 2 * params.n);

                Parameter::seletedHashFunction((char *)in, (char *)out, 128 / 8 + 2 * params.n);
                Parameter::byte2hex(out, (char *)Parameter::SKE[x * L1 * w + j * w + k], params.n);
            }
    }
}

void gen_leaf_wots(const xmss_params *params, unsigned char *leaf,
                   const unsigned char *sk_seed, const unsigned char *pub_seed,
                   uint32_t ltree_addr[8], uint32_t *addr)
{
    int x = addr[2], y = addr[0];
    int L1 = Parameter::l1;
    int w = Parameter::SetPms.aux.w;
    int i = addr[0];
    // lfx,y := TH(P, C1 x,y, SKEw-1 x,y)
    unsigned char temp_in[2 * 2 * params->n], in[128 / 8 + 2 * params->n], out[params->n];
    for (int a = 0; a < 2; a++)
        Parameter::longlong2byte(Parameter::P[a], in + a * 8);
    memcpy(temp_in, Parameter::C[x * L1 * w + y * w + 1], 2 * params->n);
    memcpy(temp_in + 2 * params->n, Parameter::SKE[x * L1 * w + y * w + (w - 1)], 2 * params->n);
    Parameter::hex2byte((char *)temp_in, in + 128 / 8, 2 * 2 * params->n);
    Parameter::seletedHashFunction((char *)in, (char *)leaf, 128 / 8 + 2 * params->n);
}

int thash_h(const xmss_params *params,
            unsigned char *out, const unsigned char *in,
            const unsigned char *pub_seed, uint32_t *addr)
{

    unsigned char data[128 / 8 + 2 * params->n + 3 * 4]; // P(16B)+epoch(4B)+height(4B)+i(4B)+in(64B)
    for (int j = 0; j < 2; j++)
        Parameter::longlong2byte(Parameter::P[j], data + j * 8);             // P
    Parameter::int2byte(addr[2], data + 128 / 8);                            // epoch
    Parameter::int2byte((addr[0] - 1) >> (addr[1] + 1), data + 128 / 8 + 4); // index(start from 0)
    Parameter::int2byte(addr[1] + 1, data + 128 / 8 + 2 * 4);                // height(start from 0)
    memcpy(data + 128 / 8 + 3 * 4, in, 2 * params->n);                       // two child node
    Parameter::SHA256((char *)data, (char *)out, 128 / 8 + 2 * params->n + 3 * 4);

    return 0;
}

static int treehash_minheight_on_stack(const xmss_params *params,
                                       bds_state *state,
                                       const treehash_inst *treehash)
{
    unsigned int r = params->tree_height, i;

    for (i = 0; i < treehash->stackusage; i++)
    {
        if (state->stacklevels[state->stackoffset - i - 1] < r)
        {
            r = state->stacklevels[state->stackoffset - i - 1];
        }
    }
    return r;
}

static void treehash_init(const xmss_params *params,
                          unsigned char *node, int height, int index,
                          bds_state *state, unsigned char *sk_seed,
                          const unsigned char *pub_seed, uint32_t *addr)
{
    unsigned int idx = index;
    // use three different addresses because at this point we use all three formats in parallel
    uint32_t ots_addr[8] = {0};
    uint32_t ltree_addr[8] = {0};
    uint32_t node_addr[8] = {0};

    uint32_t lastnode, i;
    unsigned char stack[(height + 1) * params->n];
    unsigned int stacklevels[height + 1];
    unsigned int stackoffset = 0;
    unsigned int nodeh;

#ifdef FORWARD_SECURE
    unsigned char ots_seed[params->n];
#endif

    lastnode = idx + (1 << height);

    for (i = 0; i < params->tree_height - params->bds_k; i++)
    {
        state->treehash[i].h = i;
        state->treehash[i].completed = 1;
        state->treehash[i].stackusage = 0;
    }

    i = 0;
    for (; idx < lastnode; idx++)
    {

#ifdef FORWARD_SECURE
        hash_prg(params, ots_seed, sk_seed, sk_seed, pub_seed, ots_addr);
        gen_leaf_wots(params, stack + stackoffset * params->n, ots_seed, pub_seed, ltree_addr, ots_addr);
#else
        addr[0] = idx + 1;
        gen_leaf_wots(params, stack + stackoffset * params->n, sk_seed, pub_seed, ltree_addr, addr);
#endif
        stacklevels[stackoffset] = 0;
        stackoffset++;
        if (params->tree_height - params->bds_k > 0 && i == 3)
        {
            memcpy(state->treehash[0].node, stack + (stackoffset - 1) * params->n, params->n); // ÐÞ¸ÄÎª-1
        }
#ifdef FORWARD_SECURE
        unsigned int j;
        for (j = 0; j < params->tree_height - params->bds_k - 1; j++)
        {
            if (idx >> j == 3 && (idx & ((1 << j) - 1)) == 0)
            {
                memcpy(state->treehash[j].seed_next, sk_seed, params->n);
            }
        }
#endif

        while (stackoffset > 1 && stacklevels[stackoffset - 1] == stacklevels[stackoffset - 2])
        {
            nodeh = stacklevels[stackoffset - 1];
            if (i >> nodeh == 1)
            {
                memcpy(state->auth + nodeh * params->n, stack + (stackoffset - 1) * params->n, params->n);
            }
            else
            {
                if (nodeh < params->tree_height - params->bds_k && i >> nodeh == 3)
                {
                    memcpy(state->treehash[nodeh].node, stack + (stackoffset - 1) * params->n, params->n);
                }
                else if (nodeh >= params->tree_height - params->bds_k)
                {
                    memcpy(state->retain + ((1 << (params->tree_height - 1 - nodeh)) + nodeh - params->tree_height + (((i >> nodeh) - 3) >> 1)) * params->n, stack + (stackoffset - 1) * params->n, params->n);
                }
            }
            addr[1] = stacklevels[stackoffset - 2];
            thash_h(params, stack + (stackoffset - 2) * params->n, stack + (stackoffset - 2) * params->n, pub_seed, addr);
            stacklevels[stackoffset - 2]++;
            stackoffset--;
        }
        i++;
    }

    for (i = 0; i < params->n; i++)
    {
        node[i] = stack[i];
    }
}

static void treehash_update(const xmss_params *params,
                            treehash_inst *treehash, bds_state *state,
                            const unsigned char *sk_seed,
                            const unsigned char *pub_seed,
                            uint32_t *addr)
{
    uint32_t ots_addr[8] = {0};
    uint32_t ltree_addr[8] = {0};
    uint32_t node_addr[8] = {0};

    unsigned char nodebuffer[2 * params->n];
    unsigned int nodeheight = 0;
#ifdef FORWARD_SECURE
    unsigned char ots_seed[params->n];

    // sk_seed is not needed here suppress warning
    (void)sk_seed;

    hash_prg(params, ots_seed, treehash->seed_active, treehash->seed_active, pub_seed, ots_addr);
    gen_leaf_wots(params, nodebuffer, ots_seed, pub_seed, ltree_addr, ots_addr);
#else
    gen_leaf_wots(params, nodebuffer, sk_seed, pub_seed, ltree_addr, addr);
#endif
    while (treehash->stackusage > 0 && state->stacklevels[state->stackoffset - 1] == nodeheight)
    {
        memcpy(nodebuffer + params->n, nodebuffer, params->n);
        memcpy(nodebuffer, state->stack + (state->stackoffset - 1) * params->n, params->n);

        addr[1] = nodeheight;
        thash_h(params, nodebuffer, nodebuffer, pub_seed, addr);
        nodeheight++;
        treehash->stackusage--;
        state->stackoffset--;
    }
    if (nodeheight == treehash->h)
    { // this also implies stackusage == 0
        memcpy(treehash->node, nodebuffer, params->n);
        treehash->completed = 1;
    }
    else
    {
        memcpy(state->stack + state->stackoffset * params->n, nodebuffer, params->n);
        treehash->stackusage++;
        state->stacklevels[state->stackoffset] = nodeheight;
        state->stackoffset++;
        treehash->next_idx++;
    }
}

/**
 * Returns the auth path for node leaf_idx and computes the auth path for the
 * next leaf node, using the algorithm described by Buchmann, Dahmen and Szydlo
 * in "Post Quantum Cryptography", Springer 2009.
 */
static void bds_round(const xmss_params *params,
                      bds_state *state, const unsigned long leaf_idx,
                      const unsigned char *sk_seed,
                      const unsigned char *pub_seed, uint32_t *addr)
{
    unsigned int i;
    unsigned int tau = params->tree_height;
    unsigned int startidx;
    unsigned int offset, rowidx;
    unsigned char buf[2 * params->n];

    uint32_t ots_addr[8] = {0};
    uint32_t ltree_addr[8] = {0};
    uint32_t node_addr[8] = {0};

#ifdef FORWARD_SECURE
    unsigned char ots_seed[params->n];
#endif

    for (i = 0; i < params->tree_height; i++)
    {
        if (!((leaf_idx >> i) & 1))
        {
            tau = i;
            break;
        }
    }

    if (tau > 0)
    {
        memcpy(buf, state->auth + (tau - 1) * params->n, params->n);
        // we need to do this before refreshing state->keep to prevent overwriting
        memcpy(buf + params->n, state->keep + ((tau - 1) >> 1) * params->n, params->n);
    }
    if (!((leaf_idx >> (tau + 1)) & 1) && (tau < params->tree_height - 1))
    {
        memcpy(state->keep + (tau >> 1) * params->n, state->auth + tau * params->n, params->n);
    }
    if (tau == 0)
    {

#ifdef FORWARD_SECURE
        // if lowest layer, generate a new leaf
        if (addr[0] == 0)
        {
            hash_prg(params, ots_seed, NULL, sk_seed, pub_seed, ots_addr);
            gen_leaf_wots(params, state->auth, ots_seed, pub_seed, ltree_addr, ots_addr);
        }
        else
        {
            // otherwise use the cached left leaf (as seed was already deleted)
            memcpy(state->auth, state->left_leaf, params->n);
        }
#else
        addr[0] = leaf_idx + 1;
        gen_leaf_wots(params, state->auth, sk_seed, pub_seed, ltree_addr, addr);
#endif
    }
    else
    {
        addr[0] = leaf_idx + 1;
        addr[1] = tau - 1;
        thash_h(params, state->auth + tau * params->n, buf, pub_seed, addr);
        for (i = 0; i < tau; i++)
        {
            if (i < params->tree_height - params->bds_k)
            {
                memcpy(state->auth + i * params->n, state->treehash[i].node, params->n);
            }
            else
            {
                offset = (1 << (params->tree_height - 1 - i)) + i - params->tree_height;
                rowidx = ((leaf_idx >> i) - 1) >> 1;
                memcpy(state->auth + i * params->n, state->retain + (offset + rowidx) * params->n, params->n);
            }
        }

        for (i = 0; i < ((tau < params->tree_height - params->bds_k) ? tau : (params->tree_height - params->bds_k)); i++)
        {
            startidx = leaf_idx + 1 + 3 * (1 << i);
            if (startidx < 1U << params->tree_height)
            {
                state->treehash[i].h = i;
                state->treehash[i].next_idx = startidx;
                state->treehash[i].completed = 0;
                state->treehash[i].stackusage = 0;

#ifdef FORWARD_SECURE
                memcpy(state->treehash[i].seed_active, state->treehash[i].seed_next, params->n);
#endif
            }
        }
    }
}

/**
 * Performs treehash updates on the instance that needs it the most.
 * Returns the updated number of available updates.
 **/
static char bds_treehash_update(const xmss_params *params,
                                bds_state *state, unsigned int updates,
                                const unsigned char *sk_seed,
                                unsigned char *pub_seed,
                                uint32_t *addr)
{
    uint32_t i, j;
    unsigned int level, l_min, low;
    unsigned int used = 0;

    for (j = 0; j < updates; j++)
    {
        l_min = params->tree_height;
        level = params->tree_height - params->bds_k;
        for (i = 0; i < params->tree_height - params->bds_k; i++)
        {
            if (state->treehash[i].completed)
            {
                low = params->tree_height;
            }
            else if (state->treehash[i].stackusage == 0)
            {
                low = i;
            }
            else
            {
                low = treehash_minheight_on_stack(params, state, &(state->treehash[i]));
            }
            if (low < l_min)
            {
                level = i;
                l_min = low;
            }
        }
        if (level == params->tree_height - params->bds_k)
        {
            break;
        }
        addr[0] = state->treehash[level].next_idx + 1;
        treehash_update(params, &(state->treehash[level]), state, sk_seed, pub_seed, addr);
        used++;
    }
    return updates - used;
}

void MT::Setup(int k)
{
    params.n = Parameter::n;
    params.bds_k = 0;
    params.tree_height = 0;
    while (Parameter::u > 1)
    {
        Parameter::u /= 2;
        params.tree_height++;
    }

    for (int tempi = 0; tempi < 2; tempi++)
    {
        state[tempi] = new bds_state;
        state[tempi]->treehash = new treehash_inst[params.tree_height];
        root[tempi] = new unsigned char[params.n];

        // init state
        state[tempi]->stackoffset = 0;
        state[tempi]->next_leaf = 0;
        state[tempi]->stack = new unsigned char[(params.tree_height - 1) * params.n];
        state[tempi]->stacklevels = new unsigned char[3];
        state[tempi]->keep = new unsigned char[params.tree_height * params.n];
        state[tempi]->retain = new unsigned char[params.n];
        state[tempi]->auth = new unsigned char[params.tree_height * params.n];
        // init state->treehash
        for (unsigned int j = 0; j < params.tree_height - params.bds_k; j++)
        {
            state[tempi]->treehash[j].h = j;
            state[tempi]->treehash[j].next_idx = 0;
            state[tempi]->treehash[j].stackusage = 0;
            state[tempi]->treehash[j].completed = 1;
            state[tempi]->treehash[j].node = new unsigned char[3 * params.n];
        }
    }
    // init laddr
    laddr = new unsigned int[3];
    laddr[0] = 0; // leaf_index+1 or leaf_idx+1 of right child of inner node waiting for compute
    laddr[1] = 0; // height-1 of inner node waiting for compute
    laddr[2] = 1; // epoch
}

void MT::Build()
{
    unsigned char ots_seed[params.n] = {0}, sk[params.n] = {0};

    // root/auth/treehash.node/retain
    // initialize two trees of two epochs
    laddr[2] = 1;
    treehash_init(&params, root[0], params.tree_height, 0, state[0], ots_seed, sk, laddr);
    memcpy(Parameter::pai.root, root[0], Parameter::n);

    laddr[0] = 0;
    laddr[1] = 0;
    laddr[2] = 2;
    treehash_init(&params, root[1], params.tree_height, 0, state[1], ots_seed, sk, laddr);
    memcpy(Parameter::pai.root + Parameter::n, root[1], Parameter::n);
    laddr[2] = 1;
}

void MT::GetPrf(const unsigned long leaf_idx, unsigned char *out, int epoch)
{

    uint32_t ots_addr[8] = {0};
    unsigned char sk_seed[1];
    unsigned char pub_seed[1];

    // the auth path was already computed during the previous round
    memcpy(out, state[epoch - 1]->auth, params.tree_height * params.n);
    if (leaf_idx < (1 << params.tree_height) - 1)
    {
        bds_round(&params, state[epoch - 1], leaf_idx, sk_seed, pub_seed, laddr);
        bds_treehash_update(&params, state[epoch - 1], (params.tree_height - params.bds_k) >> 1, sk_seed, pub_seed, laddr);
    }
}

bool MT::Verify(const unsigned char *root, const char *leaf_value, const int leaf_idx, const char *proof)
{
    char temp_hash[params.n];
    char jointm[2 * params.n];
    unsigned int addr[3];
    memcpy(temp_hash, leaf_value, params.n);
    for (int i = 0; i < params.tree_height; i++)
    {
        unsigned int mask;
        if ((leaf_idx >> i) & 1)
        {
            // =hash(proof[i]||temp_hash)
            memcpy(jointm, proof + i * params.n, params.n);
            memcpy(jointm + params.n, temp_hash, params.n);
        }
        else
        {
            // =hash(temp_hash||proof[i])
            memcpy(jointm, temp_hash, params.n);
            memcpy(jointm + params.n, proof + i * params.n, params.n);
        }
        unsigned char pub_seed[32];
        addr[0] = (((leaf_idx >> i) ^ 1) << i) + Parameter::pow(2, i);
        addr[1] = i;
        addr[2] = laddr[2];
        thash_h(&MT::params, (unsigned char *)temp_hash, (unsigned char *)jointm, pub_seed, addr);
    }
    bool result = false;
    if (memcmp(temp_hash, root, params.n) == 0)
    {
        result = true;
    }

    return result;
}

void MT::testleftProofGen()
{
    /***cache C/SKE of second tree***/
    MT::laddr[2] = 2;
    MT::Prepare4Build();

    /***cache third tree***/
    MT::laddr[2] = 2;
    MT::Prepare4Build();
    treehash_init(&MT::params, MT::root[1], MT::params.tree_height, 0, MT::state[1], NULL, NULL, MT::laddr);

    unsigned short m[256 / 4];
    long long cnt = HP::FindSalt(MT::root[1], m);
}