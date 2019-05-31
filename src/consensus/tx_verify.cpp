// Copyright (c) 2017-2018 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <consensus/tx_verify.h>

#include <consensus/consensus.h>
#include <primitives/transaction.h>
#include <script/interpreter.h>
#include <consensus/validation.h>

// TODO remove the following dependencies
#include <chain.h>
#include <coins.h>
#include <util/moneystr.h>
//关于私钥、公钥、地址。
//太基础了，具体地表示图放在印象笔记里了。

//关于锁定：
//交易中，发送方会将自己的UTXO使用锁定脚本锁定在接收方的地址上，
//接收方需要证明自己的身份，证明自己的身份通过使用解锁脚本解锁完成，解锁之后就可以使用了~

//比特币的脚本语言：
//虽然不是完备的，比特币也是可以写脚本的喔~比特币的脚本是基于逆波兰表示法的基于栈的执行语言。
//目前使用的交易形式一般是P2PKH（Pay-to-Public-Key-Hash），关于P2PKH的介绍写在印象笔记里乐~

//NOTE：Check if transaction is final and can be included in a block with the
 //specified height and time. Consensus critical.
bool IsFinalTx(const CTransaction &tx, int nBlockHeight, int64_t nBlockTime)
{
    if (tx.nLockTime == 0)//NOTE：没有被锁定，可以直接写入
        return true;
    if ((int64_t)tx.nLockTime < ((int64_t)tx.nLockTime < LOCKTIME_THRESHOLD ? (int64_t)nBlockHeight : nBlockTime))//NOTE：锁定时间结束。可以写入
        return true;
    //NOTE：关于时间锁nLockTime
    //nLockTime==0：代表该交易没有被锁定，可以直接加入账本
    //nLockTime<500000000的时候，nLockTime指示的是块的高度，在块高度达到这个值的时候就可以被写入了
    //nLockTime>500000000也就是（LOCKTIME_THRESHOLD），nLockTime指示的是Unix时间戳，或者说是BlockTime，在时间达到具体的时间之后可以被写入
    //那么，为什么想要实现时间锁机制呢？或者说时间锁机制有什么用呢？
    //假设场景：A说，孩子，等我80岁后，你就可以拿到这笔钱了。你看，我算了下，我80岁的时候大概Unix时间是这个
    //B说，好的爷爷。（(●'◡'●)
    //需要注意的是，即使这个交易已经被打上时间锁，也允许它在另一个交易中被消费。如果它被消费了，之前的所有交易签名都无效了
    //因为交易检查：UtXO被花了吗？是的已经被花费了。
    //时间锁唯一能够保证的只有：在规定的时间之前，这笔交易不可能被写入账本而生效
    for (const auto& txin : tx.vin) {
         /* Setting nSequence to this value for every input in a transaction
     * disables nLockTime. */
//到这里说明nLockTime不满足条件
//想要是Final还可能有一种情况，那就是设置nSequence为SEQUENCE_FINAL，于是nLockTime被禁用了，他怎么样都不管了。
        if (!(txin.nSequence == CTxIn::SEQUENCE_FINAL))//你nLockTime也不满足条件、nSequence设置也没说要禁用nLockTime，还想过？
            return false;
    }
    return true;
}


//除了上述简单地nLockTime，还有一些其他的时间锁实现，太长了。原文章在印象笔记里。
//以及：区分”时间锁“和”锁定脚本“喔~这两个是不一样的东西。

std::pair<int, int64_t> CalculateSequenceLocks(const CTransaction &tx, int flags, std::vector<int>* prevHeights, const CBlockIndex& block)
{
    assert(prevHeights->size() == tx.vin.size());//NOTE：啥是prevHeights？

    // Will be set to the equivalent height- and time-based nLockTime
    // values that would be necessary to satisfy all relative lock-
    // time constraints given our view of block chain history.
    // The semantics of nLockTime are the last invalid height/time, so
    // use -1 to have the effect of any height or time being valid.
    //该函数返回给定tx最早的有效时间。这个有效时间可能是由块高度表示，也可能是由unix时间表示，因此该函数返回这个数值对。
    //如果该交易没有设置nSequence相对有效时间，那么返回值就是-1，也就是任何时候都有效。
    //只有该交易中所有vin都解除了锁定，该交易才会被认为是有效的。
    //因此你会看到，下面的for循环遍历了该交易中所有的vin。
    int nMinHeight = -1;
    int64_t nMinTime = -1;

    // tx.nVersion is signed integer so requires cast to unsigned otherwise
    // we would be doing a signed comparison and half the range of nVersion
    // wouldn't support BIP 68.
    bool fEnforceBIP68 = static_cast<uint32_t>(tx.nVersion) >= 2
                      && flags & LOCKTIME_VERIFY_SEQUENCE;

    // Do not enforce sequence numbers as a relative lock time
    // unless we have been instructed to
    //
    if (!fEnforceBIP68) {
        return std::make_pair(nMinHeight, nMinTime);
    }

    for (size_t txinIndex = 0; txinIndex < tx.vin.size(); txinIndex++) {
        const CTxIn& txin = tx.vin[txinIndex];

        // Sequence numbers with the most significant bit set are not
        // treated as relative lock-times, nor are they given any
        // consensus-enforced meaning at this point.
        
        if (txin.nSequence & CTxIn::SEQUENCE_LOCKTIME_DISABLE_FLAG) {
            // The height of this input is not relevant for sequence locks
            (*prevHeights)[txinIndex] = 0;
            continue;//NOTE：我不确定：没锁，你肯定有效了，直接下一个。
        }

        int nCoinHeight = (*prevHeights)[txinIndex];

//对SEQUENCE_LOCKTIME_TYPE_FLAG：
/* If CTxIn::nSequence encodes a relative lock-time and this flag
     * is set, the relative lock-time has units of 512 seconds,
     * otherwise it specifies blocks with a granularity of 1. */
        if (txin.nSequence & CTxIn::SEQUENCE_LOCKTIME_TYPE_FLAG) {
            int64_t nCoinTime = block.GetAncestor(std::max(nCoinHeight-1, 0))->GetMedianTimePast();
            // NOTE: Subtract 1 to maintain nLockTime semantics//subtract：减去扣掉
            // BIP 68 relative lock times have the semantics of calculating
            // the first block or time at which the transaction would be
            // valid. When calculating the effective block time or height
            // for the entire transaction, we switch to using the
            // semantics of nLockTime which is the last invalid block
            // time or height.  Thus we subtract 1 from the calculated
            // time or height.

            // Time-based relative lock-times are measured from the
            // smallest allowed timestamp of the block containing the
            // txout being spent, which is the median time past of the
            // block prior.
            //
            nMinTime = std::max(nMinTime, nCoinTime + (int64_t)((txin.nSequence & CTxIn::SEQUENCE_LOCKTIME_MASK) << CTxIn::SEQUENCE_LOCKTIME_GRANULARITY) - 1);
        } else {
            nMinHeight = std::max(nMinHeight, nCoinHeight + (int)(txin.nSequence & CTxIn::SEQUENCE_LOCKTIME_MASK) - 1);
        }
    }
    return std::make_pair(nMinHeight, nMinTime);
}
//判断在给定块的时候这个指定交易（指定的解锁时间）能不能添加到帐本
bool EvaluateSequenceLocks(const CBlockIndex& block, std::pair<int, int64_t> lockPair)
{
    assert(block.pprev);//那你都没有父块怎么信你啊
    int64_t nBlockTime = block.pprev->GetMedianTimePast();
    //GetMedianTimePast，要是我没看错的话...求解的是从创世块或者是11个块之前（看谁更小）以来到这个块的父块的所有块时间的中位数
    //还没到解锁时间啊
    if (lockPair.first >= block.nHeight || lockPair.second >= nBlockTime)//NOTE：为什么使用的中位数时间？？？
        return false;

    return true;
}

//给定一个交易和一个块，看看这个交易能被包含到这个block里面吗
bool SequenceLocks(const CTransaction &tx, int flags, std::vector<int>* prevHeights, const CBlockIndex& block)
{
    return EvaluateSequenceLocks(block, CalculateSequenceLocks(tx, flags, prevHeights, block));
}

//legancy：遗产
//
unsigned int GetLegacySigOpCount(const CTransaction& tx)
{//那么，为什么这里没有判断是不是coinbase交易呢？
//为什么也没有判断coin是不是已经被花费了呢？？
    unsigned int nSigOps = 0;
    for (const auto& txin : tx.vin)
    {//scriptSig：解锁脚本
        nSigOps += txin.scriptSig.GetSigOpCount(false);//NOTE：为什么false啊
    }
    for (const auto& txout : tx.vout)
    {//scriptPuKey：锁定脚本
        nSigOps += txout.scriptPubKey.GetSigOpCount(false);
    }
    //NOTE：锁定脚本和解锁脚本没有区分的？？？
    return nSigOps;
}
//如果交易是基于P2SH协议，那么获取它锁定脚本的OP数目
unsigned int GetP2SHSigOpCount(const CTransaction& tx, const CCoinsViewCache& inputs)
{
    if (tx.IsCoinBase())
        return 0;

    unsigned int nSigOps = 0;
    for (unsigned int i = 0; i < tx.vin.size(); i++)
    {
        const Coin& coin = inputs.AccessCoin(tx.vin[i].prevout);//得到这个输入的指向的那个coin
        assert(!coin.IsSpent());//NOTE：为什么要在这里判断是不是已经被花费了啊？
        const CTxOut &prevout = coin.out;//应该还是那个vin[i].prevout
        if (prevout.scriptPubKey.IsPayToScriptHash())//如果是按照这个协议的交易才算数
            nSigOps += prevout.scriptPubKey.GetSigOpCount(tx.vin[i].scriptSig);
    }
    return nSigOps;
}


int64_t GetTransactionSigOpCost(const CTransaction& tx, const CCoinsViewCache& inputs, int flags)
{
    int64_t nSigOps = GetLegacySigOpCount(tx) * WITNESS_SCALE_FACTOR;//NOTE：啊！完全不懂！

    if (tx.IsCoinBase())
        return nSigOps;

    if (flags & SCRIPT_VERIFY_P2SH) {
        nSigOps += GetP2SHSigOpCount(tx, inputs) * WITNESS_SCALE_FACTOR;
    }


    for (unsigned int i = 0; i < tx.vin.size(); i++)
    {
        const Coin& coin = inputs.AccessCoin(tx.vin[i].prevout);//获取这个输入的coin
        assert(!coin.IsSpent());//没花费吧？
        const CTxOut &prevout = coin.out;
        nSigOps += CountWitnessSigOps(tx.vin[i].scriptSig, prevout.scriptPubKey, &tx.vin[i].scriptWitness, flags);//NOTE：总之获取！别问！
    }
    return nSigOps;
}

//
bool Consensus::CheckTxInputs(const CTransaction& tx, CValidationState& state, const CCoinsViewCache& inputs, int nSpendHeight, CAmount& txfee)
{
    // are the actual inputs available?
    //保证每个outpoint都真正的对应有币
    if (!inputs.HaveInputs(tx)) {
        return state.Invalid(ValidationInvalidReason::TX_MISSING_INPUTS, false, REJECT_INVALID, "bad-txns-inputs-missingorspent",
                         strprintf("%s: inputs missing/spent", __func__));
    }

    CAmount nValueIn = 0;
    for (unsigned int i = 0; i < tx.vin.size(); ++i) {
        const COutPoint &prevout = tx.vin[i].prevout;
        //确保每个对应的币都是尚未被花费的币
        const Coin& coin = inputs.AccessCoin(prevout);
        assert(!coin.IsSpent());

        // If prev is coinbase, check that it's matured
        //记住coinbase需要等COINBASE_MATURITY个块才能被花费
        if (coin.IsCoinBase() && nSpendHeight - coin.nHeight < COINBASE_MATURITY) {
            return state.Invalid(ValidationInvalidReason::TX_PREMATURE_SPEND, false, REJECT_INVALID, "bad-txns-premature-spend-of-coinbase",
                strprintf("tried to spend coinbase at depth %d", nSpendHeight - coin.nHeight));
        }

        // Check for negative or overflow input values
        //输入输出的数额是不是在规定的范围内？
        nValueIn += coin.out.nValue;
        if (!MoneyRange(coin.out.nValue) || !MoneyRange(nValueIn)) {
            return state.Invalid(ValidationInvalidReason::CONSENSUS, false, REJECT_INVALID, "bad-txns-inputvalues-outofrange");
        }
    }

    const CAmount value_out = tx.GetValueOut();//获取该交易总的输出数额
    if (nValueIn < value_out) {
        return state.Invalid(ValidationInvalidReason::CONSENSUS, false, REJECT_INVALID, "bad-txns-in-belowout",
            strprintf("value in (%s) < value out (%s)", FormatMoney(nValueIn), FormatMoney(value_out)));
    }

    // Tally transaction fees
    //NOTE：那我多出来的钱怎么就变成交易费了？
    //那我还想要找钱呢，你把我的找钱吃了？
    const CAmount txfee_aux = nValueIn - value_out;
    if (!MoneyRange(txfee_aux)) {
        return state.Invalid(ValidationInvalidReason::CONSENSUS, false, REJECT_INVALID, "bad-txns-fee-outofrange");
    }

    txfee = txfee_aux;
    return true;
}
