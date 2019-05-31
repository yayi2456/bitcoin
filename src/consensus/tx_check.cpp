// Copyright (c) 2017-2018 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <consensus/tx_check.h>

#include <primitives/transaction.h>
#include <consensus/validation.h>

//基本检查：是不是空的交易？空的付款方？空的接收方？这个交易的大小是不是超过限制了？
//交易检查：给的钱的数目是不是正常？是不是负数？会不会溢出？
//有没有可能双花？
//
bool CheckTransaction(const CTransaction& tx, CValidationState &state, bool fCheckDuplicateInputs)
{
    // Basic checks that don't depend on any context
    if (tx.vin.empty())//付款签名方
        return state.Invalid(ValidationInvalidReason::CONSENSUS, false, REJECT_INVALID, "bad-txns-vin-empty");
    if (tx.vout.empty())//收款方
        return state.Invalid(ValidationInvalidReason::CONSENSUS, false, REJECT_INVALID, "bad-txns-vout-empty");
    // Size limits (this doesn't take the witness into account, as that hasn't been checked for malleability)
    if (::GetSerializeSize(tx, PROTOCOL_VERSION | SERIALIZE_TRANSACTION_NO_WITNESS) * WITNESS_SCALE_FACTOR > MAX_BLOCK_WEIGHT)
        return state.Invalid(ValidationInvalidReason::CONSENSUS, false, REJECT_INVALID, "bad-txns-oversize");

    // Check for negative or overflow output values
    CAmount nValueOut = 0;
    //auto关键字：使程序自动推断该变量的类型。经常用于代替声明较长的类型声明，或者在模板函数中的返回值获取。
    //（这是因为使用模板的函数一般来说返回值都是在编译的时候才知道的呢
    //比如这里，auto就是代表tx.vout类型，vector<CTxOUt>啦~
    for (const auto& txout : tx.vout)
    {
        if (txout.nValue < 0)//不给我就算了还想我倒贴？
            return state.Invalid(ValidationInvalidReason::CONSENSUS, false, REJECT_INVALID, "bad-txns-vout-negative");
        if (txout.nValue > MAX_MONEY)//太多也不行，程序溢出呢
            return state.Invalid(ValidationInvalidReason::CONSENSUS, false, REJECT_INVALID, "bad-txns-vout-toolarge");
        nValueOut += txout.nValue;
        if (!MoneyRange(nValueOut))//整个交易一共给出的钱的数目也不能溢出喔！NOTE：这是为啥呢？是因为要一起从UTXO减下来？不懂欸
            return state.Invalid(ValidationInvalidReason::CONSENSUS, false, REJECT_INVALID, "bad-txns-txouttotal-toolarge");
    }

    // Check for duplicate inputs - note that this check is slow so we skip it in CheckBlock。NOTE：欸可以这样干吗？
    //NOTE：我还是不太懂，难道只要这样检测就可以了？肯定不行的，应该还有其他的关于双花的检测。
    if (fCheckDuplicateInputs) {
        std::set<COutPoint> vInOutPoints;
        for (const auto& txin : tx.vin)
        {
            //你还想双花？
            //xtree在STL里面就是红黑树的实现。
            //终于要再次好好认识一下这个传说中的红黑树啦~
            //一个输入给两个输出是不允许的哟~
            if (!vInOutPoints.insert(txin.prevout).second)//标准库里面的一个函数insert，（xtree中的insert）。
                return state.Invalid(ValidationInvalidReason::CONSENSUS, false, REJECT_INVALID, "bad-txns-inputs-duplicate");
        }
    }

    if (tx.IsCoinBase())
    {
    //NOTE：Coinbase交易
    //一个块上会包含很多交易，其中第一个交易被称为“coinbase”交易。coinbase交易是矿工创建的，是为了奖励矿工进行POW挖矿而获得的激励
    //一般包括出块奖励以及手续费
        if (tx.vin[0].scriptSig.size() < 2 || tx.vin[0].scriptSig.size() > 100)//这个交易这部分可以存储一些自己想要存储的东西，不过注意要遵守字数限制喔
            return state.Invalid(ValidationInvalidReason::CONSENSUS, false, REJECT_INVALID, "bad-cb-length");
    }
    else
    {//你不是coinbase交易还敢么有UTXO输入？？？
        for (const auto& txin : tx.vin)
            if (txin.prevout.IsNull())
                return state.Invalid(ValidationInvalidReason::CONSENSUS, false, REJECT_INVALID, "bad-txns-prevout-null");
    }

    return true;
}
