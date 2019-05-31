// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2018 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <script/script.h>

#include <tinyformat.h>
#include <util/strencodings.h>

const char* GetOpName(opcodetype opcode)
{
    switch (opcode)
    {
    // push value
    case OP_0                      : return "0";
    case OP_PUSHDATA1              : return "OP_PUSHDATA1";
    case OP_PUSHDATA2              : return "OP_PUSHDATA2";
    case OP_PUSHDATA4              : return "OP_PUSHDATA4";
    case OP_1NEGATE                : return "-1";
    case OP_RESERVED               : return "OP_RESERVED";
    case OP_1                      : return "1";
    case OP_2                      : return "2";
    case OP_3                      : return "3";
    case OP_4                      : return "4";
    case OP_5                      : return "5";
    case OP_6                      : return "6";
    case OP_7                      : return "7";
    case OP_8                      : return "8";
    case OP_9                      : return "9";
    case OP_10                     : return "10";
    case OP_11                     : return "11";
    case OP_12                     : return "12";
    case OP_13                     : return "13";
    case OP_14                     : return "14";
    case OP_15                     : return "15";
    case OP_16                     : return "16";

    // control
    case OP_NOP                    : return "OP_NOP";
    case OP_VER                    : return "OP_VER";
    case OP_IF                     : return "OP_IF";
    case OP_NOTIF                  : return "OP_NOTIF";
    case OP_VERIF                  : return "OP_VERIF";
    case OP_VERNOTIF               : return "OP_VERNOTIF";
    case OP_ELSE                   : return "OP_ELSE";
    case OP_ENDIF                  : return "OP_ENDIF";
    case OP_VERIFY                 : return "OP_VERIFY";
    case OP_RETURN                 : return "OP_RETURN";

    // stack ops
    case OP_TOALTSTACK             : return "OP_TOALTSTACK";
    case OP_FROMALTSTACK           : return "OP_FROMALTSTACK";
    case OP_2DROP                  : return "OP_2DROP";
    case OP_2DUP                   : return "OP_2DUP";
    case OP_3DUP                   : return "OP_3DUP";
    case OP_2OVER                  : return "OP_2OVER";
    case OP_2ROT                   : return "OP_2ROT";
    case OP_2SWAP                  : return "OP_2SWAP";
    case OP_IFDUP                  : return "OP_IFDUP";
    case OP_DEPTH                  : return "OP_DEPTH";
    case OP_DROP                   : return "OP_DROP";
    case OP_DUP                    : return "OP_DUP";
    case OP_NIP                    : return "OP_NIP";
    case OP_OVER                   : return "OP_OVER";
    case OP_PICK                   : return "OP_PICK";
    case OP_ROLL                   : return "OP_ROLL";
    case OP_ROT                    : return "OP_ROT";
    case OP_SWAP                   : return "OP_SWAP";
    case OP_TUCK                   : return "OP_TUCK";

    // splice ops
    case OP_CAT                    : return "OP_CAT";
    case OP_SUBSTR                 : return "OP_SUBSTR";
    case OP_LEFT                   : return "OP_LEFT";
    case OP_RIGHT                  : return "OP_RIGHT";
    case OP_SIZE                   : return "OP_SIZE";

    // bit logic
    case OP_INVERT                 : return "OP_INVERT";
    case OP_AND                    : return "OP_AND";
    case OP_OR                     : return "OP_OR";
    case OP_XOR                    : return "OP_XOR";
    case OP_EQUAL                  : return "OP_EQUAL";
    case OP_EQUALVERIFY            : return "OP_EQUALVERIFY";
    case OP_RESERVED1              : return "OP_RESERVED1";
    case OP_RESERVED2              : return "OP_RESERVED2";

    // numeric
    case OP_1ADD                   : return "OP_1ADD";
    case OP_1SUB                   : return "OP_1SUB";
    case OP_2MUL                   : return "OP_2MUL";
    case OP_2DIV                   : return "OP_2DIV";
    case OP_NEGATE                 : return "OP_NEGATE";
    case OP_ABS                    : return "OP_ABS";
    case OP_NOT                    : return "OP_NOT";
    case OP_0NOTEQUAL              : return "OP_0NOTEQUAL";
    case OP_ADD                    : return "OP_ADD";
    case OP_SUB                    : return "OP_SUB";
    case OP_MUL                    : return "OP_MUL";
    case OP_DIV                    : return "OP_DIV";
    case OP_MOD                    : return "OP_MOD";
    case OP_LSHIFT                 : return "OP_LSHIFT";
    case OP_RSHIFT                 : return "OP_RSHIFT";
    case OP_BOOLAND                : return "OP_BOOLAND";
    case OP_BOOLOR                 : return "OP_BOOLOR";
    case OP_NUMEQUAL               : return "OP_NUMEQUAL";
    case OP_NUMEQUALVERIFY         : return "OP_NUMEQUALVERIFY";
    case OP_NUMNOTEQUAL            : return "OP_NUMNOTEQUAL";
    case OP_LESSTHAN               : return "OP_LESSTHAN";
    case OP_GREATERTHAN            : return "OP_GREATERTHAN";
    case OP_LESSTHANOREQUAL        : return "OP_LESSTHANOREQUAL";
    case OP_GREATERTHANOREQUAL     : return "OP_GREATERTHANOREQUAL";
    case OP_MIN                    : return "OP_MIN";
    case OP_MAX                    : return "OP_MAX";
    case OP_WITHIN                 : return "OP_WITHIN";

    // crypto
    case OP_RIPEMD160              : return "OP_RIPEMD160";
    case OP_SHA1                   : return "OP_SHA1";
    case OP_SHA256                 : return "OP_SHA256";
    case OP_HASH160                : return "OP_HASH160";
    case OP_HASH256                : return "OP_HASH256";
    case OP_CODESEPARATOR          : return "OP_CODESEPARATOR";
    case OP_CHECKSIG               : return "OP_CHECKSIG";
    case OP_CHECKSIGVERIFY         : return "OP_CHECKSIGVERIFY";
    case OP_CHECKMULTISIG          : return "OP_CHECKMULTISIG";
    case OP_CHECKMULTISIGVERIFY    : return "OP_CHECKMULTISIGVERIFY";

    // expansion
    case OP_NOP1                   : return "OP_NOP1";
    case OP_CHECKLOCKTIMEVERIFY    : return "OP_CHECKLOCKTIMEVERIFY";
    case OP_CHECKSEQUENCEVERIFY    : return "OP_CHECKSEQUENCEVERIFY";
    case OP_NOP4                   : return "OP_NOP4";
    case OP_NOP5                   : return "OP_NOP5";
    case OP_NOP6                   : return "OP_NOP6";
    case OP_NOP7                   : return "OP_NOP7";
    case OP_NOP8                   : return "OP_NOP8";
    case OP_NOP9                   : return "OP_NOP9";
    case OP_NOP10                  : return "OP_NOP10";

    case OP_INVALIDOPCODE          : return "OP_INVALIDOPCODE";

    default:
        return "OP_UNKNOWN";
    }
}

//NOTE：既然看到了就在这里解释一下几个协议吧。具体的解释可以在印象笔记里面找到喔~
/**1. P2PKH：Pay-to-Public-Key-Hash
 * 解锁脚本：<Sig><Pubkey>由接受方提供，用来证明自己的身份
 * 锁定脚本：DUP HASH160 <PubKeyHash> EQUALVERIFY CHECKSIG
 * 执行的时候，解锁脚本在前，锁定脚本在后，以逆波兰式基于栈的方式执行。
 * 2. P2PK：Pay-to-Public-Key
 * 与P2PKH比较，省去了验证Pubkey hahs的过程：
 * 解锁脚本：<Sig>
 * 锁定脚本：<PubKey> OP_CHECKSIG
 * 3. MS：Multiple Signatures，主要用来允许多个签名与公钥的验证
 * 解锁脚本：OP_0 <Sig1> <Sig2> ... <Sigm>，其中OP_0只是一个占位符，没有实际的意义。
 * 锁定脚本：M <PubKey1> <PubKey2> ... <PubKeyn> N OP_CHECKMULTISIG，其中M是为了解锁需要的最少的PubKey数目
 * 4. P2SH：Pay-to-Script-Hash：似乎是该版本的BItcoin常用的协议呢，是MS的变体
 * 解锁脚本：<Sig1> <Sig2> <2 PK1 PK2 PK3 PK4 PK5 5 OP_CHECKMULTISIG>
 * 锁定脚本：2 <Public Key A> <Public Key B> <Public Key C> 3 OP_CHECKMULTISIG
 * 锁定脚本不会以原型方式存在，而是会被首先做SHA256hash，然后运用RIPEMD160，添加需要的运算，可以变为：（中间的哈希：hash od redeem script
 * OP_HASH160 8ac1d7a2fa204a16dc984fa81cfdf86a2a4e1731 OP_EQUAL
 * 最终脚本变为：<Sig1> <Sig2> <2 PK1 PK2 PK3 PK4 PK5 5 OP_CHECKMULTISIG> OP_HASH160 8ac1d7a2fa204a16dc984fa81cfdf86a2a4e1731 OP_EQUAL
 * 首先会验证给出的解锁脚本是不是针对的是给出的锁定脚本，可以看到，这种方式的交易协议把制作脚本的责任推给了接收方。
 * 可以暂缓节点存储的压力。
 * 4.P2WSH：支持隔离见证的P2SH。以及P2WPKH：支持隔离见证的P2PKH
 * 什么是隔离见证？什么是见证？见证就是上面说的“锁定脚本”以及“解锁脚本”，隔离见证就是把这两者隔离出来。
 * 为什么要隔离出来？之前，见证是直接被封装在交易里面的。对于P2SH这种多输入多输出来说，会比较占空间。于是决定隔离出来，装到一个叫做SigWit的数据结构中。
 * 
 * 
**/
//获取该脚本中操作数的个数
//设置：精确：获取脚本中实际存在的操作数的个数
//设置：非精确：获取脚本中可以存在的最多的操作数的个数
unsigned int CScript::GetSigOpCount(bool fAccurate) const
{
    unsigned int n = 0;
    const_iterator pc = begin();//
    opcodetype lastOpcode = OP_INVALIDOPCODE;
    while (pc < end())
    {
        opcodetype opcode;
        if (!GetOp(pc, opcode))
            break;
        if (opcode == OP_CHECKSIG || opcode == OP_CHECKSIGVERIFY)
            n++;
        else if (opcode == OP_CHECKMULTISIG || opcode == OP_CHECKMULTISIGVERIFY)
        {//很明显你属于MS那一挂的，所以需要看看你究竟有多少个OP呢？
            if (fAccurate && lastOpcode >= OP_1 && lastOpcode <= OP_16)
                n += DecodeOP_N(lastOpcode);
            else
                n += MAX_PUBKEYS_PER_MULTISIG;//不精确的话，就给出最大值
        }
        lastOpcode = opcode;
    }
    return n;
}

unsigned int CScript::GetSigOpCount(const CScript& scriptSig) const
{
    if (!IsPayToScriptHash())//协议不是P2SH！
        return GetSigOpCount(true);

    // This is a pay-to-script-hash scriptPubKey;
    // get the last item that the scriptSig
    // pushes onto the stack:
    const_iterator pc = scriptSig.begin();//脚本开始
    std::vector<unsigned char> vData;
    while (pc < scriptSig.end())//遍历脚本数据
    {
        opcodetype opcode;
        if (!scriptSig.GetOp(pc, opcode, vData))//拿这个op以及他对应的操作数，更新pc，拿到opcode以及对应的操作数（存在vData中）//NOTE：函数里面有一个clear，不会把数据清除吗？我是不太懂啦
            return 0;//不正确的格式
        if (opcode > OP_16)//NOTE：不能出现除了OP_NUM之外的其他OP吗
            return 0;
    }

    /// ... and return its opcount:
    //使用vaData重新构造一个脚本，然后计算
    //为什么要这么做？
    CScript subscript(vData.begin(), vData.end());
    return subscript.GetSigOpCount(true);//返回精确的操作数们个数
}

bool CScript::IsPayToScriptHash() const
{
    // Extra-fast test for pay-to-script-hash CScripts:
    //验证协议是不是P2SH
    return (this->size() == 23 &&
            (*this)[0] == OP_HASH160 &&
            (*this)[1] == 0x14 &&
            (*this)[22] == OP_EQUAL);
}

bool CScript::IsPayToWitnessScriptHash() const
{
    // Extra-fast test for pay-to-witness-script-hash CScripts:
    //
    return (this->size() == 34 &&
            (*this)[0] == OP_0 &&
            (*this)[1] == 0x20);
}

// A witness program is any valid CScript that consists of a 1-byte push opcode
// followed by a data push between 2 and 40 bytes.
//支持隔离见证的版本
//它的特点就是，一个版本号1-byte，后面接着哈希值，20byte（P2WPKH）或者32byte（P2WSH）
bool CScript::IsWitnessProgram(int& version, std::vector<unsigned char>& program) const
{
    if (this->size() < 4 || this->size() > 42) {
        return false;//size不对
    }
    if ((*this)[0] != OP_0 && ((*this)[0] < OP_1 || (*this)[0] > OP_16)) {
        return false;//版本号不对
    }
    if ((size_t)((*this)[1] + 2) == this->size()) {
        version = DecodeOP_N((opcodetype)(*this)[0]);//版本号
        program = std::vector<unsigned char>(this->begin() + 2, this->end());//script hash
        return true;
    }
    return false;
}

//NOTE：我没太懂这个函数想干啥...
bool CScript::IsPushOnly(const_iterator pc) const
{
    while (pc < end())
    {
        opcodetype opcode;
        if (!GetOp(pc, opcode))
            return false;
        // Note that IsPushOnly() *does* consider OP_RESERVED to be a
        // push-type opcode, however execution of OP_RESERVED fails, so
        // it's not relevant to P2SH/BIP62 as the scriptSig would fail prior to
        // the P2SH special validation code being executed.
        if (opcode > OP_16)
            return false;
    }
    return true;
}

bool CScript::IsPushOnly() const
{
    return this->IsPushOnly(begin());//em，NOTE：begin是谁，有this吗？
}

std::string CScriptWitness::ToString() const
{
    std::string ret = "CScriptWitness(";
    for (unsigned int i = 0; i < stack.size(); i++) {
    //哇感觉还蛮机智哒，因为第一个i不会有逗号啊，不过这样会不会加重了运行时的时间呢还是说编译的时候就会优化掉了呢。
    //感觉像是编译+体系结构？
    //NOTE
        if (i) {
            ret += ", ";
        }
        ret += HexStr(stack[i]);
    }
    return ret + ")";
}
//给的这个script里面究竟有没有一个能用的op
bool CScript::HasValidOps() const
{
    CScript::const_iterator it = begin();
    while (it < end()) {
        opcodetype opcode;
        std::vector<unsigned char> item;
        if (!GetOp(it, opcode, item) || opcode > MAX_OPCODE || item.size() > MAX_SCRIPT_ELEMENT_SIZE) {
            return false;
        }
    }
    return true;
}
//获取给定脚本中的给定pc开始的一个操作符以及他所对应的操作数
bool GetScriptOp(CScriptBase::const_iterator& pc, CScriptBase::const_iterator end, opcodetype& opcodeRet, std::vector<unsigned char>* pvchRet)
{
    opcodeRet = OP_INVALIDOPCODE;
    if (pvchRet)
        pvchRet->clear();//eraser all
    if (pc >= end)
        return false;

    // Read instruction
    if (end - pc < 1)
        return false;
    unsigned int opcode = *pc++;

//这下肯定有东西了
    // Immediate operand
    if (opcode <= OP_PUSHDATA4)
    {
        unsigned int nSize = 0;
        if (opcode < OP_PUSHDATA1)//OP_0
        {
            nSize = opcode;
        }
        else if (opcode == OP_PUSHDATA1)
        {
            if (end - pc < 1)//一定要有一个操作数啊
                return false;
            nSize = *pc++;//NOTE：nSize里面存的是操作数
        }
        else if (opcode == OP_PUSHDATA2)
        {
            if (end - pc < 2)//一定要有两个操作数啊
                return false;
            nSize = ReadLE16(&pc[0]);//16bits，拿到从&pc[0]地址开始的接下来的16bits的数值，即两个操作数
            pc += 2;//跨过这两个操作数
        }
        else if (opcode == OP_PUSHDATA4)
        {
            if (end - pc < 4)
                return false;
            nSize = ReadLE32(&pc[0]);//32bits，拿到从&pc[0]地址开始的接下来的32bits的数值，即四个操作数
            pc += 4;//跨这4个操作数
        }
        if (end - pc < 0 || (unsigned int)(end - pc) < nSize)
            return false;//地址对不上，一定是哪里出现了问题
        if (pvchRet)//NOTE：？
            pvchRet->assign(pc, pc + nSize);//把操作数给pvchRet
        pc += nSize;//pc移位到下一个需要判断的位置
    }

    opcodeRet = static_cast<opcodetype>(opcode);//拿到OP操作符
    return true;
}
