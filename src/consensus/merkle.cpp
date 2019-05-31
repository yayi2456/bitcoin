// Copyright (c) 2015-2018 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <consensus/merkle.h>
#include <hash.h>
#include <util/strencodings.h>

/*     WARNING! If you're reading this because you're learning about crypto
       and/or designing a new system that will use merkle trees, keep in mind
       that the following merkle tree algorithm has a serious flaw related to
       duplicate txids, resulting in a vulnerability (CVE-2012-2459).

       The reason is that if the number of hashes in the list at a given time
       is odd, the last one is duplicated before computing the next level (which
       is unusual in Merkle trees). This results in certain sequences of
       transactions leading to the same merkle root. For example, these two
       trees:
       //NOTE：大概就是，本来序列只有123456的，块头数据不可更改里面包含了R，所以本来说来，123456对应的tx应该是安全存储的。
       //但是发生了意外：把123456改成12345656也能得出同一个R，这不就麻烦了吗？
        //按照这里说的，12345656就被认定是无效的，但是实际上人家老实本分的123456有效的呀。
        //但是接收者不管，接收者记得，你这个块头不行的呀，你这个交易列表无效的呀，你再给我这个块头我也不承认的呀。
        //发送者委屈。
        //233话说回来，为什么就不能重新验证一下交易列表而是后来给的也要拒绝呢？？？
        //不明白。

       //NOTE：HASH(F)==HASH(F||F)？？？

                    A               A
                  /  \            /   \
                B     C         B       C
               / \    |        / \     / \
              D   E   F       D   E   F   F
             / \ / \ / \     / \ / \ / \ / \
             1 2 3 4 5 6     1 2 3 4 5 6 5 6

             那么这样呢
                     A               A
                  /  \            /   \
                B     C         B       C
               / \    |        / \     / \
              D   E   F       D   E   F   F
             / \ / \ / \     / \ / \ / \ / \
             1 2 3 4 5 5     1 2 3 4 5 5 5 5


       for transaction lists [1,2,3,4,5,6] and [1,2,3,4,5,6,5,6] (where 5 and
       6 are repeated) result in the same root hash A (because the hash of both
       of (F) and (F,F) is C).

       The vulnerability results from being able to send a block with such a
       transaction list, with the same merkle root, and the same block hash as
       the original without duplication, resulting in failed validation. If the  //NOTE：emm为什么会验证失败呢？
       receiving node proceeds to mark that block as permanently invalid
       however, it will fail to accept further unmodified (and thus potentially
       valid) versions of the same block.  //NOTE：为什么会不接受这个块？
       
       We defend against this by detecting
       the case where we would hash two identical hashes at the end of the list
       together, and treating that identically to the block having an invalid
       merkle root. 
       //NOTE：检测方式：把任意两个tx放在最后两个，看看结果Root是什么，这个Root会被当做是无效的Root。
       Assuming no double-SHA256 collisions, this will detect all
       known ways of changing the transactions without affecting the merkle
       root.
*/


uint256 ComputeMerkleRoot(std::vector<uint256> hashes, bool* mutated) {
    bool mutation = false;
    while (hashes.size() > 1) {
        if (mutated) {
            for (size_t pos = 0; pos + 1 < hashes.size(); pos += 2) {
                if (hashes[pos] == hashes[pos + 1]) mutation = true;//每两个比较，看看是不是存在上述的FF情况
            }
        }
        if (hashes.size() & 1) {//奇数个哈希值，不行，需要在后面再加一个同样的哈希值。
        //NOTE：话说，为啥不行呢？为什么一定要求merkle树是一个二叉平衡树呢？？？
            hashes.push_back(hashes.back());
        }
        SHA256D64(hashes[0].begin(), hashes[0].begin(), hashes.size() / 2);//crypto中的函数。应该是计算更上一层的哈希值vector的。
        hashes.resize(hashes.size() / 2);
    }//该循环出来之后，应该已经到了最上层：计算得到了根
    if (mutated) *mutated = mutation;//变异状态设置为最上层的变异状态
    if (hashes.size() == 0) return uint256();//不太可能是0，如果是0，一定是传入的hashes就是空的。返回空的256
    return hashes[0];//返回树根。
}


uint256 BlockMerkleRoot(const CBlock& block, bool* mutated)
{
    std::vector<uint256> leaves;
    leaves.resize(block.vtx.size());//塑造leaves的大小，一共只需要存储vtx.size个交易哈希就可以啦，因为是叶节点嘛
    for (size_t s = 0; s < block.vtx.size(); s++) {
        leaves[s] = block.vtx[s]->GetHash();//获取交易哈希
    }
    return ComputeMerkleRoot(std::move(leaves), mutated);//获取Root并返回
}

uint256 BlockWitnessMerkleRoot(const CBlock& block, bool* mutated)
{
    std::vector<uint256> leaves;
    leaves.resize(block.vtx.size());
    leaves[0].SetNull(); // The witness hash of the coinbase is 0.//NOTE：置空啦！？那第一个交易怎么办！？
    for (size_t s = 1; s < block.vtx.size(); s++) {
        leaves[s] = block.vtx[s]->GetWitnessHash();//witness哈希//先检查有人监视吗？有好的我算，没有算了我不算
    }
    return ComputeMerkleRoot(std::move(leaves), mutated);//move：返回一个指向leaves的右值引用。不懂为啥要用move。应该是因为限制指向右值，所以只能读不能改吧？
    //右值：可读，左值：可寻址
}

