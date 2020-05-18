// Copyright (c) 2014-2015 The Dash developers
// Copyright (c) 2015-2017 The PIVX developers
// Copyright (c) 2019 The Zel developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BLVCASHNODES_BLVNODESYNC_H
#define BLVCASHNODES_BLVNODESYNC_H

#include <map>
#include "uint256.h"

#define BLVNODE_SYNC_FAILED -1
#define BLVNODE_SYNC_INITIAL 0
#define BLVNODE_SYNC_SPORKS 1
#define BLVNODE_SYNC_LIST 2
#define BLVNODE_SYNC_MNW 3
#define BLVNODE_SYNC_FINISHED 999

#define BLVNODE_SYNC_TIMEOUT 5
#define BLVNODE_SYNC_THRESHOLD 4 // Bitcoinlove has a default 16 connections. So we want to communicate with at least 1/4 of them


class ZelnodeSync;
class CNode;
class CDataStream;

extern ZelnodeSync zelnodeSync;

class ZelnodeSync
{
public:
    std::map<uint256, int> mapSeenSyncZNB;
    std::map<uint256, int> mapSeenSyncZNW;

    int64_t lastZelnodeList;
    int64_t lastZelnodeWinner;
    int64_t lastFailure;
    int nCountFailures;

    // sum of all counts
    int sumZelnodeList;
    int sumZelnodeWinner;
    // peers that reported counts
    int countZelnodeList;
    int countZelnodeWinner;

    // Count peers we've requested the list from
    int RequestedZelnodeAssets;
    int RequestedZelnodeAttempt;

    // Time when current zelnode asset sync started
    int64_t nTimeAssetSyncStarted;

    ZelnodeSync();

    void AddedZelnodeList(uint256 hash);
    void AddedZelnodeWinner(uint256 hash);
    void GetNextAsset();
    std::string GetSyncStatus();
    void ProcessMessage(CNode* pfrom, std::string& strCommand, CDataStream& vRecv);

    void Reset();
    void Process();
    bool IsSynced();
    bool IsBlockchainSynced();
    bool IsZelnodeListSynced() { return RequestedZelnodeAssets > BLVNODE_SYNC_LIST; }
    bool IsZelnodeWinnersSynced() { return RequestedZelnodeAssets > BLVNODE_SYNC_MNW; }
    bool IsFailed() { return RequestedZelnodeAssets == BLVNODE_SYNC_FAILED; }
    void ClearFulfilledRequest();
};


#endif //BLVCASHNODES_BLVNODESYNC_H
