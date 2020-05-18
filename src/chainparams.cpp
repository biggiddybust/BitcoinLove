// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "key_io.h"
#include "main.h"
#include "crypto/equihash.h"

#include "util.h"
#include "utilstrencodings.h"

#include <assert.h>

#include <boost/assign/list_of.hpp>

#include "chainparamsseeds.h"

#include <mutex>
#include "metrics.h"
#include "crypto/equihash.h"

static CBlock CreateGenesisBlock(const char* pszTimestamp, const CScript& genesisOutputScript, uint32_t nTime, const uint256& nNonce, const std::vector<unsigned char>& nSolution, uint32_t nBits, int32_t nVersion, const CAmount& genesisReward)
{
    // To create a genesis block for a new chain which is Overwintered:
    //   txNew.nVersion = OVERWINTER_TX_VERSION
    //   txNew.fOverwintered = true
    //   txNew.nVersionGroupId = OVERWINTER_VERSION_GROUP_ID
    //   txNew.nExpiryHeight = <default value>
    CMutableTransaction txNew;
    txNew.nVersion = 1;
    txNew.vin.resize(1);
    txNew.vout.resize(1);
    txNew.vin[0].scriptSig = CScript() << 520617983 << CScriptNum(4) << std::vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
    txNew.vout[0].nValue = genesisReward;
    txNew.vout[0].scriptPubKey = genesisOutputScript;

    CBlock genesis;
    genesis.nTime    = nTime;
    genesis.nBits    = nBits;
    genesis.nNonce   = nNonce;
    genesis.nSolution = nSolution;
    genesis.nVersion = nVersion;
    genesis.vtx.push_back(txNew);
    genesis.hashPrevBlock.SetNull();
    genesis.hashMerkleRoot = genesis.BuildMerkleTree();
    return genesis;
}

/**
 * Build the genesis block. Note that the output of its generation
 * transaction cannot be spent since it did not originally exist in the
 * database (and is in any case of zero value).
 *
 * >>> from pyblake2 import blake2s
 * >>> 'Bitcoinlove' + blake2s(b'TODO').hexdigest()
 *
 * CBlock(hash=00052461, ver=4, hashPrevBlock=00000000000000, hashMerkleRoot=94c7ae, nTime=1516980000, nBits=1f07ffff, nNonce=6796, vtx=1)
 *   CTransaction(hash=94c7ae, ver=1, vin.size=1, vout.size=1, nLockTime=0)
 *     CTxIn(COutPoint(000000, -1), coinbase 04ffff071f0104455a6361736830623963346565663862376363343137656535303031653335303039383462366665613335363833613763616331343161303433633432303634383335643334)
 *     CTxOut(nValue=0.00000000, scriptPubKey=0x5F1DF16B2B704C8A578D0B)
 *   vMerkleTree: 94c7ae
 */
static CBlock CreateGenesisBlock(uint32_t nTime, const uint256& nNonce, const std::vector<unsigned char>& nSolution, uint32_t nBits, int32_t nVersion, const CAmount& genesisReward)
{
    const char* pszTimestamp = "BitcoinLovebf2839041bae14cece46440eb9e8683e7af0e4468da10746375b5bb6d3f38ba1";
    const CScript genesisOutputScript = CScript() << ParseHex("04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5f") << OP_CHECKSIG;
    return CreateGenesisBlock(pszTimestamp, genesisOutputScript, nTime, nNonce, nSolution, nBits, nVersion, genesisReward);
}

/**
 * Main network
 */
/**
 * What makes a good checkpoint block?
 * + Is surrounded by blocks with reasonable timestamps
 *   (no blocks before with a timestamp after, none after with
 *    timestamp before)
 * + Contains no strange transactions
 */

const arith_uint256 maxUint = UintToArith256(uint256S("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"));

class CMainParams : public CChainParams {
public:
    CMainParams() {
        strNetworkID = "main";
        strCurrencyUnits = "BLV";
	bip44CoinType = 19167;
        consensus.fCoinbaseMustBeProtected = true;
        consensus.nSubsidySlowStartInterval = 5000;
        consensus.nSubsidyHalvingInterval = 655350; // 2.5 years
        consensus.nMajorityEnforceBlockUpgrade = 750;
        consensus.nMajorityRejectBlockOutdated = 950;
        consensus.nMajorityWindow = 4000;
        consensus.powLimit = uint256S("0007ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.nDigishieldAveragingWindow = 17;
        assert(maxUint/UintToArith256(consensus.powLimit) >= consensus.nDigishieldAveragingWindow);
        consensus.nDigishieldMaxAdjustDown = 32; // 32% adjustment down
        consensus.nDigishieldMaxAdjustUp = 16; // 16% adjustment up
	consensus.nPowAllowMinDifficultyBlocksAfterHeight = boost::none;
        consensus.nPowTargetSpacing = 2 * 60;

        consensus.vUpgrades[Consensus::BASE].nProtocolVersion = 170002;
        consensus.vUpgrades[Consensus::BASE].nActivationHeight =
            Consensus::NetworkUpgrade::ALWAYS_ACTIVE;

        consensus.vUpgrades[Consensus::UPGRADE_TESTDUMMY].nProtocolVersion = 170002;
        consensus.vUpgrades[Consensus::UPGRADE_TESTDUMMY].nActivationHeight =
            Consensus::NetworkUpgrade::NO_ACTIVATION_HEIGHT;

	consensus.vUpgrades[Consensus::UPGRADE_LWMA].nProtocolVersion = 170002;
	consensus.vUpgrades[Consensus::UPGRADE_LWMA].nActivationHeight = 125000;

	consensus.vUpgrades[Consensus::UPGRADE_EQUI144_5].nProtocolVersion = 170002;
	consensus.vUpgrades[Consensus::UPGRADE_EQUI144_5].nActivationHeight = 125100;

	consensus.vUpgrades[Consensus::UPGRADE_ACADIA].nProtocolVersion = 170007;
        consensus.vUpgrades[Consensus::UPGRADE_ACADIA].nActivationHeight = 250000;		// Approx January 12th

    consensus.vUpgrades[Consensus::UPGRADE_KAMIOOKA].nProtocolVersion = 170012;
        consensus.vUpgrades[Consensus::UPGRADE_KAMIOOKA].nActivationHeight = 372500;  // Approx July 2nd - Zel Team Boulder Meetup 

	consensus.nZawyLWMAAveragingWindow = 60;
	consensus.eh_epoch_fade_length = 11;

	eh_epoch_1 = eh200_9;
        eh_epoch_2 = eh144_5;
        eh_epoch_3 = zelHash;

        // The best chain should have at least this much work.
        consensus.nMinimumChainWork = uint256S("0x00");

        /**
         * The message start string should be awesome! ⓩ❤
         */
        pchMessageStart[0] = 0xd0;
        pchMessageStart[1] = 0xe1;
        pchMessageStart[2] = 0xcd;
        pchMessageStart[3] = 0xf4;
        vAlertPubKey = ParseHex("04025b2cf3a116782a69bb68cb4ae5ba3b7f05069f7139b75573dd28e48f8992d95c118122b618d4943456ad64e7356b0b45b2ef179cbe3d9767a2426662d13d32"); //Zel Technologies GmbH
        nDefaultPort = 16525;
        nPruneAfterHeight = 100000;


        genesis = CreateGenesisBlock(
            1587650672,
            uint256S("0x0000000000000000000000000000000000000000000000000000000000001867"),
            ParseHex("0024b090d250b73cbb0da55281b1e286f4adfbb3d74b538ca540a424bdfed734d883cbc7b6fa80b912a502e447f3bd17119f199a625e981e6d49c97b96e98d0f0fa6aeee5f648dccb9b4e5986155ead7101ce7030790b42a7e5aaf35dc1eb47659c515115244d8030542eaf6637c360b11e2e93a7b1074ed3760ee5f474c12539671cb95f84cb9258856a2ce35e27716dba8f923af0b067897a345c90fd67076bb1bd63f7c78cb09004bf9710354b43f20c6c1ac022eeae94ad3b447fd1668f91b38b76a6bf8e2b94ecff6b0638b7e1ed1210de40a17f3da3fa1b6c2d2589e15da8685ec5cd94c1039da6f5f06be0fde019704aa7604da51025426f304e88a26584598a86e41711a308b6e0a0afd38823f0794cdd45b0dc03bef58a0dc6888a6a123867c41f916d07f3e3b4617c1dd93a2c2cffe77d54374eb6e743c41f796bb5ad4d57062fd24c36e50ff52efffa3c703bf334dfa29c395d14453b1675c407758f7dcff740e453374866ced01f6f9d3b5127d64e9c3849ad8c30ed3423fd852d18377e3b3d8573e911dcb481cdd79214ef182c3666cc56b1d634b4e1de5fce6271a655d087f8f5d29c63039ef663371feaea1bd888a13641b45fb1cebe363e4519fee470bb75ef7de2c385d550e0a2096e1824de8727564f12b0de0f5d26956fc3ecb1dbdbda7eb1389dae35b950335fae55188d0bf391405978418491a55cad4d9a7d301e087aa99347e87b82312543d10defba19e2d4288d0228f2cdbfedb378d0d82713b5ae2743bc9152167ae8be511a6913f2cf92822f4666d4d70b3756183635a3deb32793d1a59da11006a208b88f464ba18b552cb3c512243e11aea79192fcd04bcccb680a8d714e4ad4bfe66676417baf1155ae3d0f6dfd349923e87791de220eb8d2b9dc3af2b62a32ef7524c7d9688a5112ef140e25f863363480171d2c5496ebe0bc4b060190a83bf78a1cdf2a7903b6a0349725398f70027a6016670470dd94bd83ab02cc7b17a10da2e756401f4e0dd2b8c09a8a1ba47254ebf4b436359c0a5ae28c5001235f0156269f3207e0551e5cc69248f697f60b12a7ee5a687717cdda8fe06638b6d2b4c43b0ea66ec8fd579e6d77b4d7fef4d26e3120acf214dcf9e261606b3563a4e9239d4d99c397ade81ada0336bb826c405f16fa276014cd2c3c10612fddde511c998d644a23d20b63f558646992a000764f3d73a2ff379a879c13a700e975d6be8ba3c48140e95de9aa3c3275e2622fd464e4621b8dd8f2cd521297cd244cb639d3d5625809dead4aaa69c37e1b4089a40aa90e1bfc123a2726a92e9551958b8b5ce5b10cf157d969ab07dbb7984209531877786d21c4c1f15cb0d8f3dd56701569c345028cb50aa415e5dc97e216802bde751ee3d67433425a4ce9415a7d59684e9063dd25ed5689179c212d140acf2f91b8ec53e029f0a151b50dd515135d633536e9cdf77596a415097db18ce5591e816e910cdb206ea35ea731e06761bea71407a33e4f1de558dca378671736efa9631ff9341ac33badce86b972233296664612c322501f7f8fb0ba643126dbc2beaf5cf721949f9dd69086aa0d77fe12c33ed1f6284512d74b1d699be32f939aaaaaf156bca3707d598d2d0fe5bf22be73f9ef59be1dab7b9ac710824bbd553e706eb4f05f96ce4e132f2fb163c2555093bd1b9d6184fa6efd201b4f7cfa10d680a4ebe120c969596fa841f4f607861668841fdd19a668e0b0814a9b0fa1359744d94daf49de5e6dda72fbafba0a8120ce6b18ac60b8543f0016aa4d3d0cd3d9d4e56072dbf76a12793dfd8c91c34c7af37780d5046f98b82126756c11a990895246412b3b7720e151b00d1e6811f55cf72bad3c5b7d4c7eaecbae7569efbba5f7c20"),
            0x1f07ffff, 4, 0);
        consensus.hashGenesisBlock = genesis.GetHash();
        printf("%s\n", consensus.hashGenesisBlock.ToString().c_str());
	printf("%s\n", genesis.hashMerkleRoot.ToString().c_str());
        assert(consensus.hashGenesisBlock == uint256S("0x0001ef3414b00d7f224be4f48584a8ef3ecca5e015fe050362e060990b0446ef"));
        assert(genesis.hashMerkleRoot == uint256S("0xdcbddb3ae83c9844c050b950d51d1f543086eca5feff6bb50b1aa8a4ced5ce59"));

        vFixedSeeds.clear();
        vSeeds.clear();
        vSeeds.push_back(CDNSSeedData("vps.zel.network", "singapore.zel.network")); // MilesManley
        vSeeds.push_back(CDNSSeedData("vpsone.zel.network", "bangalore.zel.network")); // MilesManley
        vSeeds.push_back(CDNSSeedData("vpstwo.zel.network", "frankfurt.zel.network")); // MilesManley
        vSeeds.push_back(CDNSSeedData("vpsthree.zel.network", "newyork.zel.network")); // MilesManley
        vSeeds.push_back(CDNSSeedData("vps.bitcoinlove.online", "dnsseed.bitcoinlove.online")); // TheTrunk

        // guarantees the first 2 characters, when base58 encoded, are "B1"
        base58Prefixes[PUBKEY_ADDRESS]     = {0x05,0xA2};
        // guarantees the first 2 characters, when base58 encoded, are "B3"
        base58Prefixes[SCRIPT_ADDRESS]     = {0x05,0xA6};
        // the first character, when base58 encoded, is "5" or "K" or "L" (as in Bitcoin)
        base58Prefixes[SECRET_KEY]         = {0x80};
        // do not rely on these BIP32 prefixes; they are not specified and may change
        base58Prefixes[EXT_PUBLIC_KEY]     = {0x04,0x88,0xB2,0x1E};
        base58Prefixes[EXT_SECRET_KEY]     = {0x04,0x88,0xAD,0xE4};
        // guarantees the first 2 characters, when base58 encoded, are "zc"
        base58Prefixes[ZCPAYMENT_ADDRRESS] = {0x16,0x9A};
        // guarantees the first 4 characters, when base58 encoded, are "ZiVK"
        base58Prefixes[ZCVIEWING_KEY]      = {0xA8,0xAB,0xD3};
        // guarantees the first 2 characters, when base58 encoded, are "SK"
        base58Prefixes[ZCSPENDING_KEY]     = {0xAB,0x36};

        bech32HRPs[SAPLING_PAYMENT_ADDRESS]      = "za";
        bech32HRPs[SAPLING_FULL_VIEWING_KEY]     = "zviewa";
        bech32HRPs[SAPLING_INCOMING_VIEWING_KEY] = "zivka";
        bech32HRPs[SAPLING_EXTENDED_SPEND_KEY]   = "secret-extended-key-main";

        vFixedSeeds = std::vector<SeedSpec6>(pnSeed6_main, pnSeed6_main + ARRAYLEN(pnSeed6_main));

        fMiningRequiresPeers = true;
        fDefaultConsistencyChecks = false;
        fRequireStandard = true;
        fMineBlocksOnDemand = false;
        fTestnetToBeDeprecatedFieldRPC = false;

        strSporkKey = "04f5382d5868ae49aedfd67efce7c0f56a66a9405a2cc13f8ef236aabb3f0f1d00031f9b9ca67edc93044918a1cf265655108bab531e94c7d48918e40a94a34f77";
        nStartZelnodePayments = 1550748576; //Thu, 21 Feb 2019 11:29:36 UTC // Not being used, but could be in the future
        networkID = CBaseChainParams::Network::MAIN;
        strZelnodeTestingDummyAddress= "t1Ub8iNuaoCAKTaiVyCh8d3iZ31QJFxnGzU";

        checkpointData = (CCheckpointData) {
            boost::assign::map_list_of
            (0, consensus.hashGenesisBlock), //Halep won French Open 2018
            1587650672,     // * UNIX timestamp of last checkpoint block
            0,              // * total number of transactions between genesis and last checkpoint
                            //   (the tx=... number in the SetBestChain debug.log lines)
            1               // * estimated number of transactions per day
                            //   total number of tx / (checkpoint block height / (24 * 24))
        };

        // Hardcoded fallback value for the Sprout shielded value pool balance
        // for nodes that have not reindexed since the introduction of monitoring
        // in #2795.
        // nSproutValuePoolCheckpointHeight = 520633;
        // nSproutValuePoolCheckpointBalance = 22145062442933;
        // fZIP209Enabled = true;
        // hashSproutValuePoolCheckpointBlock = uint256S("0000000000c7b46b6bc04b4cbf87d8bb08722aebd51232619b214f7273f8460e");
    }
};
static CMainParams mainParams;

/**
 * testnet-kamiooka
 */
class CTestNetParams : public CChainParams {
public:
    CTestNetParams() {
        strNetworkID = "test";
        strCurrencyUnits = "TESTBLV";
        bip44CoinType = 1;
        consensus.fCoinbaseMustBeProtected = true;
        consensus.nSubsidySlowStartInterval = 5000;
        consensus.nSubsidyHalvingInterval = 655350; // 2.5 years
        consensus.nMajorityEnforceBlockUpgrade = 51;
        consensus.nMajorityRejectBlockOutdated = 75;
        consensus.nMajorityWindow = 400;
        consensus.powLimit = uint256S("07ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.nDigishieldAveragingWindow = 17;
        assert(maxUint/UintToArith256(consensus.powLimit) >= consensus.nDigishieldAveragingWindow);
        consensus.nDigishieldMaxAdjustDown = 32; // 32% adjustment down
        consensus.nDigishieldMaxAdjustUp = 16; // 16% adjustment up
        consensus.nPowAllowMinDifficultyBlocksAfterHeight = 299187;
        consensus.nPowTargetSpacing = 2 * 60;

        consensus.vUpgrades[Consensus::BASE].nProtocolVersion = 170002;
        consensus.vUpgrades[Consensus::BASE].nActivationHeight =
        Consensus::NetworkUpgrade::ALWAYS_ACTIVE;

        consensus.vUpgrades[Consensus::UPGRADE_TESTDUMMY].nProtocolVersion = 170002;
        consensus.vUpgrades[Consensus::UPGRADE_TESTDUMMY].nActivationHeight =
        Consensus::NetworkUpgrade::NO_ACTIVATION_HEIGHT;

        consensus.vUpgrades[Consensus::UPGRADE_LWMA].nProtocolVersion = 170002;
	    consensus.vUpgrades[Consensus::UPGRADE_LWMA].nActivationHeight = 70;

	    consensus.vUpgrades[Consensus::UPGRADE_EQUI144_5].nProtocolVersion = 170002;
	    consensus.vUpgrades[Consensus::UPGRADE_EQUI144_5].nActivationHeight = 100;

        consensus.vUpgrades[Consensus::UPGRADE_ACADIA].nProtocolVersion = 170007;
        consensus.vUpgrades[Consensus::UPGRADE_ACADIA].nActivationHeight = 120;

	    consensus.vUpgrades[Consensus::UPGRADE_KAMIOOKA].nProtocolVersion = 170012;
        consensus.vUpgrades[Consensus::UPGRADE_KAMIOOKA].nActivationHeight = 720;


        consensus.nZawyLWMAAveragingWindow = 60;
	    consensus.eh_epoch_fade_length = 10;

	    //eh_epoch_1 = eh96_5;
    eh_epoch_1 = eh200_9;
        eh_epoch_2 = eh144_5;
        eh_epoch_3 = zelHash;


        pchMessageStart[0] = 0xf2;
        pchMessageStart[1] = 0x1b;
        pchMessageStart[2] = 0xdc;
        pchMessageStart[3] = 0xbc;
        vAlertPubKey = ParseHex("044b5cb8fd1db34e2d89a93e7becf3fb35dd08a81bb3080484365e567136403fd4a6682a43d8819522ae35394704afa83de1ef069a3104763fd0ebdbdd505a1386"); //Zel Technologies GmbH

        nDefaultPort = 26525;

        nPruneAfterHeight = 1000;

        genesis = CreateGenesisBlock(
            1587661086,
            uint256S("0x000000000000000000000000000000000000000000000000000000000000001e"),
            ParseHex("0025f40814f3900bf1f872a495b632e65bf4dee02213b9a3459c2594d1b72f21698f3fbf627f7359b06203e9b10b9d1fe221770b0054626f1b422b94329ad217be6c7dba898bb7b3f3f575ee488ced808afb12cf030ad7b31ad54205a219a47de7f8e42987ef301d720ece8288aa6dfab9dc53b21457f50b80bc872f2614168ea372910f140946ade3a1e4d5430907d4f7b11c42464e4d4e25fdab64ac39f26afa83d695463ff4080d251be3b8895ccc9d55f0f6494a8f9d92a8d3f8070e2d9dee1caf7d01fb388324fc70ab8a93fb1b569210bcfbaf482a24b752b272f930cec910dfc3ce7bf341367e90db5a9d3ff8c1b49aac7b129b2ff3dc6bfa14d2a193f4925c3edb8f05dc55f453aa419c96f3e51f5c7b88a6241f9f2fbc45f6f260f4e291bdf96eb4162a99c33e514acf4641880d7d5fcc2b3ecf3ec97a4033beaaff770343fda5845cc0d02cb72245d92de90039a0106659cc52fd8b62101a930e18c96b08ee330fbcd202402155db65bdd54ca0d385d17ea74f9fdc08dae1e2d8ca5c7db706b129f5347b08b7c91fe9d31fbb4a309e8cfbdffbb754c440fb8e815c8a5373c30b5059574287171bdbba45834ae1a32f0870b86af50e60a6f9ab1b3a011d09a151c91f33b8ce073f37690dcbcf80b0653523f75110f50c26536a40ffd27f4f2d990b5f222245f7acbc93847a451cf103752b45e30394408ce3cdbe469b68b0a78ff782429f123f5da33e624c3d51f3c09ff44fd47faf506be642bdff3b2b07607e6f83609a0b3caee3b0d5325c7564b35bb47d08db02d1528c0d0d28e7926168358e15e4d70f964c03a67f899e51489b1d7ee1996ddb409e2bde1a0e6c0546d72612dd48719873d162ee7127387c5de3ef5f13f8c519ea557473bf56c425a839c7cb5bda1e6f7735e7428d2fdb3e8fd589d3fa6fa3be9ebfbe5c320a002644a403c9836e971fd20d58ef48b566f4f7c65f19e1f97db8939c4cb13b13de7e2c37b112e13900f9048c99cfeb98bf3fc6a222cd9e79f2f986c0d1cb1d1bd9c39f44e2209dee80c38c432715d530231bd6c90880743b19ca8b531920119afe131531cd4473ccd242c9da3724e9ae91b2cba64ca75c730a2245f38ddc1c12821ad0f5aed3d55df2de90d460c98faeb89a7e2eb24e46595daf9b3e2a3391abf33f72129dd46dee0301c5417d1f1dfb8d94e500bc4dcc72e2607ea76d0554cab87b0c014ec790d0935b9303a8341a79ebd2055850dfa39ada4b66b084d380f03dd69e591b95f2144f75302f88c44efe20347e83d85ae95ca678349c1d7d19ddb699f621a9d7b38f48503aea6a88d6f1e93638dfeb9555ac18c9ac837fbd20beb241c3bab03328ebf332309fc5dd0f574312927b7d23d8af7fb6a7354362f1baa50e154ab23777756d353fded13fe15000746a287dc0892b178160f5bb6e6c72cd26d8f3bc1225fa1128dfdb059e7715da9e5a70479ce8fdeb1b117ab4ba73cefd60b4af429ebb2c04bca8d327a05c1908bf30d78f666357780379002c62afa6e99f18761a98170a5fdbb63d4dab04e22fe286fdc781fe454b25bd869357118f6745da63026aed1ec69b4657187b299d7c616393a48ac7ea03086131ed91e5b3efaafc34466fbe351518097895c4234ec9c39b31e57cf45e03c401d456dbfa453645c04db6ce42f0844e6725213fad3b31a49770e77c8c37524b556f0aeb19993a8706ffe5d0b36cbcadd11a99cae3ed5f575f2fbd37cf5abb26689f9f7625cd0635c65a45bc0b29dabfc37c0632e42ff51f5cb1679e91b314599f4de5beb6bbba0c5ba41ae63bda4ff13741646a20df2d580d5f1acd1395b381272ad2478f7931e76592bad5c19cf4b4291baec48deef12503a51db37507c2d11eccb0ff56dc"),
            0x2007ffff, 4, 0);
        
        consensus.hashGenesisBlock = genesis.GetHash();
        printf("%s\n", consensus.hashGenesisBlock.ToString().c_str());
	printf("%s\n", genesis.hashMerkleRoot.ToString().c_str());
        assert(consensus.hashGenesisBlock == uint256S("0x04ac0086967f92d3896276bfeb5d521e465ca0b4cb2942b89238f5cd5654e53c"));
        assert(genesis.hashMerkleRoot == uint256S("0xdcbddb3ae83c9844c050b950d51d1f543086eca5feff6bb50b1aa8a4ced5ce59"));

        vFixedSeeds.clear();
        vSeeds.clear();
        vSeeds.push_back(CDNSSeedData("test.vps.zel.network", "test.singapore.zel.network")); // MilesManley
        vSeeds.push_back(CDNSSeedData("test.vpsone.zel.network", "test.bangalore.zel.network")); // MilesManley
        vSeeds.push_back(CDNSSeedData("test.vpstwo.zel.network", "test.frankfurt.zel.network")); // MilesManley
        vSeeds.push_back(CDNSSeedData("test.vpsthree.zel.network", "test.newyork.zel.network")); // MilesManley
        //vSeeds.push_back(CDNSSeedData("vps.testnet.bitcoinlove.online", "dnsseedtestnet.bitcoinlove.online")); // TheTrunk


        // guarantees the first 2 characters, when base58 encoded, are "b1"
        base58Prefixes[PUBKEY_ADDRESS]     = {0x13,0x25};
        // guarantees the first 2 characters, when base58 encoded, are "b2"
        base58Prefixes[SCRIPT_ADDRESS]     = {0x13,0x27};
        // the first character, when base58 encoded, is "9" or "c" (as in Bitcoin)
        base58Prefixes[SECRET_KEY]         = {0xEF};
        // do not rely on these BIP32 prefixes; they are not specified and may change
        base58Prefixes[EXT_PUBLIC_KEY]     = {0x04,0x35,0x87,0xCF};
        base58Prefixes[EXT_SECRET_KEY]     = {0x04,0x35,0x83,0x94};
        // guarantees the first 2 characters, when base58 encoded, are "zt"
        base58Prefixes[ZCPAYMENT_ADDRRESS] = {0x16,0xB6};
        // guarantees the first 4 characters, when base58 encoded, are "ZiVt"
        base58Prefixes[ZCVIEWING_KEY]      = {0xA8,0xAC,0x0C};
        // guarantees the first 2 characters, when base58 encoded, are "ST"
        base58Prefixes[ZCSPENDING_KEY]     = {0xAC,0x08};

        bech32HRPs[SAPLING_PAYMENT_ADDRESS]      = "ztestacadia";
        bech32HRPs[SAPLING_FULL_VIEWING_KEY]     = "zviewtestacadia";
        bech32HRPs[SAPLING_INCOMING_VIEWING_KEY] = "zivktestacadia";
        bech32HRPs[SAPLING_EXTENDED_SPEND_KEY]   = "secret-extended-key-test";

        vFixedSeeds = std::vector<SeedSpec6>(pnSeed6_test, pnSeed6_test + ARRAYLEN(pnSeed6_test));

        fMiningRequiresPeers = true;
        fDefaultConsistencyChecks = false;
        fRequireStandard = true;
        fMineBlocksOnDemand = false;
        fTestnetToBeDeprecatedFieldRPC = true;
        strSporkKey = "0408c6a3a6cacb673fc38f27c75d79c865e1550441ea8b5295abf21116972379a1b49416da07b7d9b40fb9daf8124f309c608dfc79756a5d3c2a957435642f7f1a";
        nStartZelnodePayments = 1550748576; //Thu, 21 Feb 2019 11:29:36 UTC // Currently not being used.
        networkID = CBaseChainParams::Network::TESTNET;
        strZelnodeTestingDummyAddress= "tmXxZqbmvrxeSFQsXmm4N9CKyME767r47fS";




        checkpointData = (CCheckpointData) {
            boost::assign::map_list_of
            (0, consensus.hashGenesisBlock),
            1587661086,  // * UNIX timestamp of last checkpoint block
            0,           // * total number of transactions between genesis and last checkpoint
                         //   (the tx=... number in the SetBestChain debug.log lines)
            1            // * estimated number of transactions per day after checkpoint 720 newly mined +30 for txs that users are doing
                         //   total number of tx / (checkpoint block height / (24 * 24))
        };

    // Hardcoded fallback value for the Sprout shielded value pool balance
        // for nodes that have not reindexed since the introduction of monitoring
        // in #2795.
        //nSproutValuePoolCheckpointHeight = 440329;
        //nSproutValuePoolCheckpointBalance = 40000029096803;
        //fZIP209Enabled = true;
        //hashSproutValuePoolCheckpointBlock = uint256S("000a95d08ba5dcbabe881fc6471d11807bcca7df5f1795c99f3ec4580db4279b");

    }
};
static CTestNetParams testNetParams;

/**
 * Regression test
 */
class CRegTestParams : public CChainParams {
public:
    CRegTestParams() {
        strNetworkID = "regtest";
        strCurrencyUnits = "REG";
        bip44CoinType = 1;
        consensus.fCoinbaseMustBeProtected = false;
        consensus.nSubsidySlowStartInterval = 0;
        consensus.nSubsidyHalvingInterval = 150;
        consensus.nMajorityEnforceBlockUpgrade = 750;
        consensus.nMajorityRejectBlockOutdated = 950;
        consensus.nMajorityWindow = 1000;
        consensus.powLimit = uint256S("0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f");
        consensus.nDigishieldAveragingWindow = 17;
        assert(maxUint/UintToArith256(consensus.powLimit) >= consensus.nDigishieldAveragingWindow);
        consensus.nDigishieldMaxAdjustDown = 0; // Turn off adjustment down
        consensus.nDigishieldMaxAdjustUp = 0; // Turn off adjustment up

        consensus.nPowTargetSpacing = 2 * 60;
	consensus.nPowAllowMinDifficultyBlocksAfterHeight = 0;

        consensus.vUpgrades[Consensus::BASE].nProtocolVersion = 170002;
        consensus.vUpgrades[Consensus::BASE].nActivationHeight =
            Consensus::NetworkUpgrade::ALWAYS_ACTIVE;
        consensus.vUpgrades[Consensus::UPGRADE_TESTDUMMY].nProtocolVersion = 170002;
        consensus.vUpgrades[Consensus::UPGRADE_TESTDUMMY].nActivationHeight =
            Consensus::NetworkUpgrade::NO_ACTIVATION_HEIGHT;

	consensus.vUpgrades[Consensus::UPGRADE_LWMA].nProtocolVersion = 170002;
	consensus.vUpgrades[Consensus::UPGRADE_LWMA].nActivationHeight =
	    Consensus::NetworkUpgrade::NO_ACTIVATION_HEIGHT;

	consensus.vUpgrades[Consensus::UPGRADE_EQUI144_5].nProtocolVersion = 170002;
	consensus.vUpgrades[Consensus::UPGRADE_EQUI144_5].nActivationHeight =
            Consensus::NetworkUpgrade::NO_ACTIVATION_HEIGHT;

    consensus.vUpgrades[Consensus::UPGRADE_ACADIA].nProtocolVersion = 170006;
    consensus.vUpgrades[Consensus::UPGRADE_ACADIA].nActivationHeight =
            Consensus::NetworkUpgrade::NO_ACTIVATION_HEIGHT;

    consensus.vUpgrades[Consensus::UPGRADE_KAMIOOKA].nProtocolVersion = 170012;
    consensus.vUpgrades[Consensus::UPGRADE_KAMIOOKA].nActivationHeight =
            Consensus::NetworkUpgrade::NO_ACTIVATION_HEIGHT;


        // The best chain should have at least this much work.
        consensus.nMinimumChainWork = uint256S("0x00");

	consensus.nZawyLWMAAveragingWindow = 60;
	consensus.eh_epoch_fade_length = 11;

	eh_epoch_1 = eh48_5;
        eh_epoch_2 = eh48_5;

        pchMessageStart[0] = 0xe3;
        pchMessageStart[1] = 0xab;
        pchMessageStart[2] = 0x4f;
        pchMessageStart[3] = 0x2f;
        nDefaultPort = 26526;
        nPruneAfterHeight = 1000;


        genesis = CreateGenesisBlock(
            1587661394,
            uint256S("0000000000000000000000000000000000000000000000000000000000000014"),
            ParseHex("02eaef5e85b529bfd7073ddad863b26ab9b41b7c703af73402158c402a95ec9544666fcd"),
            0x200f0f0f, 4, 0);

        consensus.hashGenesisBlock = genesis.GetHash();
        printf("%s\n", consensus.hashGenesisBlock.ToString().c_str());
	printf("%s\n", genesis.hashMerkleRoot.ToString().c_str());
        assert(consensus.hashGenesisBlock == uint256S("0x0ad8650bf7d270c47560dbe67d4ecccf7c8803b4274a4a77f4504b5050199202"));
        assert(genesis.hashMerkleRoot == uint256S("0xdcbddb3ae83c9844c050b950d51d1f543086eca5feff6bb50b1aa8a4ced5ce59"));

        vFixedSeeds.clear(); //!< Regtest mode doesn't have any fixed seeds.
        vSeeds.clear();      //!< Regtest mode doesn't have any DNS seeds.

        fMiningRequiresPeers = false;
        fDefaultConsistencyChecks = true;
        fRequireStandard = false;
        fMineBlocksOnDemand = true;
        fTestnetToBeDeprecatedFieldRPC = false;

        networkID = CBaseChainParams::Network::REGTEST;

        checkpointData = (CCheckpointData){
            boost::assign::map_list_of
            ( 0, uint256S("dcbddb3ae83c9844c050b950d51d1f543086eca5feff6bb50b1aa8a4ced5ce59")),
            0,
            0,
            0
        };
        // These prefixes are the same as the testnet prefixes
        base58Prefixes[PUBKEY_ADDRESS]     = {0x13,0x25};
        base58Prefixes[SCRIPT_ADDRESS]     = {0x13,0x27};
        base58Prefixes[SECRET_KEY]         = {0xEF};
        // do not rely on these BIP32 prefixes; they are not specified and may change
        base58Prefixes[EXT_PUBLIC_KEY]     = {0x04,0x35,0x87,0xCF};
        base58Prefixes[EXT_SECRET_KEY]     = {0x04,0x35,0x83,0x94};
        base58Prefixes[ZCPAYMENT_ADDRRESS] = {0x16,0xB6};
        base58Prefixes[ZCVIEWING_KEY]      = {0xA8,0xAC,0x0C};
        base58Prefixes[ZCSPENDING_KEY]     = {0xAC,0x08};

        bech32HRPs[SAPLING_PAYMENT_ADDRESS]      = "zregtestsapling";
        bech32HRPs[SAPLING_FULL_VIEWING_KEY]     = "zviewregtestsapling";
        bech32HRPs[SAPLING_INCOMING_VIEWING_KEY] = "zivkregtestsapling";
        bech32HRPs[SAPLING_EXTENDED_SPEND_KEY]   = "secret-extended-key-regtest";
    }

    void UpdateNetworkUpgradeParameters(Consensus::UpgradeIndex idx, int nActivationHeight)
    {
        assert(idx > Consensus::BASE && idx < Consensus::MAX_NETWORK_UPGRADES);
        consensus.vUpgrades[idx].nActivationHeight = nActivationHeight;
    }

    void SetRegTestZIP209Enabled() {
        fZIP209Enabled = true;
    }
};
static CRegTestParams regTestParams;

static CChainParams *pCurrentParams = 0;

const CChainParams &Params() {
    assert(pCurrentParams);
    return *pCurrentParams;
}

CChainParams &Params(CBaseChainParams::Network network) {
    switch (network) {
        case CBaseChainParams::MAIN:
            return mainParams;
        case CBaseChainParams::TESTNET:
            return testNetParams;
        case CBaseChainParams::REGTEST:
            return regTestParams;
        default:
            assert(false && "Unimplemented network");
            return mainParams;
    }
}

void SelectParams(CBaseChainParams::Network network) {
    SelectBaseParams(network);
    pCurrentParams = &Params(network);

    // Some python qa rpc tests need to enforce the coinbase consensus rule
    if (network == CBaseChainParams::REGTEST && mapArgs.count("-regtestprotectcoinbase")) {
        regTestParams.SetRegTestCoinbaseMustBeProtected();
    }

    // When a developer is debugging turnstile violations in regtest mode, enable ZIP209
    if (network == CBaseChainParams::REGTEST && mapArgs.count("-developersetpoolsizezero")) {
        regTestParams.SetRegTestZIP209Enabled();
    }
}

bool SelectParamsFromCommandLine()
{
    CBaseChainParams::Network network = NetworkIdFromCommandLine();
    if (network == CBaseChainParams::MAX_NETWORK_TYPES)
        return false;

    SelectParams(network);
    return true;
}


// Block height must be >0 and <=last founders reward block height
// Index variable i ranges from 0 - (vFoundersRewardAddress.size()-1)
std::string CChainParams::GetFoundersRewardAddressAtHeight(int nHeight) const {
    int maxHeight = consensus.GetLastFoundersRewardBlockHeight();
    assert(nHeight > 0 && nHeight <= maxHeight);

    size_t addressChangeInterval = (maxHeight + vFoundersRewardAddress.size()) / vFoundersRewardAddress.size();
    size_t i = nHeight / addressChangeInterval;
    return vFoundersRewardAddress[i];
}


// Block height must be >0 and <=last founders reward block height
// The founders reward address is expected to be a multisig (P2SH) address
CScript CChainParams::GetFoundersRewardScriptAtHeight(int nHeight) const {
    assert(nHeight > 0 && nHeight <= consensus.GetLastFoundersRewardBlockHeight());

    CTxDestination address = DecodeDestination(GetFoundersRewardAddressAtHeight(nHeight).c_str());
    assert(IsValidDestination(address));
    assert(boost::get<CScriptID>(&address) != nullptr);
    CScriptID scriptID = boost::get<CScriptID>(address); // address is a boost variant
    CScript script = CScript() << OP_HASH160 << ToByteVector(scriptID) << OP_EQUAL;
    return script;
}
std::string CChainParams::GetFoundersRewardAddressAtIndex(int i) const {
    assert(i >= 0 && i < vFoundersRewardAddress.size());
    return vFoundersRewardAddress[i];
}

void UpdateNetworkUpgradeParameters(Consensus::UpgradeIndex idx, int nActivationHeight)
{
    regTestParams.UpdateNetworkUpgradeParameters(idx, nActivationHeight);
}

int validEHparameterList(EHparameters *ehparams, unsigned long blockheight, const CChainParams& params){
    //if in overlap period, there will be two valid solutions, else 1.
    //The upcoming version of EH is preferred so will always be first element
    //returns number of elements in list

    int current_height = (int)blockheight;
    if (current_height < 0)
        current_height = 0;

    // When checking to see if the activation height is above the fade length, we subtract the fade length from the
    // current height and run it through the NetworkUpgradeActive method
    int modified_height = (int)(current_height - params.GetConsensus().eh_epoch_fade_length);
    if (modified_height < 0)
        modified_height = 0;

    // check to see if the block height is greater then the overlap period ( height - fade depth >= Upgrade Height)
    if (NetworkUpgradeActive(modified_height, Params().GetConsensus(), Consensus::UPGRADE_KAMIOOKA)) {
        ehparams[0]=params.eh_epoch_3_params();
        return 1;
    }

    // check to see if the block height is in the overlap period.
    // The above if statement shows us that we are already below the upgrade height + the fade depth, so now we check
    // to see if we are above just the upgrade height
    if (NetworkUpgradeActive(current_height, Params().GetConsensus(), Consensus::UPGRADE_KAMIOOKA)) {
        ehparams[0]=params.eh_epoch_3_params();
        ehparams[1]=params.eh_epoch_2_params();
        return 2;
    }

    // check to see if the block height is greater then the overlap period (height - fade depth >= Upgrade Height)
    if (NetworkUpgradeActive(modified_height, Params().GetConsensus(), Consensus::UPGRADE_EQUI144_5)) {
        ehparams[0]=params.eh_epoch_2_params();
        return 1;
    }

    // check to see if the block height is in the overlap period
    // The above if statement shows us that we are already below the upgrade height + the fade depth, so now we check
    // to see if we are above just the upgrade height
    if (NetworkUpgradeActive(current_height, Params().GetConsensus(), Consensus::UPGRADE_EQUI144_5)) {
        ehparams[0]=params.eh_epoch_2_params();
        ehparams[1]=params.eh_epoch_1_params();
        return 2;
    }

    // return the block height is less than the upgrade height params
    ehparams[0]=params.eh_epoch_1_params();
    return 1;
}
