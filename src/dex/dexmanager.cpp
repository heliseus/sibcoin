
#include "dexmanager.h"

#include "init.h"
#include "util.h"
#include "utilstrencodings.h"
#include "masternode-sync.h"

#include "dex/dexdb.h"
#include "txmempool.h"
#include "base58.h"



#define PAYOFFER_RETURN_FEE     10000
#define PAYOFFER_TX_FEE         50000000
#define PAYOFFER_MIN_TX_HEIGHT  6


CDexManager dexman;


CDexManager::CDexManager()
{
    db = nullptr;
    uncOffers = new UnconfirmedOffers();
}

CDexManager::~CDexManager()
{
}



void CDexManager::ProcessMessage(CNode* pfrom, const std::string& strCommand, CDataStream& vRecv)
{
    if (db == nullptr) {
        if (DexDB::self() == 0) {
            db = new DexDB(strDexDbFile);
        } else {
            db = DexDB::self();
        }
    }

    if (strCommand == NetMsgType::DEXSYNCGETALLHASH) {
        sendHashOffers(pfrom);
    } else if (strCommand == NetMsgType::DEXSYNCALLHASH) {
        getHashsAndSendRequestForGetOffers(pfrom, vRecv);
    } else if (strCommand == NetMsgType::DEXSYNCGETOFFER) {
        sendOffer(pfrom, vRecv);
    } else if (strCommand == NetMsgType::DEXSYNCOFFER) {
        getOfferAndSaveInDb(vRecv);
    } else if (strCommand == NetMsgType::DEXOFFBCST) {
        getAndSendNewOffer(pfrom, vRecv);
    } else if (strCommand == NetMsgType::DEXOFFEDIT) {
        getAndSendEditedOffer(vRecv);
    } else if (strCommand == NetMsgType::DEXDELOFFER) {
        getAndDelOffer(pfrom, vRecv);
    }
}

void CDexManager::sendNewOffer(const CDexOffer &offer)
{
    LOCK2(cs_main, cs_vNodes);

    for (CNode *pNode : vNodes) {
        pNode->PushMessage(NetMsgType::DEXOFFBCST, offer);
    }
}

void CDexManager::sendEditedOffer(const CDexOffer &offer)
{
    LOCK2(cs_main, cs_vNodes);

    for (CNode *pNode : vNodes) {
        pNode->PushMessage(NetMsgType::DEXOFFEDIT, offer);
    }
}

void CDexManager::checkUncOffers()
{
    auto list = uncOffers->getOffers();

    for (auto offer : list) {
        CDex dex(offer);
        std::string error;
        if (dex.CheckOfferTx(error)) {
            if (offer.isBuy())  {
                if (!db->isExistOfferBuy(offer.idTransaction)) {
                    db->addOfferBuy(offer);
                }
            }

            if (offer.isSell())  {
                if (!db->isExistOfferSell(offer.idTransaction)) {
                    db->addOfferSell(offer);
                }
            }

            uncOffers->deleteOffer(offer.hash);
        }
    }
}

void CDexManager::setStatusExpiredForMyOffers()
{
    auto offers = db->getMyOffers();

    long long int currentTime = static_cast<long long int>(time(NULL));

    for (auto item : offers) {
        long long int finish = item.timeCreate + item.timeToExpiration * 86400;

        if (finish < currentTime) {
            item.status = dex::Expired;
            db->editMyOffer(item);
        }
    }
}

void CDexManager::deleteOldUncOffers()
{
    uncOffers->deleteOldOffers();
}

void CDexManager::deleteOldOffers()
{
    db->deleteOldOffersBuy();
    db->deleteOldOffersSell();
}

void CDexManager::sendHashOffers(CNode *pfrom) const
{
    auto hvs = availableOfferHashAndVersion();

    if (hvs.size() > 0) {
        LogPrintf("DEXSYNCGETALLHASH -- send list pairs hashe and version\n");
        pfrom->PushMessage(NetMsgType::DEXSYNCALLHASH, hvs);
    }
}

void CDexManager::getHashsAndSendRequestForGetOffers(CNode *pfrom, CDataStream &vRecv) const
{
    LogPrintf("DEXSYNCALLHASH -- get list hashes\n");

    std::list<std::pair<uint256, int>>  nodeHvs;
    vRecv >> nodeHvs;
    auto hvs = availableOfferHashAndVersion();

    for (auto h : nodeHvs) {
        auto found = std::find_if(hvs.begin(), hvs.end(), [h](std::pair<uint256, int> item){ return item.first == h.first; });

        auto isSend = false;

        if (found != hvs.end()) {
            if (h.second > found->second) {
                isSend = true;
            }
        } else {
            isSend = true;
        }

        if (isSend) {
            LogPrintf("DEXSYNCALLHASH -- send a request for get offer info with hash = %s\n", h.first.GetHex().c_str());
            pfrom->PushMessage(NetMsgType::DEXSYNCGETOFFER, h);
        }
    }
}

void CDexManager::sendOffer(CNode *pfrom, CDataStream &vRecv) const
{
    uint256 hash;
    vRecv >> hash;

    auto offer = getOfferInfo(hash);

    if (offer.Check(true)) {
        LogPrintf("DEXSYNCGETOFFER -- send offer info with hash = %s\n", hash.GetHex().c_str());
        pfrom->PushMessage(NetMsgType::DEXSYNCOFFER, offer);
    }
}

void CDexManager::getOfferAndSaveInDb(CDataStream &vRecv)
{
    CDexOffer offer;
    vRecv >> offer;

    LogPrintf("DEXSYNCOFFER -- get offer info with hash = %s\n", offer.hash.GetHex().c_str());

    if (offer.Check(true)) {
        CDex dex(offer);
        std::string error;
        if (dex.CheckOfferTx(error)) {
            if (offer.isBuy())  {
                if (db->isExistOfferBuy(offer.idTransaction)) {
                    OfferInfo existOffer = db->getOfferBuy(offer.idTransaction);
                    if (offer.editingVersion > existOffer.editingVersion) {
                        db->editOfferBuy(offer);
                    }
                } else {
                    db->addOfferBuy(offer);
                }
            } else if (offer.isSell())  {
                if (db->isExistOfferSell(offer.idTransaction)) {
                    OfferInfo existOffer = db->getOfferSell(offer.idTransaction);
                    if (offer.editingVersion > existOffer.editingVersion) {
                        db->editOfferSell(offer);
                    }
                } else {
                    db->addOfferSell(offer);
                }
            }
        } else {
            uncOffers->setOffer(offer);
        }
    }
}

void CDexManager::getAndSendNewOffer(CNode *pfrom, CDataStream &vRecv)
{
    CDexOffer offer;
    vRecv >> offer;
    if (offer.Check(true)) {
        CDex dex(offer);
        std::string error;
        if (dex.CheckOfferTx(error)) {
            bool bFound = false;
            if (offer.isBuy())  {
                if (db->isExistOfferBuy(offer.idTransaction)) {
                  bFound = true;
                } else {
                    db->addOfferBuy(offer);
                }
            }

            if (offer.isSell())  {
                if (db->isExistOfferSell(offer.idTransaction)) {
                  bFound = true;
                } else {
                    db->addOfferSell(offer);
                }
            }

            if (!bFound) { // need to save and relay
                LOCK2(cs_main, cs_vNodes);
                BOOST_FOREACH(CNode* pNode, vNodes) {
                    pNode->PushMessage(NetMsgType::DEXOFFBCST, offer);
                }
            }
            LogPrintf("DEXOFFBCST --\n%s\nfound %d\n", offer.dump().c_str(), bFound); // NODE: edit message
        } else {
            uncOffers->setOffer(offer);

            LOCK2(cs_main, cs_vNodes);
            BOOST_FOREACH(CNode* pNode, vNodes) {
                pNode->PushMessage(NetMsgType::DEXOFFBCST, offer);
            }

            LogPrintf("DEXOFFBCST --check offer tx fail(%s)\n", offer.idTransaction.GetHex().c_str()); // NODE: edit message
        }
    } else {
        LogPrintf("DEXOFFBCST -- offer check fail\n");
    }
}


void CDexManager::getAndDelOffer(CNode *pfrom, CDataStream &vRecv)
{
    std::vector<unsigned char> vchSign;
    CDexOffer offer;
    vRecv >> offer;
    vRecv >> vchSign;

    if (offer.Check(true)) {
        CDex dex(offer);
        std::string error;
        if (dex.CheckOfferSign(vchSign, error)) {
            bool bFound = false;
            if (offer.isBuy())  {
                if (db->isExistOfferBuy(offer.idTransaction)) {
                    db->deleteOfferBuy(offer.idTransaction);
                    bFound = true;
                }
            }

            if (offer.isSell())  {
                if (db->isExistOfferSell(offer.idTransaction)) {
                    db->deleteOfferSell(offer.idTransaction);
                    bFound = true;
                }
            }
            if (!bFound) {
                if (uncOffers->isExistOffer(offer.hash)) {
                    bFound = true;
                    uncOffers->deleteOffer(offer.hash);
                }

            }

            if (bFound) { // need to delete and relay
                LOCK2(cs_main, cs_vNodes);
                BOOST_FOREACH(CNode* pNode, vNodes) {
                    pNode->PushMessage(NetMsgType::DEXDELOFFER, offer, vchSign);
                }
            }
            LogPrintf("DEXDELOFFER --\n%s\nfound %d\n", offer.dump().c_str(), bFound);
        } else {
            LogPrintf("DEXDELOFFER --check offer sign fail(%s)\n", offer.hash.GetHex().c_str());
        }
    } else {
        LogPrintf("DEXDELOFFER -- offer check fail\n");
    }
}

void CDexManager::getAndSendEditedOffer(CDataStream& vRecv)
{
    CDexOffer offer;
    vRecv >> offer;
    if (offer.Check(true)) {
        CDex dex(offer);
        std::string error;
        if (dex.CheckOfferTx(error)) {
            bool isActual = false;
            if (offer.isBuy()) {
                if (db->isExistOfferBuy(offer.idTransaction)) {
                    OfferInfo existOffer = db->getOfferBuy(offer.idTransaction);
                    if (offer.editingVersion > existOffer.editingVersion) {
                        db->editOfferBuy(offer);
                        isActual = true;
                    }
                } else {
                    db->addOfferBuy(offer);
                    isActual = true;
                }
            }

            if (offer.isSell()) {
                if (db->isExistOfferSell(offer.idTransaction)) {
                    OfferInfo existOffer = db->getOfferSell(offer.idTransaction);
                    if (offer.editingVersion > existOffer.editingVersion) {
                        db->editOfferSell(offer);
                        isActual = true;
                    }
                } else {
                    db->addOfferSell(offer);
                    isActual = true;
                }
            }

            if (isActual) {
                LOCK2(cs_main, cs_vNodes);
                for (CNode* pNode : vNodes) {
                    pNode->PushMessage(NetMsgType::DEXOFFEDIT, offer);
                }
            }

            LogPrintf("DEXOFFEDIT --\n%s\nactual %d\n", offer.dump().c_str(), isActual);
        } else {
            LogPrintf("DEXOFFEDIT --check offer tx fail(%s)\n", offer.idTransaction.GetHex().c_str());
        }
    } else {
        LogPrintf("DEXOFFEDIT -- offer check fail\n");
    }
}

std::list<std::pair<uint256, int>> CDexManager::availableOfferHashAndVersion() const
{
    std::list<std::pair<uint256, int>> list;

    for (auto offer : db->getOffersSell()) {
        list.push_back(std::make_pair(offer.hash, offer.editingVersion));
    }

    for (auto offer : db->getOffersBuy()) {
        list.push_back(std::make_pair(offer.hash, offer.editingVersion));
    }

    for (auto offer : uncOffers->getOffers()) {
        list.push_back(std::make_pair(offer.hash, offer.editingVersion));
    }

    return list;
}

CDexOffer CDexManager::getOfferInfo(const uint256 &hash) const
{
    if (db->isExistOfferSellByHash(hash)) {
        return CDexOffer(db->getOfferSellByHash(hash), Sell);
    }

    if (db->isExistOfferBuyByHash(hash)) {
        return CDexOffer(db->getOfferBuyByHash(hash), Buy);
    }

    if (uncOffers->isExistOffer(hash)) {
        return uncOffers->getOffer(hash);
    }

    return CDexOffer();
}




void ThreadDexManager()
{
    while (true) {
        MilliSleep(1000);

        if (masternodeSync.IsSynced()) {
            std::vector<CNode*> vNodesCopy = CopyNodeVector();

            for (auto node : vNodesCopy) {
                if(node->fMasternode || (fMasterNode && node->fInbound)) {
                    continue;
                }

                node->PushMessage(NetMsgType::DEXSYNCGETALLHASH);
            }

            break;
        }
    }

    int step = 0;
    while (true) {
        MilliSleep(1000);

        if (step % 60 == 0) {
            dexman.checkUncOffers();
        }

        if (step % 1800 == 0) {
            dexman.deleteOldUncOffers();
        }

        if (step % 3600 == 0) {
            dexman.deleteOldOffers();
            dexman.setStatusExpiredForMyOffers();
        }

        if (step == 3600) {
            step = 0;
        } else {
            step++;
        }
    }
}
