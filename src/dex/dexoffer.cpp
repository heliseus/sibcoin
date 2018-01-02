
#include "dexoffer.h"
#include "init.h"
#include "util.h"
#include "utiltime.h"
#include "db/countryiso.h"
#include "db/currencyiso.h"
#include "db/paymentmethodtype.h"
#include "utilstrencodings.h"
#include <univalue.h>


const char * OFFER_TYPE_BUY  =  "buy";
const char * OFFER_TYPE_SELL = "sell";


dex::CurrencyIso  defaultCurrencyIso;
dex::CountryIso  defaultCountryIso;
dex::PaymentMethodType defaultPaymentMethod;



CDexOffer::CDexOffer()
{
    SetNull();
}

CDexOffer::CDexOffer(const CDexOffer &off)
{
    idTransaction    = off.idTransaction;
    hash             = off.hash;
    pubKey           = off.pubKey;
    countryIso       = off.countryIso;
    currencyIso      = off.currencyIso;
    paymentMethod    = off.paymentMethod;
    price            = off.price;
    minAmount        = off.minAmount;
    timeCreate       = off.timeCreate;
    timeExpiration   = off.timeExpiration;
    shortInfo        = off.shortInfo;
    details          = off.details;
    type             = off.type;
}


CDexOffer::CDexOffer(const dex::OfferInfo &info, dex::TypeOffer offertype)
{
    idTransaction    = info.idTransaction;
    hash             = info.hash;
    pubKey           = info.pubKey;
    countryIso       = info.countryIso;
    currencyIso      = info.currencyIso;
    paymentMethod    = info.paymentMethod;
    price            = info.price;
    minAmount        = info.minAmount;
    timeCreate       = info.timeCreate;
    timeExpiration   = info.timeToExpiration;
    shortInfo        = info.shortInfo;
    details          = info.details;
    switch (offertype) {
        case  dex::Buy: type = OFFER_TYPE_BUY;  break;
        case dex::Sell: type = OFFER_TYPE_SELL; break;
    }
}

CDexOffer::CDexOffer(const dex::MyOfferInfo &info)
{
    idTransaction    = info.idTransaction;
    hash             = info.hash;
    pubKey           = info.pubKey;
    countryIso       = info.countryIso;
    currencyIso      = info.currencyIso;
    paymentMethod    = info.paymentMethod;
    price            = info.price;
    minAmount        = info.minAmount;
    timeCreate       = info.timeCreate;
    timeExpiration   = info.timeToExpiration;
    shortInfo        = info.shortInfo;
    details          = info.details;
    switch (info.type) {
        case  dex::Buy: type = OFFER_TYPE_BUY;  break;
        case dex::Sell: type = OFFER_TYPE_SELL; break;
    }
}



void CDexOffer::SetNull()
{
    hash.SetNull();
    idTransaction.SetNull();
    pubKey.clear();
    type.clear();
    countryIso.clear();
    currencyIso.clear();
    paymentMethod = 0;;
    price = 0;
    minAmount = 0;
    timeCreate = 0;
    timeExpiration = 0;
    shortInfo.clear();
    details.clear();
}



bool CDexOffer::Create(Type type_, const std::string &pubKey_, const std::string &countryIso_, const std::string &currencyIso_,
           uint8_t paymentMethod_, uint64_t price_, uint64_t minAmount_, int timeExpiration_,
           const std::string &shortInfo_, const std::string &details_)
{
    uint256 txid;
    return Create(txid, type_, pubKey_, countryIso_, currencyIso_, paymentMethod_, price_, minAmount_, timeExpiration_, shortInfo_, details_);
}



bool CDexOffer::Create(const uint256 &idTransaction_, Type type_, const std::string &pubKey_, const std::string &countryIso_, const std::string &currencyIso_,
           uint8_t paymentMethod_, uint64_t price_, uint64_t minAmount_, int timeExpiration_,
           const std::string &shortInfo_, const std::string &details_)
{
    idTransaction   = idTransaction_;
    pubKey          = pubKey_;
    paymentMethod   = paymentMethod_;
    currencyIso     = currencyIso_;
    countryIso      = countryIso_;
    price           = price_;
    minAmount       = minAmount_;
    timeCreate      = GetTime();
    timeExpiration  = timeExpiration_;
    shortInfo       = shortInfo_;
    details         = details_;
    switch (type_) {
        case  BUY: type = OFFER_TYPE_BUY;  break;
        case SELL: type = OFFER_TYPE_SELL; break;
    }
    if (!Check(false)) {
        SetNull();
        return false;
    }
    hash = MakeHash();
    //LogPrintf("Create DexOffer\n%s\n", dump().c_str()); ///< for debug only
    return true;
}


bool CDexOffer::Create(const dex::OfferInfo &info, dex::TypeOffer offertype)
{
    idTransaction   = info.idTransaction;
    pubKey          = info.pubKey;
    paymentMethod   = info.paymentMethod;
    currencyIso     = info.currencyIso;
    countryIso      = info.countryIso;
    price           = info.price;
    minAmount       = info.minAmount;
    timeCreate      = info.timeCreate;
    timeExpiration  = info.timeToExpiration;
    shortInfo       = info.shortInfo;
    details         = info.details;
    switch (offertype) {
        case  dex::Buy: type = OFFER_TYPE_BUY;  break;
        case dex::Sell: type = OFFER_TYPE_SELL; break;
    }
    if (!Check(false)) {
        SetNull();
        return false;
    }
    hash = MakeHash();
    return true;
}

bool CDexOffer::Create(const dex::MyOfferInfo &info) {
    return Create(info.getOfferInfo(), info.type);
}



uint256 CDexOffer::MakeHash()
{
    return SerializeHash(*this);
}



CDexOffer::operator dex::OfferInfo() const
{
    dex::OfferInfo info;
    info.idTransaction    = idTransaction;
    info.hash             = hash;
    info.pubKey           = pubKey;
    info.countryIso       = countryIso;
    info.currencyIso      = currencyIso;
    info.paymentMethod    = paymentMethod;
    info.price            = price;
    info.minAmount        = minAmount;
    info.timeCreate       = timeCreate;
    info.timeToExpiration = timeExpiration;
    info.shortInfo        = shortInfo;
    info.details          = details;
    return info;
}

CDexOffer& CDexOffer::operator=(const CDexOffer& off)
{
    idTransaction    = off.idTransaction;
    hash             = off.hash;
    pubKey           = off.pubKey;
    countryIso       = off.countryIso;
    currencyIso      = off.currencyIso;
    paymentMethod    = off.paymentMethod;
    price            = off.price;
    minAmount        = off.minAmount;
    timeCreate       = off.timeCreate;
    timeExpiration   = off.timeExpiration;
    shortInfo        = off.shortInfo;
    details          = off.details;
    type             = off.type;
    return *this;
}

std::string CDexOffer::getType() const
{
    return type;
}

dex::TypeOffer CDexOffer::getTypeOffer() const
{
    if (type == OFFER_TYPE_BUY)  {
        return dex::Buy;
    } else {
        return dex::Sell;
    }
}


bool CDexOffer::isBuy() const
{
    return type == OFFER_TYPE_BUY;
}


bool CDexOffer::isSell() const
{
    return type == OFFER_TYPE_SELL;
}



std::string CDexOffer::dump() const
{
    return strprintf("CDexOffer::dump()\n"
        "\ttype\t\t%s\n"
        "\tidTransaction\t%s\n"
        "\thash\t\t%s\n"
        "\tpubKey\t\t%s\n"
        "\tcountryIso\t%s\n"
        "\tcurrencyIso\t%s\n"
        "\tpaymentMethod\t%d\n"
        "\tprice\t\t%lld\n"
        "\tminAmount\t%lld\n"
        "\ttimeCreate\t%lld\n"
        "\ttimeExpiration\t%d\n"
        "\tshortInfo\t%s\n"
        "\tdetails\t\t%s\n",
        type.c_str(), idTransaction.GetHex().c_str(), hash.GetHex().c_str(), pubKey.c_str(),
        countryIso.c_str(), currencyIso.c_str(), paymentMethod, price, minAmount, timeCreate,
        timeExpiration, shortInfo.c_str(), details.c_str());
}


CPubKey CDexOffer::getPubKeyObject() const
{
    std::vector<unsigned char> data(ParseHex(pubKey));
    CPubKey key(data.begin(), data.end());
    return key;
}


bool CDexOffer::Check(bool fullcheck)
{
    do {
        if (fullcheck && idTransaction.IsNull()) {
            LogPrintf("DexOffer::Check error: idTransaction is empty\n");
            break;
        }
        if (fullcheck && hash.IsNull()) {
            LogPrintf("DexOffer::Check(%s) error: hash is empty\n", idTransaction.GetHex().c_str());
            break;
        }
        if (fullcheck && !getPubKeyObject().IsFullyValid()) {
            LogPrintf("DexOffer::Check(%s) error: pubKey is invalid\n", idTransaction.GetHex().c_str());
            break;
        }
        if (fullcheck && hash != MakeHash()) {
            LogPrintf("DexOffer::Check(%s) error: hash not equal\n", idTransaction.GetHex().c_str());
            break;
        }
        if (countryIso.size() != 2) {
            LogPrintf("DexOffer::Check(%s) error: wrong countryIso size\n", idTransaction.GetHex().c_str());
            break;
        }
        if (currencyIso.size() != 3) {
            LogPrintf("DexOffer::Check(%s) error:  wrong currencyIso size\n", idTransaction.GetHex().c_str());
            break;
        }
        if (shortInfo.size() > DEX_SHORT_INFO_LENGTH) {
            LogPrintf("DexOffer::Check(%s) error: shortinfo string too long\n", idTransaction.GetHex().c_str());
            break;
        }
        if (details.size() > DEX_DETAILS_LENGTH) {
            LogPrintf("DexOffer::Check(%s) error: details string too long\n", idTransaction.GetHex().c_str());
            break;
        }
        if (type.empty() || (type != OFFER_TYPE_BUY && type != OFFER_TYPE_SELL)) {
            LogPrintf("DexOffer::Check(%s) error: error type\n", idTransaction.GetHex().c_str());
            break;
        }
        if (!defaultCountryIso.isValid(countryIso)) {
            LogPrintf("DexOffer::Check(%s) error: wrong countryIso code\n", idTransaction.GetHex().c_str());
            break;
        }
        if (!defaultCurrencyIso.isValid(currencyIso)) {
            LogPrintf("DexOffer::Check(%s) error: wrong currencyIso code\n", idTransaction.GetHex().c_str());
            break;
        }
        if (!defaultPaymentMethod.isValid(paymentMethod)) {
            LogPrintf("DexOffer::Check(%s) error: wrong payment method\n", idTransaction.GetHex().c_str());
            break;
        }
        if (timeCreate + (timeExpiration * 86400) < (uint64_t)GetTime()) {
            LogPrintf("DexOffer::Check(%s) error: offer expiration time out\n", idTransaction.GetHex().c_str());
            break;
        }
        return true;
    } while (false);
    SetNull();
    return false;
}


UniValue CDexOffer::getUniValue()
{
    UniValue result(UniValue::VOBJ);
    result.push_back(Pair("type", type));
    result.push_back(Pair("idTransaction", idTransaction.GetHex()));
    result.push_back(Pair("hash", hash.GetHex()));
    result.push_back(Pair("pubKey", pubKey));
    result.push_back(Pair("countryIso", countryIso));
    result.push_back(Pair("currencyIso", currencyIso));
    result.push_back(Pair("paymentMethod", paymentMethod));
    result.push_back(Pair("price", price));
    result.push_back(Pair("minAmount", minAmount));
    result.push_back(Pair("timeCreate", timeCreate));
    result.push_back(Pair("timeExpiration", timeExpiration));
    result.push_back(Pair("shortInfo", shortInfo));
    result.push_back(Pair("details", details));
    return result;
}


