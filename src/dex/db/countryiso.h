#ifndef COUNTRYISO_H
#define COUNTRYISO_H

#include <set>
#include <string>

namespace dex {

class CountryIso {
public:
    CountryIso();

    bool isValid(const std::string &iso);

private:
    void initListIso();
    std::set<std::string> setIso;
};

}

#endif
