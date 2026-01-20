#ifndef INC_NFTCfgLexer_hpp_
#define INC_NFTCfgLexer_hpp_

#include <istream>
#include <string>
#include <vector>

class NftCfgLexer
{
    std::vector<std::string> tokens_cache;

    void tokenize(std::istream &input);

public:
    explicit NftCfgLexer(std::istream &input);

    const std::vector<std::string>& tokens() const { return tokens_cache; }
};

#endif
