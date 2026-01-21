#ifndef INC_NFTCfgParser_hpp_
#define INC_NFTCfgParser_hpp_

#include "NftCfgLexer.hpp"
#include "NftImporter.h"

#include <string>
#include <vector>

class NftCfgParser
{
    NftCfgLexer &lexer;
    size_t pos;

    bool hasTokens() const;
    const std::string& peek() const;
    const std::string& consume();

    void parseTable();
    void parseChain();
    void parseRuleTokens(std::vector<std::string> &rule_tokens);
    void parseSetDefinition(bool is_map);
    void parseDefinitionTokens(std::vector<std::string> &tokens);

public:
    NftImporter *importer;

    explicit NftCfgParser(NftCfgLexer &lex);

    void cfgfile();
};

#endif
