#include "NftCfgParser.hpp"

#include <stdexcept>

using namespace std;

NftCfgParser::NftCfgParser(NftCfgLexer &lex) : lexer(lex), pos(0)
{
    importer = nullptr;
}

bool NftCfgParser::hasTokens() const
{
    return pos < lexer.tokens().size();
}

const std::string& NftCfgParser::peek() const
{
    return lexer.tokens()[pos];
}

const std::string& NftCfgParser::consume()
{
    return lexer.tokens()[pos++];
}

void NftCfgParser::cfgfile()
{
    while (hasTokens())
    {
        if (peek() == "table")
        {
            parseTable();
            continue;
        }
        consume();
    }
}

void NftCfgParser::parseTable()
{
    consume();
    if (!hasTokens()) return;
    string family = consume();
    if (!hasTokens()) return;
    string name = consume();

    if (importer) importer->setTable(name);

    if (hasTokens() && peek() == "{") consume();

    while (hasTokens() && peek() != "}")
    {
        if (peek() == "chain")
        {
            parseChain();
            continue;
        }
        if (peek() == "set")
        {
            parseSetDefinition(false);
            continue;
        }
        if (peek() == "map")
        {
            parseSetDefinition(true);
            continue;
        }
        consume();
    }

    if (hasTokens() && peek() == "}") consume();

    (void)family;
}

void NftCfgParser::parseChain()
{
    consume();
    if (!hasTokens()) return;
    string name = consume();

    if (importer) importer->startChain(name);

    if (hasTokens() && peek() == "{") consume();

    while (hasTokens() && peek() != "}")
    {
        if (peek() == ";")
        {
            consume();
            continue;
        }

        if (peek() == "type" && pos + 1 < lexer.tokens().size())
        {
            consume();
            string type_name = consume();
            if (importer) importer->setChainType(type_name);
            continue;
        }

        if (peek() == "hook" && pos + 1 < lexer.tokens().size())
        {
            consume();
            string hook_name = consume();
            if (importer) importer->setChainHook(hook_name);
            continue;
        }

        if (peek() == "policy" && pos + 1 < lexer.tokens().size())
        {
            consume();
            string policy = consume();
            if (importer) importer->setChainPolicy(policy);
            continue;
        }

        vector<string> rule_tokens;
        parseRuleTokens(rule_tokens);
    }

    if (hasTokens() && peek() == "}") consume();
}

void NftCfgParser::parseRuleTokens(vector<string> &rule_tokens)
{
    while (hasTokens() && peek() != ";" && peek() != "}")
    {
        rule_tokens.push_back(consume());
    }

    if (hasTokens() && peek() == ";") consume();

    if (rule_tokens.empty()) return;

    if (importer) importer->parseRuleTokens(rule_tokens);
}

void NftCfgParser::parseSetDefinition(bool is_map)
{
    consume();
    if (!hasTokens()) return;
    string name = consume();

    if (importer) importer->startSetDefinition(name, is_map);

    if (hasTokens() && peek() == "{") consume();

    while (hasTokens() && peek() != "}")
    {
        if (peek() == ";")
        {
            consume();
            continue;
        }

        vector<string> tokens;
        parseDefinitionTokens(tokens);
        if (!tokens.empty() && importer) importer->parseSetStatement(tokens);
    }

    if (hasTokens() && peek() == "}") consume();

    if (importer) importer->endSetDefinition();
}

void NftCfgParser::parseDefinitionTokens(vector<string> &tokens)
{
    int depth = 0;
    while (hasTokens())
    {
        if (peek() == ";" && depth == 0)
        {
            consume();
            break;
        }
        if (peek() == "}" && depth == 0)
        {
            break;
        }

        string tok = consume();
        if (tok == "{") depth++;
        else if (tok == "}" && depth > 0) depth--;
        tokens.push_back(tok);
    }
}
