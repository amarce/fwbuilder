#include "NftCfgLexer.hpp"

#include <cctype>

using namespace std;

NftCfgLexer::NftCfgLexer(std::istream &input)
{
    tokenize(input);
}

void NftCfgLexer::tokenize(std::istream &input)
{
    string token;
    bool in_string = false;

    auto flush_token = [&]() {
        if (!token.empty())
        {
            tokens_cache.push_back(token);
            token.clear();
        }
    };

    char ch;
    while (input.get(ch))
    {
        if (!in_string && ch == '#')
        {
            while (input.get(ch) && ch != '\n')
            {
            }
            flush_token();
            continue;
        }

        if (ch == '"')
        {
            in_string = !in_string;
            if (!in_string)
            {
                flush_token();
            }
            continue;
        }

        if (!in_string)
        {
            if (ch == '{' || ch == '}' || ch == ';')
            {
                flush_token();
                string delim(1, ch);
                tokens_cache.push_back(delim);
                continue;
            }
            if (ch == ',' || isspace(static_cast<unsigned char>(ch)))
            {
                flush_token();
                continue;
            }
        }

        token.push_back(ch);
    }

    flush_token();
}
