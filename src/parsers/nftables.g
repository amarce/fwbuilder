/*

                          Firewall Builder

                 Copyright (C) 2024 NetCitadel, LLC

  Author:  OpenAI

  This grammar documents the subset of nftables configuration syntax
  supported by the importer. It is intentionally limited to table/chain
  blocks and basic rule statements.

*/

header "pre_include_hpp"
{
#include "NftImporter.h"
}

header "post_include_hpp"
{
class NftImporter;
}

options
{
    language="Cpp";
}

class NftCfgParser extends Parser;
options
{
    k = 2;
}
{
    public:

    NftImporter *importer;
}

cfgfile
    : (table_def)*
    ;

table_def
    : "table" family:IDENT name:IDENT LBRACE chain_def* RBRACE
    ;

chain_def
    : "chain" cname:IDENT LBRACE chain_stmt* RBRACE
    ;

chain_stmt
    : chain_header
    | rule_stmt
    | SEMI
    ;

chain_header
    : "type" ctype:IDENT
    | "hook" hook:IDENT
    | "policy" policy:IDENT
    ;

rule_stmt
    : (IDENT)+ SEMI
    ;

class NftCfgLexer extends Lexer;
options
{
    k = 2;
}

LBRACE: '{';
RBRACE: '}';
SEMI: ';';
IDENT: (~(' ' | '\t' | '\r' | '\n' | '{' | '}' | ';'))+;
WS: (' ' | '\t' | '\r' | '\n') { $setType(antlr::Token::SKIP); };
