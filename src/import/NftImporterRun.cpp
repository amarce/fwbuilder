/*

                          Firewall Builder

                 Copyright (C) 2024 NetCitadel, LLC

  Author:  OpenAI

  This program is free software which we release under the GNU General Public
  License. You may redistribute and/or modify this program under the terms
  of that license as published by the Free Software Foundation; either
  version 2 of the License, or (at your option) any later version.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  To get a copy of the GNU General Public License, write to the Free Software
  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

*/

#include "NftImporter.h"

#include <QString>
#include <QStringList>
#include <QtDebug>

#include <ios>
#include <sstream>

#include "../parsers/NftCfgLexer.hpp"
#include "../parsers/NftCfgParser.hpp"

extern int fwbdebug;

using namespace std;

void NftImporter::run()
{
    QStringList err;
    QString parser_err = QObject::tr("Parser error:");
    QString gen_err = QObject::tr("Error:");

    input.seekg(0, ios::beg);
    NftCfgLexer lexer(input);
    NftCfgParser parser(lexer);
    parser.importer = this;

    try
    {
        parser.cfgfile();
    } catch(const std::exception &e)
    {
        err << parser_err + " " + e.what();
    }

    if (haveFirewallObject())
    {
        if (countInterfaces() == 0) err << noInterfacesErrorMessage();
        if (countRules() == 0) err << noRulesErrorMessage();
    } else
    {
        err << parser_err;
        err << noFirewallErrorMessage();
        err << commonFailureErrorMessage();
    }

    if (!err.isEmpty())
        *logger << err.join("\n").toUtf8().constData();
}
