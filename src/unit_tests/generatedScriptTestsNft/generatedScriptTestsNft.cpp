/*

                          Firewall Builder

                 Copyright (C) 2024 NetCitadel, LLC

  Author:  Vadim Kurland     vadim@fwbuilder.org

  $Id$

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

#include "generatedScriptTestsNft.h"

#include "CompilerDriver_nft.h"

#include "fwbuilder/Constants.h"
#include "fwbuilder/FWException.h"
#include "fwbuilder/IPService.h"

#include <QFile>
#include <QFileInfo>
#include <QTest>
#include <QStringList>
#include <QtDebug>

using namespace std;
using namespace libfwbuilder;
using namespace fwcompiler;

class UpgradePredicate: public XMLTools::UpgradePredicate
{
    public:
    virtual bool operator()(const string&) const
    {
        cout << "Data file has been created in the old version of Firewall Builder. Use fwbuilder GUI to convert it." << std::endl;
        return false;
    }
};

void GeneratedScriptTestsNft::init()
{
    objdb = nullptr;

    IPService::addNamedProtocol(51, "ah");
    IPService::addNamedProtocol(112, "vrrp");
}

void GeneratedScriptTestsNft::cleanup()
{
}

void GeneratedScriptTestsNft::loadDataFile(const string &file_name)
{
    try
    {
        UpgradePredicate upgrade_predicate;

        objdb->setReadOnly(false);
        objdb->load(file_name, &upgrade_predicate, Constants::getDTDDirectory());
        objdb->setFileName(file_name);
        objdb->reIndex();
    } catch (FWException &ex)
    {
        qDebug() << ex.toString().c_str();
    }
}

void GeneratedScriptTestsNft::runCompiler(const std::string &test_file,
                                          const std::string &firewall_object_name,
                                          const std::string &generate_file_name)
{
    loadDataFile(test_file);

    QStringList args;
    args << firewall_object_name.c_str();

    CompilerDriver_nft driver(objdb);
    driver.setEmbeddedMode();
    QVERIFY2(driver.prepare(args) == true,
             "CompilerDriver_nft initialization failed");
    driver.compile();

    QFileInfo fi(generate_file_name.c_str());
    QVERIFY2(fi.exists() == true,
             std::string("Generated file " + generate_file_name + " not found").data());
}

void GeneratedScriptTestsNft::GeneratedScriptTest()
{
    objdb = new FWObjectDatabase();
    runCompiler("test1.fwb", "nft-test", "nft-test.fw");

    QFile expected_file("expected_output.txt");
    QVERIFY2(expected_file.open(QIODevice::ReadOnly | QIODevice::Text),
             "Unable to open expected_output.txt");
    QStringList expected_lines = QString::fromUtf8(expected_file.readAll())
        .split("\n", Qt::SkipEmptyParts);

    QFile generated_file("nft-test.fw");
    QVERIFY2(generated_file.open(QIODevice::ReadOnly | QIODevice::Text),
             "Unable to open generated nft-test.fw");
    QString generated = QString::fromUtf8(generated_file.readAll());

    int last_index = -1;
    for (const QString &line : expected_lines)
    {
        int index = generated.indexOf(line, last_index + 1);
        QVERIFY2(index != -1,
                 QString("Expected line not found or out of order: %1")
                     .arg(line)
                     .toLatin1()
                     .constData());
        last_index = index;
    }

    delete objdb;
    objdb = nullptr;
}
