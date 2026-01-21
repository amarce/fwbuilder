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

#ifndef _FWB_POLICY_IMPORTER_NFT_H_
#define _FWB_POLICY_IMPORTER_NFT_H_

#include "Importer.h"

#include "fwbuilder/NAT.h"
#include "fwbuilder/Policy.h"

#include <QString>

#include <map>
#include <string>
#include <vector>

class NftImporter : public Importer
{
    std::string current_table;
    std::string current_chain;
    std::string current_chain_type;
    std::string current_chain_hook;

    std::string target;

    std::string i_intf;
    std::string o_intf;

    std::string src_port_range_start;
    std::string src_port_range_end;
    std::string dst_port_range_start;
    std::string dst_port_range_end;

    std::string nat_addr;
    std::string nat_nm;
    std::string nat_port_range_start;
    std::string nat_port_range_end;

    struct NftSetDefinition
    {
        std::string name;
        std::string key_type;
        std::string value_type;
        std::vector<std::string> elements;
        std::vector<std::pair<std::string, std::string>> map_elements;
        bool is_map = false;
        bool has_elements = false;
    };

    std::map<std::string, NftSetDefinition> set_definitions;
    std::map<std::string, libfwbuilder::FWObject*> set_objects;
    std::string current_set_name;
    bool current_set_is_map = false;

    std::string src_set_name;
    std::string dst_set_name;
    bool src_set_is_map = false;
    bool dst_set_is_map = false;

    void pushPolicyRule();
    void pushNATRule();

    bool isAddressSetType(const std::string &type_name) const;
    void parseSetTypeStatement(const std::vector<std::string> &tokens);
    void parseSetElementsStatement(const std::vector<std::string> &tokens);
    libfwbuilder::FWObject* ensureSetObject(const std::string &name, bool is_map);
    void populateSetElements(libfwbuilder::FWObject *obj,
                             const NftSetDefinition &definition);

    void parseAddress(const std::string &value,
                      std::string &address,
                      std::string &netmask) const;

    void parsePortRange(const std::string &value,
                        std::string &range_start,
                        std::string &range_end) const;

    bool isNatTarget() const;

    libfwbuilder::FWObject* makeSrcObj() override;
    libfwbuilder::FWObject* makeDstObj() override;

public:
    NftImporter(libfwbuilder::FWObject *lib,
                std::istringstream &input,
                libfwbuilder::Logger *log,
                const std::string &fwname);
    ~NftImporter();

    void run() override;
    void clear() override;

    void setTable(const std::string &table_name);
    void startChain(const std::string &chain_name);
    void setChainType(const std::string &chain_type);
    void setChainHook(const std::string &hook_name);
    void setChainPolicy(const std::string &policy);

    void startSetDefinition(const std::string &name, bool is_map);
    void parseSetStatement(const std::vector<std::string> &tokens);
    void endSetDefinition();

    void setInterfaceIn(const std::string &name);
    void setInterfaceOut(const std::string &name);

    void setProtocol(const std::string &proto);
    void setSourceAddress(const std::string &addr);
    void setDestinationAddress(const std::string &addr);
    void setSourcePortRange(const std::string &range);
    void setDestinationPortRange(const std::string &range);
    void setSourceSet(const std::string &name, bool is_map);
    void setDestinationSet(const std::string &name, bool is_map);

    void setTarget(const std::string &action);
    void setNatTo(const std::string &addr);

    void parseRuleTokens(const std::vector<std::string> &tokens);

    void pushRule() override;

    libfwbuilder::FWObject* createTCPService(const QString &name="") override;
    libfwbuilder::FWObject* createUDPService(const QString &name="") override;
};

#endif
