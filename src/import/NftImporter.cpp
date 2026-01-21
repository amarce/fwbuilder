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

#include "fwbuilder/Address.h"
#include "fwbuilder/AddressRange.h"
#include "fwbuilder/AddressTable.h"
#include "fwbuilder/FWObjectDatabase.h"
#include "fwbuilder/InetAddr.h"
#include "fwbuilder/Library.h"
#include "fwbuilder/TCPService.h"
#include "fwbuilder/UDPService.h"

#include <QObject>
#include <QString>
#include <QStringList>
#include <QtDebug>

#include <algorithm>
#include <cstdlib>
#include <sstream>

extern int fwbdebug;

using namespace std;
using namespace libfwbuilder;

NftImporter::NftImporter(FWObject *lib,
                         std::istringstream &input,
                         Logger *log,
                         const std::string &fwname) : Importer(lib, "nftables", input, log, fwname)
{
    current_table = "";
    current_chain = "";
    current_chain_type = "";
    current_chain_hook = "";
    target = "";
    clear();
}

NftImporter::~NftImporter()
{
    clear();
}

void NftImporter::clear()
{
    Importer::clear();

    target = "";
    i_intf = "";
    o_intf = "";

    src_port_range_start = "";
    src_port_range_end = "";
    dst_port_range_start = "";
    dst_port_range_end = "";

    nat_addr = "";
    nat_nm = "";
    nat_port_range_start = "";
    nat_port_range_end = "";

    src_set_name = "";
    dst_set_name = "";
    src_set_is_map = false;
    dst_set_is_map = false;
}

void NftImporter::setTable(const std::string &table_name)
{
    current_table = table_name;
}

void NftImporter::startChain(const std::string &chain_name)
{
    current_chain = chain_name;
    current_chain_type = "";
    current_chain_hook = "";
}

void NftImporter::setChainType(const std::string &chain_type)
{
    current_chain_type = chain_type;
}

void NftImporter::setChainHook(const std::string &hook_name)
{
    current_chain_hook = hook_name;
}

void NftImporter::setChainPolicy(const std::string &policy)
{
    if (current_chain.empty()) return;

    UnidirectionalRuleSet *rs = getUnidirRuleSet(current_chain, Policy::TYPENAME);
    current_ruleset = rs;

    if (policy == "accept")
        setDefaultAction("ACCEPT");
    else if (policy == "drop")
        setDefaultAction("DROP");
    else if (policy == "reject")
        setDefaultAction("REJECT");
}

void NftImporter::startSetDefinition(const std::string &name, bool is_map)
{
    current_set_name = name;
    current_set_is_map = is_map;

    if (set_definitions.count(name) != 0)
    {
        addMessageToLog(
            QString("Warning: nft %1 '%2' redefined; last definition wins.")
                .arg(is_map ? "map" : "set")
                .arg(QString::fromUtf8(name.c_str())));
    }

    NftSetDefinition def;
    def.name = name;
    def.is_map = is_map;
    set_definitions[name] = def;
}

void NftImporter::parseSetStatement(const std::vector<std::string> &tokens)
{
    if (current_set_name.empty() || tokens.empty()) return;

    if (tokens[0] == "type")
    {
        parseSetTypeStatement(tokens);
        return;
    }

    if (tokens[0] == "elements")
    {
        parseSetElementsStatement(tokens);
        return;
    }
}

void NftImporter::endSetDefinition()
{
    if (current_set_name.empty()) return;

    auto it = set_definitions.find(current_set_name);
    if (it == set_definitions.end()) return;

    FWObject *obj = ensureSetObject(current_set_name, current_set_is_map);
    if (obj)
    {
        populateSetElements(obj, it->second);
    }

    current_set_name = "";
    current_set_is_map = false;
}

void NftImporter::setInterfaceIn(const std::string &name)
{
    i_intf = name;
}

void NftImporter::setInterfaceOut(const std::string &name)
{
    o_intf = name;
}

void NftImporter::setProtocol(const std::string &proto)
{
    protocol = proto;
}

void NftImporter::parseAddress(const std::string &value,
                               std::string &address,
                               std::string &netmask) const
{
    string::size_type slash = value.find('/');
    string addr = value;
    string mask;

    if (slash != string::npos)
    {
        addr = value.substr(0, slash);
        string prefix = value.substr(slash + 1);
        if (!prefix.empty())
        {
            int af = (addr.find(':') == string::npos) ? AF_INET : AF_INET6;
            int bits = atoi(prefix.c_str());
            if (bits >= 0)
            {
                InetAddr nm(af, bits);
                mask = nm.toString();
            }
        }
    }

    address = addr;
    netmask = mask;
}

void NftImporter::setSourceAddress(const std::string &addr)
{
    parseAddress(addr, src_a, src_nm);
}

void NftImporter::setDestinationAddress(const std::string &addr)
{
    parseAddress(addr, dst_a, dst_nm);
}

void NftImporter::setSourceSet(const std::string &name, bool is_map)
{
    src_set_name = name;
    src_set_is_map = is_map;
    src_a = "";
    src_nm = "";
    ensureSetObject(name, is_map);
}

void NftImporter::setDestinationSet(const std::string &name, bool is_map)
{
    dst_set_name = name;
    dst_set_is_map = is_map;
    dst_a = "";
    dst_nm = "";
    ensureSetObject(name, is_map);
}

void NftImporter::parsePortRange(const std::string &value,
                                 std::string &range_start,
                                 std::string &range_end) const
{
    string::size_type pos = value.find('-');
    if (pos == string::npos)
        pos = value.find(':');

    if (pos == string::npos)
    {
        range_start = value;
        range_end = value;
        return;
    }

    range_start = value.substr(0, pos);
    range_end = value.substr(pos + 1);
}

void NftImporter::setSourcePortRange(const std::string &range)
{
    parsePortRange(range, src_port_range_start, src_port_range_end);
}

void NftImporter::setDestinationPortRange(const std::string &range)
{
    parsePortRange(range, dst_port_range_start, dst_port_range_end);
}

void NftImporter::setTarget(const std::string &action)
{
    target = action;
}

void NftImporter::setNatTo(const std::string &addr)
{
    string::size_type pos = addr.find(':');
    if (pos != string::npos && addr.find('.') != string::npos)
    {
        string host = addr.substr(0, pos);
        string port = addr.substr(pos + 1);
        parseAddress(host, nat_addr, nat_nm);
        parsePortRange(port, nat_port_range_start, nat_port_range_end);
        return;
    }

    parseAddress(addr, nat_addr, nat_nm);
}

bool NftImporter::isNatTarget() const
{
    return (target == "DNAT" || target == "SNAT" || target == "MASQUERADE");
}

void NftImporter::parseRuleTokens(const vector<string> &tokens)
{
    clear();

    for (size_t i = 0; i < tokens.size(); ++i)
    {
        const string &tok = tokens[i];

        if (tok == "counter") continue;

        if ((tok == "ip" || tok == "ip6") && i + 2 < tokens.size())
        {
            const string &next = tokens[i + 1];
            if (next == "saddr")
            {
                if (i + 3 < tokens.size() &&
                    (tokens[i + 2] == "map" || tokens[i + 2] == "vmap") &&
                    !tokens[i + 3].empty() && tokens[i + 3][0] == '@')
                {
                    setSourceSet(tokens[i + 3].substr(1), true);
                    i += 3;
                } else if (!tokens[i + 2].empty() && tokens[i + 2][0] == '@')
                {
                    setSourceSet(tokens[i + 2].substr(1), false);
                    i += 2;
                } else
                {
                    setSourceAddress(tokens[i + 2]);
                    i += 2;
                }
                continue;
            }
            if (next == "daddr")
            {
                if (i + 3 < tokens.size() &&
                    (tokens[i + 2] == "map" || tokens[i + 2] == "vmap") &&
                    !tokens[i + 3].empty() && tokens[i + 3][0] == '@')
                {
                    setDestinationSet(tokens[i + 3].substr(1), true);
                    i += 3;
                } else if (!tokens[i + 2].empty() && tokens[i + 2][0] == '@')
                {
                    setDestinationSet(tokens[i + 2].substr(1), false);
                    i += 2;
                } else
                {
                    setDestinationAddress(tokens[i + 2]);
                    i += 2;
                }
                continue;
            }
            if (next == "protocol")
            {
                setProtocol(tokens[i + 2]);
                i += 2;
                continue;
            }
        }

        if (tok == "saddr" && i + 1 < tokens.size())
        {
            if (i + 2 < tokens.size() &&
                (tokens[i + 1] == "map" || tokens[i + 1] == "vmap") &&
                !tokens[i + 2].empty() && tokens[i + 2][0] == '@')
            {
                setSourceSet(tokens[i + 2].substr(1), true);
                i += 2;
            } else if (!tokens[i + 1].empty() && tokens[i + 1][0] == '@')
            {
                setSourceSet(tokens[i + 1].substr(1), false);
                i += 1;
            } else
            {
                setSourceAddress(tokens[i + 1]);
                i += 1;
            }
            continue;
        }
        if (tok == "daddr" && i + 1 < tokens.size())
        {
            if (i + 2 < tokens.size() &&
                (tokens[i + 1] == "map" || tokens[i + 1] == "vmap") &&
                !tokens[i + 2].empty() && tokens[i + 2][0] == '@')
            {
                setDestinationSet(tokens[i + 2].substr(1), true);
                i += 2;
            } else if (!tokens[i + 1].empty() && tokens[i + 1][0] == '@')
            {
                setDestinationSet(tokens[i + 1].substr(1), false);
                i += 1;
            } else
            {
                setDestinationAddress(tokens[i + 1]);
                i += 1;
            }
            continue;
        }

        if (tok == "meta" && i + 2 < tokens.size())
        {
            if (tokens[i + 1] == "l4proto")
            {
                setProtocol(tokens[i + 2]);
                i += 2;
                continue;
            }
        }

        if (tok == "tcp" || tok == "udp")
        {
            setProtocol(tok);
            if (i + 2 < tokens.size())
            {
                if (tokens[i + 1] == "dport")
                {
                    setDestinationPortRange(tokens[i + 2]);
                    i += 2;
                    continue;
                }
                if (tokens[i + 1] == "sport")
                {
                    setSourcePortRange(tokens[i + 2]);
                    i += 2;
                    continue;
                }
            }
            continue;
        }

        if (tok == "icmp" || tok == "icmpv6")
        {
            setProtocol("icmp");
            continue;
        }

        if ((tok == "iif" || tok == "iifname") && i + 1 < tokens.size())
        {
            setInterfaceIn(tokens[i + 1]);
            i += 1;
            continue;
        }

        if ((tok == "oif" || tok == "oifname") && i + 1 < tokens.size())
        {
            setInterfaceOut(tokens[i + 1]);
            i += 1;
            continue;
        }

        if (tok == "log")
        {
            logging = true;
            continue;
        }

        if (tok == "accept")
        {
            setTarget("ACCEPT");
            continue;
        }

        if (tok == "drop")
        {
            setTarget("DROP");
            continue;
        }

        if (tok == "reject")
        {
            setTarget("REJECT");
            continue;
        }

        if (tok == "masquerade")
        {
            setTarget("MASQUERADE");
            continue;
        }

        if ((tok == "dnat" || tok == "snat") && i + 1 < tokens.size())
        {
            setTarget((tok == "dnat") ? "DNAT" : "SNAT");
            if (i + 2 < tokens.size() && tokens[i + 1] == "to")
            {
                setNatTo(tokens[i + 2]);
                i += 2;
            }
            continue;
        }

        if (tok == "return")
        {
            setTarget("RETURN");
            continue;
        }
    }

    pushRule();
}

void NftImporter::pushRule()
{
    if (target.empty()) return;

    bool is_nat = isNatTarget();
    if (current_chain_type == "nat" || current_table == "nat") is_nat = true;

    if (is_nat)
    {
        newNATRule();
        pushNATRule();
    } else
    {
        newPolicyRule();
        pushPolicyRule();
    }
}

FWObject* NftImporter::makeSrcObj()
{
    if (!src_set_name.empty())
    {
        FWObject *obj = ensureSetObject(src_set_name, src_set_is_map);
        if (obj && isObjectBroken(obj))
            error_tracker->registerError(getBrokenObjectError(obj));
        return obj;
    }
    return Importer::makeSrcObj();
}

FWObject* NftImporter::makeDstObj()
{
    if (!dst_set_name.empty())
    {
        FWObject *obj = ensureSetObject(dst_set_name, dst_set_is_map);
        if (obj && isObjectBroken(obj))
            error_tracker->registerError(getBrokenObjectError(obj));
        return obj;
    }
    return Importer::makeDstObj();
}

void NftImporter::pushPolicyRule()
{
    PolicyRule *rule = PolicyRule::cast(current_rule);
    FWOptions  *ropt = current_rule->getOptionsObject();
    assert(ropt != nullptr);

    PolicyRule::Action action = PolicyRule::Unknown;

    if (target == "ACCEPT") action = PolicyRule::Accept;
    if (target == "DROP") action = PolicyRule::Deny;
    if (target == "REJECT") action = PolicyRule::Reject;
    if (target == "RETURN") action = PolicyRule::Continue;

    rule->setAction(action);
    rule->setLogging(logging);

    addSrc();
    addDst();
    addSrv();

    UnidirectionalRuleSet *rs = getUnidirRuleSet(current_chain, Policy::TYPENAME);
    RuleSet *ruleset = rs->ruleset;
    ruleset->add(current_rule);
    ruleset->renumberRules();

    if (error_tracker->hasWarnings())
    {
        QStringList warn = error_tracker->getWarnings();
        foreach(QString w, warn)
        {
            if (!w.startsWith("Parser warning:")) addMessageToLog("Warning: " + w);
        }
        markCurrentRuleBad();
    }

    if (error_tracker->hasErrors())
    {
        QStringList err = error_tracker->getErrors();
        foreach(QString e, err)
        {
            if (!e.startsWith("Parser error:")) addMessageToLog("Error: " + e);
        }
        markCurrentRuleBad();
    }

    if (!i_intf.empty() && !o_intf.empty())
    {
        rule->setDirection(PolicyRule::Both);
        newInterface(i_intf);
        newInterface(o_intf);
        RuleElementItf *re = rule->getItf();
        re->addRef(all_interfaces[i_intf]);
        re->addRef(all_interfaces[o_intf]);

        rule_comment += QString(
            " Both inbound and outbound interfaces specified: iif %1 oif %2")
            .arg(i_intf.c_str())
            .arg(o_intf.c_str())
            .toStdString();
    } else if (!i_intf.empty())
    {
        rule->setDirection(PolicyRule::Inbound);
        newInterface(i_intf);
        RuleElementItf *re = rule->getItf();
        re->addRef(all_interfaces[i_intf]);
    } else if (!o_intf.empty())
    {
        rule->setDirection(PolicyRule::Outbound);
        newInterface(o_intf);
        RuleElementItf *re = rule->getItf();
        re->addRef(all_interfaces[o_intf]);
    } else
    {
        rule->setDirection(PolicyRule::Both);
    }

    addStandardImportComment(
        current_rule, QString::fromUtf8(rule_comment.c_str()));

    current_rule = nullptr;
    rule_comment = "";

    clear();
}

void NftImporter::pushNATRule()
{
    NATRule *rule = NATRule::cast(current_rule);

    addOSrc();
    addODst();
    addOSrv();

    NATRule::NATRuleTypes rule_type = NATRule::Unknown;
    auto make_translated_service = [&]() -> FWObject* {
        if (nat_port_range_start.empty()) return nullptr;
        ObjectSignature psig(error_tracker);
        if (protocol == "udp")
            psig.type_name = UDPService::TYPENAME;
        else
            psig.type_name = TCPService::TYPENAME;
        psig.setSrcPortRange("0", "0", protocol.empty() ? "tcp" : protocol.c_str());
        psig.setDstPortRange(nat_port_range_start.c_str(),
                             nat_port_range_end.c_str(),
                             protocol.empty() ? "tcp" : protocol.c_str());
        return commitObject(service_maker->createObject(psig));
    };

    if (target == "ACCEPT")
    {
        rule_type = NATRule::NONAT;
    }

    if (target == "MASQUERADE")
    {
        rule_type = NATRule::Masq;
        RuleElementTSrc *re = rule->getTSrc();
        if (!o_intf.empty())
        {
            newInterface(o_intf);
            re->addRef(all_interfaces[o_intf]);
        } else
        {
            re->addRef(getFirewallObject());
        }
    }

    if (target == "SNAT")
    {
        rule_type = NATRule::SNAT;
        FWObject *tsrc = nullptr;

        ObjectSignature sig(error_tracker);
        sig.type_name = Address::TYPENAME;
        sig.setAddress(nat_addr.c_str());
        if (!nat_nm.empty()) sig.setNetmask(nat_nm.c_str());
        tsrc = commitObject(address_maker->createObject(sig));

        RuleElementTSrc *re = rule->getTSrc();
        re->addRef(tsrc);

        if (!nat_port_range_start.empty())
        {
            FWObject *s = make_translated_service();
            RuleElementTSrv *srv = rule->getTSrv();
            if (s) srv->addRef(s);
        }

        if (!o_intf.empty())
        {
            RuleElement *itf_o = rule->getItfOutb();
            newInterface(o_intf);
            itf_o->addRef(all_interfaces[o_intf]);
        }
    }

    if (target == "DNAT")
    {
        rule_type = NATRule::DNAT;
        FWObject *tdst = nullptr;

        ObjectSignature sig(error_tracker);
        sig.type_name = Address::TYPENAME;
        sig.setAddress(nat_addr.c_str());
        if (!nat_nm.empty()) sig.setNetmask(nat_nm.c_str());
        tdst = commitObject(address_maker->createObject(sig));

        RuleElementTDst *re = rule->getTDst();
        re->addRef(tdst);

        if (!nat_port_range_start.empty())
        {
            FWObject *s = make_translated_service();
            RuleElementTSrv *srv = rule->getTSrv();
            if (s) srv->addRef(s);
        }

        if (!i_intf.empty())
        {
            RuleElement *itf_i = rule->getItfInb();
            newInterface(i_intf);
            itf_i->addRef(all_interfaces[i_intf]);
        }
    }

    rule->setRuleType(rule_type);

    UnidirectionalRuleSet *rs = getUnidirRuleSet(current_chain, NAT::TYPENAME);
    RuleSet *ruleset = rs->ruleset;
    ruleset->add(current_rule);
    ruleset->renumberRules();

    if (error_tracker->hasWarnings())
    {
        QStringList warn = error_tracker->getWarnings();
        foreach(QString w, warn)
        {
            if (!w.startsWith("Parser warning:")) addMessageToLog("Warning: " + w);
        }
        markCurrentRuleBad();
    }

    if (error_tracker->hasErrors())
    {
        QStringList err = error_tracker->getErrors();
        foreach(QString e, err)
        {
            if (!e.startsWith("Parser error:")) addMessageToLog("Error: " + e);
        }
        markCurrentRuleBad();
    }

    addStandardImportComment(
        current_rule, QString::fromUtf8(rule_comment.c_str()));

    current_rule = nullptr;
    rule_comment = "";

    clear();
}

FWObject* NftImporter::createTCPService(const QString &)
{
    if (src_port_range_start.empty() && dst_port_range_start.empty())
        return nullptr;

    ObjectSignature sig(error_tracker);
    sig.type_name = TCPService::TYPENAME;
    sig.setSrcPortRange(src_port_range_start.empty() ? "0" : src_port_range_start.c_str(),
                        src_port_range_end.empty() ? "0" : src_port_range_end.c_str(),
                        "tcp");
    sig.setDstPortRange(dst_port_range_start.empty() ? "0" : dst_port_range_start.c_str(),
                        dst_port_range_end.empty() ? "0" : dst_port_range_end.c_str(),
                        "tcp");
    return commitObject(service_maker->createObject(sig));
}

FWObject* NftImporter::createUDPService(const QString &)
{
    if (src_port_range_start.empty() && dst_port_range_start.empty())
        return nullptr;

    ObjectSignature sig(error_tracker);
    sig.type_name = UDPService::TYPENAME;
    sig.setSrcPortRange(src_port_range_start.empty() ? "0" : src_port_range_start.c_str(),
                        src_port_range_end.empty() ? "0" : src_port_range_end.c_str(),
                        "udp");
    sig.setDstPortRange(dst_port_range_start.empty() ? "0" : dst_port_range_start.c_str(),
                        dst_port_range_end.empty() ? "0" : dst_port_range_end.c_str(),
                        "udp");
    return commitObject(service_maker->createObject(sig));
}

bool NftImporter::isAddressSetType(const std::string &type_name) const
{
    if (type_name == "ipv4_addr" || type_name == "ipv6_addr" || type_name == "inet_addr")
        return true;
    return false;
}

void NftImporter::parseSetTypeStatement(const std::vector<std::string> &tokens)
{
    if (current_set_name.empty() || tokens.size() < 2) return;

    auto &def = set_definitions[current_set_name];

    string type_token = tokens[1];
    string value_type;

    string::size_type pos = type_token.find(':');
    if (pos != string::npos)
    {
        value_type = type_token.substr(pos + 1);
        type_token = type_token.substr(0, pos);
    } else
    {
        for (size_t i = 2; i < tokens.size(); ++i)
        {
            if (tokens[i] == ":" && i + 1 < tokens.size())
            {
                value_type = tokens[i + 1];
                break;
            }
        }
    }

    def.key_type = type_token;
    def.value_type = value_type;
}

void NftImporter::parseSetElementsStatement(const std::vector<std::string> &tokens)
{
    if (current_set_name.empty()) return;

    auto &def = set_definitions[current_set_name];
    def.has_elements = true;

    auto start_it = std::find(tokens.begin(), tokens.end(), "{");
    auto end_it = std::find(tokens.rbegin(), tokens.rend(), "}");
    if (start_it == tokens.end() || end_it == tokens.rend()) return;

    size_t start = static_cast<size_t>(std::distance(tokens.begin(), start_it)) + 1;
    size_t end = tokens.size() - static_cast<size_t>(std::distance(tokens.rbegin(), end_it)) - 1;
    if (end <= start) return;

    if (def.is_map)
    {
        for (size_t i = start; i < end; ++i)
        {
            const string &key = tokens[i];
            if (key == ":" || key == "=") continue;
            if (i + 2 < end && tokens[i + 1] == ":")
            {
                def.map_elements.emplace_back(key, tokens[i + 2]);
                i += 2;
                continue;
            }
            def.elements.push_back(key);
        }
        return;
    }

    for (size_t i = start; i < end; ++i)
    {
        const string &tok = tokens[i];
        if (tok == "=" || tok == "{" || tok == "}") continue;
        def.elements.push_back(tok);
    }
}

FWObject* NftImporter::ensureSetObject(const std::string &name, bool is_map)
{
    auto it = set_objects.find(name);
    if (it != set_objects.end()) return it->second;

    if (set_definitions.count(name) == 0)
    {
        NftSetDefinition def;
        def.name = name;
        def.is_map = is_map;
        set_definitions[name] = def;
        addMessageToLog(
            QString("Warning: nft %1 '%2' referenced but not defined.")
                .arg(is_map ? "map" : "set")
                .arg(QString::fromUtf8(name.c_str())));
    }

    ObjectSignature sig(error_tracker);
    sig.type_name = AddressTable::TYPENAME;
    sig.object_name = QString::fromUtf8(name.c_str());
    sig.address_table_name = "";
    FWObject *obj = address_maker->createObject(sig);

    if (obj)
    {
        addStandardImportComment(
            obj,
            QString("Imported from nft %1 definition")
                .arg(set_definitions[name].is_map ? "map" : "set"));
        obj = commitObject(obj);
        set_objects[name] = obj;
    }

    return obj;
}

void NftImporter::populateSetElements(FWObject *obj, const NftSetDefinition &definition)
{
    AddressTable *table = AddressTable::cast(obj);
    if (!table) return;

    if (!definition.key_type.empty() && !isAddressSetType(definition.key_type))
    {
        QString err = QString("nft %1 '%2' uses unsupported key type '%3'.")
                          .arg(definition.is_map ? "map" : "set")
                          .arg(QString::fromUtf8(definition.name.c_str()))
                          .arg(QString::fromUtf8(definition.key_type.c_str()));
        addMessageToLog("Warning: " + err);
        registerBrokenObject(table, err);
        return;
    }

    if (definition.is_map)
    {
        if (!definition.map_elements.empty())
        {
            addMessageToLog(
                QString("Warning: nft map '%1' values are not imported; only keys are used.")
                    .arg(QString::fromUtf8(definition.name.c_str())));
            QString err =
                QObject::tr("nft map '%1' values are not represented in the import.")
                    .arg(QString::fromUtf8(definition.name.c_str()));
            registerBrokenObject(table, err);
        }
    }

    auto add_element = [&](const std::string &token) {
        if (token.find('-') != string::npos)
        {
            addMessageToLog(
                QString("Warning: nft %1 '%2' element '%3' is an address range "
                        "and was skipped during import.")
                    .arg(definition.is_map ? "map" : "set")
                    .arg(QString::fromUtf8(definition.name.c_str()))
                    .arg(QString::fromUtf8(token.c_str())));
            return;
        }

        string addr;
        string nm;
        parseAddress(token, addr, nm);
        if (addr.empty()) return;
        FWObject *addr_obj = makeAddressObj(addr, nm);
        if (addr_obj) table->addRef(addr_obj);
    };

    if (definition.is_map)
    {
        for (const auto &entry : definition.map_elements)
            add_element(entry.first);
        for (const auto &entry : definition.elements)
            add_element(entry);
    } else
    {
        for (const auto &entry : definition.elements)
            add_element(entry);
    }
}
