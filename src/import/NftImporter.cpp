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
                setSourceAddress(tokens[i + 2]);
                i += 2;
                continue;
            }
            if (next == "daddr")
            {
                setDestinationAddress(tokens[i + 2]);
                i += 2;
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
            setSourceAddress(tokens[i + 1]);
            i += 1;
            continue;
        }
        if (tok == "daddr" && i + 1 < tokens.size())
        {
            setDestinationAddress(tokens[i + 1]);
            i += 1;
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
