/*

                          Firewall Builder

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

#include "nft_utils.h"

#include <algorithm>
#include <cctype>
#include <map>
#include <sstream>
#include <vector>

namespace fwcompiler {
namespace nft_utils {

namespace {
std::string toLower(std::string value)
{
    std::transform(value.begin(), value.end(), value.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return value;
}

std::vector<std::string> split(const std::string &value, char sep)
{
    std::vector<std::string> parts;
    std::string current;
    for (char ch : value)
    {
        if (ch == sep)
        {
            if (!current.empty())
            {
                parts.push_back(current);
                current.clear();
            }
        } else
        {
            current.push_back(ch);
        }
    }
    if (!current.empty()) parts.push_back(current);
    return parts;
}
}

std::string commandPrefix(bool atomic_mode)
{
    return atomic_mode ? std::string() : std::string("$NFT ");
}

std::string familyName(bool ipv6)
{
    return ipv6 ? "ip6" : "ip";
}

std::string baseChainDefinition(const std::string &table,
                                const std::string &chain,
                                bool ipv6,
                                const std::string &policy)
{
    static const std::map<std::string, std::map<std::string, std::string>> hooks = {
        {"filter",
         { {"INPUT", "type filter hook input priority 0"},
           {"FORWARD", "type filter hook forward priority 0"},
           {"OUTPUT", "type filter hook output priority 0"} }},
        {"mangle",
         { {"PREROUTING", "type filter hook prerouting priority -150"},
           {"INPUT", "type filter hook input priority -150"},
           {"FORWARD", "type filter hook forward priority -150"},
           {"OUTPUT", "type filter hook output priority -150"},
           {"POSTROUTING", "type filter hook postrouting priority -150"} }},
        {"nat",
         { {"PREROUTING", "type nat hook prerouting priority -100"},
           {"INPUT", "type nat hook input priority -100"},
           {"OUTPUT", "type nat hook output priority -100"},
           {"POSTROUTING", "type nat hook postrouting priority 100"} }}
    };

    auto table_it = hooks.find(table);
    if (table_it == hooks.end()) return "";

    auto chain_it = table_it->second.find(chain);
    if (chain_it == table_it->second.end()) return "";

    std::ostringstream output;
    output << "add chain " << familyName(ipv6) << " " << table << " " << chain
           << " { " << chain_it->second;
    if (!policy.empty()) output << "; policy " << policy;
    output << "; }";
    return output.str();
}

std::string markMatchExpression(const std::string &mark, bool negated)
{
    auto parts = split(mark, '/');
    std::ostringstream output;
    output << "meta mark";
    if (parts.size() == 2)
    {
        output << " & " << parts[1] << (negated ? " != " : " == ") << parts[0];
    } else
    {
        output << (negated ? " != " : " == ") << mark;
    }
    return output.str();
}

std::string markSetExpression(const std::string &mark)
{
    return "meta mark set " + mark;
}

std::string setMatchExpression(const std::string &family,
                               const std::string &direction,
                               const std::string &set_name,
                               bool negated)
{
    std::ostringstream output;
    output << family << " " << direction;
    if (negated) output << " != "; else output << " ";
    output << "@" << set_name;
    return output.str();
}

std::string conntrackStateExpression(const std::string &states, bool negated)
{
    std::string normalized = toLower(states);
    std::replace(normalized.begin(), normalized.end(), ',', ' ');
    std::ostringstream output;
    output << "ct state";
    if (negated) output << " != "; else output << " { ";
    if (negated)
        output << normalized;
    else
        output << normalized << " }";
    return output.str();
}

std::string rejectWithExpression(const std::string &reject_with, bool ipv6)
{
    static const std::map<std::string, std::string> map = {
        {"tcp-reset", "reject with tcp reset"},
        {"icmp-net-unreachable", "reject with icmp type net-unreachable"},
        {"icmp-host-unreachable", "reject with icmp type host-unreachable"},
        {"icmp-port-unreachable", "reject with icmp type port-unreachable"},
        {"icmp-proto-unreachable", "reject with icmp type protocol-unreachable"},
        {"icmp-net-prohibited", "reject with icmp type net-prohibited"},
        {"icmp-host-prohibited", "reject with icmp type host-prohibited"},
        {"icmp-admin-prohibited", "reject with icmp type admin-prohibited"},
        {"icmp6-addr-unreachable", "reject with icmpv6 type addr-unreachable"},
        {"icmp6-port-unreachable", "reject with icmpv6 type port-unreachable"},
        {"icmp6-adm-prohibited", "reject with icmpv6 type admin-prohibited"}
    };

    auto it = map.find(reject_with);
    if (it != map.end()) return it->second;

    if (ipv6)
        return "reject with icmpv6 type admin-prohibited";

    return "reject with icmp type admin-prohibited";
}

std::string tcpFlagsExpression(const std::string &mask, const std::string &comp)
{
    auto mask_parts = split(toLower(mask), ',');
    auto comp_parts = split(toLower(comp), ',');

    if (mask_parts.empty() || comp_parts.empty()) return "";

    std::ostringstream mask_stream;
    for (size_t i = 0; i < mask_parts.size(); ++i)
    {
        if (i > 0) mask_stream << "|";
        mask_stream << mask_parts[i];
    }

    std::ostringstream comp_stream;
    for (size_t i = 0; i < comp_parts.size(); ++i)
    {
        if (i > 0) comp_stream << "|";
        comp_stream << comp_parts[i];
    }

    std::ostringstream output;
    output << "tcp flags & (" << mask_stream.str() << ") == "
           << comp_stream.str();
    return output.str();
}

std::string timeMatchExpression(const std::string &start_time,
                                const std::string &stop_time,
                                const std::string &days_of_week,
                                bool use_kernel_tz)
{
    std::vector<std::string> parts;
    if (!start_time.empty() && !stop_time.empty())
    {
        std::ostringstream range;
        range << "time { " << start_time << "-" << stop_time << " }";
        parts.push_back(range.str());
    }

    if (!days_of_week.empty())
    {
        std::ostringstream days;
        days << "time day { " << toLower(days_of_week) << " }";
        parts.push_back(days.str());
    }

    if (use_kernel_tz)
        parts.push_back("time zone kernel");

    if (parts.empty()) return "";

    std::ostringstream output;
    for (size_t i = 0; i < parts.size(); ++i)
    {
        if (i > 0) output << " ";
        output << parts[i];
    }
    return output.str();
}

}
}
