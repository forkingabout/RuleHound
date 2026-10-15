#!/usr/bin/env python3
"""
SonicWall configuration -> RuleHound YAML (objects + links).

Parses an entire SonicOS configuration export into RuleHound's
Meta / Objects / Links YAML format.  Every key in the configuration ends
up in exactly one object:

  * Indexed keys (name_<n>=value) are grouped into tables.  Known tables
    become typed objects (Zone, Interface, AccessRule, ...), one object per
    row.  Unknown tables become ConfigTableRow / ConfigList objects so
    nothing is dropped.
  * Signature- or category-keyed tables (IPS, App Control, ...) become one
    KeyedTable-style object each, holding "key=value" lists.
  * Un-indexed keys become SystemSettings objects grouped by key family.

Links are created from declared reference fields (LINK_SPECS) and group
membership tables (GROUP_SPECS).  See SONICWALL_PARSER.md (generated with
--doc) for every object type, property and link rule.

Usage:
    sonicwall_parser.py <config> [-o out.yaml]
    sonicwall_parser.py <config> --doc SONICWALL_PARSER.md

The input may be a base64 .exp export ('&'-separated, URL-encoded) or an
already-decoded plaintext dump (one key=value per line).
"""

import argparse
import base64
import json
import re
import sys
from collections import OrderedDict, defaultdict
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Tuple
from urllib.parse import unquote

PARSER_VERSION = "3.0"

META_YAML = """Meta:
  ParserName: "Sonicwall Parser"
  ParserVersion: "{version}"
  ParserAuthor: "RuleHound"
  FirewallBrand: "Sonicwall"
  FirewallVersions:
    - "7.0"
    - "7.2"
    - "7.3"
"""

INDEXED_KEY_RE = re.compile(r"^(.+)_(\d+)$")
KEY_LINE_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_]*=")
HTML_OPEN_RE = re.compile(r"(?i)<html|<!doctype")
HTML_CLOSE_RE = re.compile(r"(?i)</html>")

# Values meaning "nothing / any" in reference fields; never linked or reported
NULL_REFS = {"", "-1", "4294967295"}
# SonicWall sentinel values such as __RemoteNatUseOriginalAddress__
SENTINEL_RE = re.compile(r"^__\w+__$")
# Large generic tables are condensed into one ConfigTable object instead of one row each
GENERIC_ROW_LIMIT = 64

# --------------------------------------------------------------------------
# Value helpers
# --------------------------------------------------------------------------

# SonicWall-encrypted value ("<n>,<hex>"); used only to recognise unused pre-allocated rows
ENCRYPTED_VALUE_RE = re.compile(r"^\d+,[0-9a-fA-F]{16,}$")
# Values that mean "not set" in reference fields (used by the --orphans report only)
EMPTY_VALUES = {"", "0", "off", "-1", "0.0.0.0", "::", "4294967295", "000000000000", "00:00:00:00:00:00"}
KEY_TOKEN_RE = re.compile(r"[A-Z]+(?![a-z])|[A-Z]?[a-z]+|\d+")
TRIVIAL_VALUE_RE = re.compile(r"^(on|off|true|false|\d{1,4})$", re.IGNORECASE)


# --------------------------------------------------------------------------
# Config loading
# --------------------------------------------------------------------------

class Config:
    def __init__(self, scalars, indexed):
        self.scalars = scalars    # key -> value (insertion ordered)
        self.indexed = indexed    # base -> {index: value} (insertion ordered)

    @classmethod
    def load(cls, path):
        with open(path, "r", encoding="utf-8", errors="replace", newline="") as f:
            raw = f.read()
        pairs = cls.split_pairs(raw)
        scalars, indexed = OrderedDict(), OrderedDict()
        for key, value in pairs:
            m = INDEXED_KEY_RE.match(key)
            if m:
                indexed.setdefault(m.group(1), OrderedDict())[int(m.group(2))] = value
            else:
                scalars[key] = value
        if not scalars and not indexed:
            raise ValueError(f"{path}: no key=value pairs found - not a SonicWall export?")
        cfg = cls(scalars, indexed)
        cfg.pairs = pairs
        return cfg

    @staticmethod
    def split_pairs(raw):
        """Split an export into (key, value) pairs, exactly as stored.

        Plaintext dumps hold one key=value per line, but some values span several lines: URL lists hold one
        domain per line, and block/login pages hold whole HTML documents including blank lines and script
        lines such as `base="";` that look like keys. A line therefore starts a new key only when it matches
        the SonicWall key pattern and no HTML document (opened by <html or <!DOCTYPE) is still open; every
        other line, blank or not, continues the current value. "\\n".join(key=value) reproduces the file.
        Base64 .exp exports are '&'-separated with URL-encoded values, so their values never span lines."""
        kv_lines = sum(1 for line in raw.splitlines()[:50] if "=" in line)
        if kv_lines < 2:
            b64 = re.sub(r"[^A-Za-z0-9+/]", "", raw)
            b64 += "=" * (-len(b64) % 4)
            text = base64.b64decode(b64).decode("utf-8", errors="replace")
            pairs = []
            for part in text.split("&"):
                if "=" in part:
                    key, value = part.split("=", 1)
                    if key:
                        pairs.append((key, unquote(value)))
            return pairs
        body = raw[:-1] if raw.endswith("\n") else raw
        pairs, in_document = [], False
        for line in body.split("\n"):
            if not in_document and KEY_LINE_RE.match(line):
                key, value = line.split("=", 1)
                pairs.append([key, value])
                in_document = bool(HTML_OPEN_RE.search(value)) and not HTML_CLOSE_RE.search(value)
            elif pairs:
                pairs[-1][1] += "\n" + line
                if in_document and HTML_CLOSE_RE.search(line):
                    in_document = False
            else:
                pairs.append(["", line])          # text before the first key: kept, never dropped
        return [tuple(p) for p in pairs]


# --------------------------------------------------------------------------
# Value decoders (added as extra, human-readable properties)
# --------------------------------------------------------------------------

POLICY_ACTIONS = {"0": "Deny", "1": "Discard", "2": "Allow"}
ADDRESS_TYPES = {"1": "Host", "2": "Range", "4": "Network", "8": "Group",
                 "256": "Host", "512": "Host", "1024": "Range", "2048": "Network",
                 "4096": "MAC", "8192": "FQDN"}
IP_PROTOCOLS = {"0": "IP", "1": "ICMP", "2": "IGMP", "6": "TCP", "17": "UDP", "41": "IPv6",
                "47": "GRE", "50": "ESP", "51": "AH", "58": "ICMPv6", "89": "OSPF",
                "108": "IPComp", "170": "Group"}
BOOL_ON = {"1", "on", "true", "yes"}


def on(value):
    return str(value).lower() in BOOL_ON


# --------------------------------------------------------------------------
# Table specifications
# --------------------------------------------------------------------------

@dataclass
class TableSpec:
    """One SonicWall table -> one object per row."""
    type: str                                 # object Type (default)
    prefixes: Tuple[str, ...]                 # config key prefixes belonging to this table
    name: Optional[str] = None                # config key holding the object name
    strip: Optional[str] = None               # prefix removed from property keys
    v6: Optional[str] = None                  # "only": keys end in V6; "exclude": reject V6 keys
    type_field: Optional[str] = None          # config key selecting the Type per row
    type_map: Dict[str, str] = field(default_factory=dict)
    keys: Dict[str, str] = field(default_factory=dict)       # extra lookup key -> config key
    derive: Optional[Callable] = None         # (raw row) -> OrderedDict of decoded properties
    caption: Optional[Callable] = None        # (props) -> caption
    name_fn: Optional[Callable] = None        # (raw row, index) -> name when name key empty
    category: str = "Other"
    description: str = ""

    def matches(self, base):
        for p in self.prefixes:
            if base.startswith(p):
                if self.v6 == "only" and not base.endswith("V6"):
                    return 0
                if self.v6 == "exclude" and base.endswith("V6"):
                    return 0
                return len(p)
        return 0

    def prop_key(self, base):
        key = base
        if self.v6 == "only" and key.endswith("V6"):
            key = key[:-2]
        if self.strip and key.startswith(self.strip) and len(key) > len(self.strip):
            key = key[len(self.strip):]
        return key.lstrip("_") or base


def g(raw, key, default=""):
    """Row lookup that tolerates the V6 key suffix."""
    if key in raw:
        return raw[key]
    return raw.get(key + "V6", default)


# ---- derived-property helpers ----------------------------------------------

def derive_policy(raw):
    return OrderedDict([
        ("ActionName", POLICY_ACTIONS.get(g(raw, "policyAction"), g(raw, "policyAction"))),
        ("Enabled", on(g(raw, "policyEnabled"))),
        ("SourceZone", g(raw, "policySrcZone")),
        ("DestZone", g(raw, "policyDstZone")),
        ("SourceNet", g(raw, "policySrcNet") or "Any"),
        ("DestNet", g(raw, "policyDstNet") or "Any"),
        ("SourceService", g(raw, "policySrcSvc") or "Any"),
        ("DestService", g(raw, "policyDstSvc") or "Any"),
    ])


def caption_policy(p):
    return (f"{p['ActionName']}: {p['SourceZone']}->{p['DestZone']} "
            f"{p['SourceNet']} -> {p['DestNet']} ({p['DestService']})")


def derive_nat(raw):
    return OrderedDict([
        ("Enabled", on(g(raw, "natPolicyEnabled"))),
        ("Reflexive", on(g(raw, "natPolicyReflexive"))),
        ("OriginalSource", g(raw, "natPolicyOrigSrc") or "Any"),
        ("TranslatedSource", g(raw, "natPolicyTransSrc") or "Original"),
        ("OriginalDest", g(raw, "natPolicyOrigDst") or "Any"),
        ("TranslatedDest", g(raw, "natPolicyTransDst") or "Original"),
        ("OriginalService", g(raw, "natPolicyOrigSvc") or "Any"),
        ("TranslatedService", g(raw, "natPolicyTransSvc") or "Original"),
    ])


def caption_nat(p):
    return (f"NAT: {p['OriginalSource']} -> {p['OriginalDest']} ({p['OriginalService']}) "
            f"=> {p['TranslatedSource']} -> {p['TranslatedDest']}")


def derive_addr(raw):
    t = next((v for k, v in raw.items() if k.endswith("Type")), "")
    return OrderedDict([("AddressType", ADDRESS_TYPES.get(t, t))])


def derive_addr_v4(raw):
    d = derive_addr(raw)
    d["Family"] = "IPv4"
    return d


def derive_addr_v6(raw):
    d = derive_addr(raw)
    d["Family"] = "IPv6"
    return d


def country_bit(index_value):
    return int(index_value) & 0xFFFF if str(index_value).isdigit() else None


def derive_country(raw):
    v = raw.get("countryObjIndex", "")
    if not v.isdigit():
        return OrderedDict()
    n = int(v)
    code = (chr(n >> 16 & 0xFF) + chr(n >> 24 & 0xFF)) if 32 < (n >> 16 & 0xFF) < 127 else ""
    return OrderedDict([("CountryCode", code), ("BitmapBit", n & 0xFFFF)])


def category_flags(value):
    """CFS profile category list ("1,1,0,...") -> category ids whose flag is 1 (position n = category n+1)."""
    if not value or "," not in value or not re.fullmatch(r"[0-9,]+", value):
        return []
    return [str(pos + 1) for pos, flag in enumerate(value.split(",")) if flag == "1"]


def category_catalogue(cfg):
    """SonicWall's web-category catalogue (cfsCategoryStr JSON): id -> name."""
    raw = cfg.scalars.get("cfsCategoryStr", "")
    try:
        entries = json.loads(raw).get("entries", [])
    except (ValueError, AttributeError):
        return OrderedDict()
    out = OrderedDict()
    for e in entries:
        for k, v in (e.items() if isinstance(e, dict) else ()):
            if str(k).isdigit():
                out[int(k)] = v
    return out


def bitmap_bits(value):
    """Geo-IP bitmap (hex string) -> set bit numbers, MSB-first within each byte."""
    if not value or not re.fullmatch(r"[0-9a-fA-F]+", value) or len(value) % 2:
        return []
    raw = bytes.fromhex(value)
    return [str(8 * k + (7 - b)) for k, byte in enumerate(raw) for b in range(8) if byte >> b & 1]


WEEKDAYS = ("Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat")   # schedObjDaysOfWeek bit 0 = Sunday


def hhmm(minutes):
    m = int(minutes)
    return f"{m // 60:02d}:{m % 60:02d}"


def derive_schedule(raw):
    """Recurring window: DaysOfWeek bitmask + minutes since midnight. One-time window: Start*/End* fields."""
    if raw.get("schedObjType") != "1":
        return OrderedDict()      # groups carry no times of their own; their members do
    out = OrderedDict()
    days = raw.get("schedObjDaysOfWeek", "")
    if days.isdigit():
        out["Days"] = [d for bit, d in enumerate(WEEKDAYS) if int(days) >> bit & 1]
    for prop, key in (("StartTime", "schedObjTimeBegin"), ("EndTime", "schedObjTimeEnd")):
        if raw.get(key, "").isdigit():
            out[prop] = hhmm(raw[key])
    parts = {k: raw.get("schedObj" + k, "0") for k in ("StartYear", "StartMon", "StartDay", "StartHour",
             "StartMinute", "EndYear", "EndMon", "EndDay", "EndHour", "EndMinute")}
    if any(v not in ("", "0") for v in parts.values()):
        def stamp(p):
            return (f"{int(parts[p + 'Year']):04d}-{int(parts[p + 'Mon']):02d}-{int(parts[p + 'Day']):02d} "
                    f"{int(parts[p + 'Hour']):02d}:{int(parts[p + 'Minute']):02d}")
        out["OneTimeStart"], out["OneTimeEnd"] = stamp("Start"), stamp("End")
    return out


def derive_service(raw):
    proto = raw.get("svcObjIpType", "")
    return OrderedDict([("ProtocolName", IP_PROTOCOLS.get(proto, proto))])


def interface_ip(raw):
    for k in ("iface_lan_ip", "iface_static_ip", "iface_mgmt_ip"):
        v = raw.get(k, "")
        if v and v != "0.0.0.0":
            mask = raw.get(k.replace("_ip", "_mask"), "") or raw.get("iface_lan_mask", "")
            return v, mask
    return "", ""


def derive_interface(raw):
    ip, mask = interface_ip(raw)
    ifnum = raw.get("iface_ifnum", "")
    is_vlan = raw.get("iface_phys_type") == "2" or (ifnum.isdigit() and int(ifnum) >= 0x10000000)
    return OrderedDict([
        ("IPAddress", ip),
        ("SubnetMask", mask),
        ("Zone", raw.get("interface_Zone", "")),
        ("IsVLAN", is_vlan),
    ])


def caption_interface(p):
    zone = p.get("Zone") or "unassigned"
    ip = f" {p['IPAddress']}" if p.get("IPAddress") else ""
    return f"{p['ObjectName']} ({zone}){ip}"


def name_dhcp_scope(raw, i):
    return f"{raw.get('prefs_dhdynstart', '?')}-{raw.get('prefs_dhdynend', '?')}"


def name_dhcp_static(raw, i):
    return raw.get("prefs_dhstaticname") or raw.get("prefs_dhstaticip") or f"Static {i}"


SPECS: List[TableSpec] = [
    # ---------------- Network ----------------
    TableSpec("Zone", ("zoneObj", "wgsSocial"), name="zoneObjId", strip="zoneObj",
              category="Network",
              description="Security zone. Includes per-zone guest-services and social-login settings."),
    TableSpec("Interface",
              ("iface_", "interface_", "eth_", "ex_eth", "if_", "ZOspf", "ZRip", "swZ", "swIsIfArsRdy",
               "sw_enable_auto_discover", "haIf", "haPhysical", "haLogical", "haPrimary", "haBackup",
               "haRemote", "haIsManual", "haVirtual", "http_mgmt", "https_mgmt", "ssh_mgmt", "ping_mgmt",
               "snmp_mgmt", "secSubnet", "portGrouping", "portShutdown", "loc_v6", "rmt_v6",
               "bridge_bypass", "bridged_iface", "pppoe_", "pppoe6_", "redundantPort", "nativebridge_",
               "NDP_max", "linkAggrPort", "wmLinkAggrPort"),
              name="iface_name", strip="iface_", keys={"ifnum": "iface_ifnum"},
              derive=derive_interface, caption=caption_interface, category="Network",
              description="Physical, VLAN, tunnel or virtual interface. All per-interface tables "
                          "(Ethernet, HA, routing protocol, management, PPPoE, bridge, link "
                          "aggregation) are merged into the interface row with the same index."),
    TableSpec("MacIpAntiSpoof", ("macIpSpoof",), strip="macIpSpoof", name_fn=lambda r, i: f"IPv4 anti-spoof {r.get('macIpSpoofIface', i)}",
              category="Network", description="MAC-IP anti-spoof settings for one interface (IPv4)."),
    TableSpec("MacIpAntiSpoofV6", ("macIpv6Spoof",), strip="macIpv6Spoof",
              name_fn=lambda r, i: f"IPv6 anti-spoof {r.get('macIpv6SpoofIface', i)}",
              category="Network", description="MAC-IP anti-spoof settings for one interface (IPv6)."),
    TableSpec("LoadBalancingGroup", ("irg_",), name="irg_display_name", strip="irg_", category="Network",
              description="Failover & load-balancing group of WAN interfaces."),
    TableSpec("LoadBalancingMember", ("irgmem_",), name="irgmem_display_name", strip="irgmem_",
              caption=lambda p: f"{p['ObjectName']} in {p.get('group_name', '').strip()}",
              category="Network", description="One interface's membership in a load-balancing group."),
    TableSpec("RoutePolicy", ("pbr",), name="pbrObjId", strip="pbrObj", category="Network",
              description="Static / policy-based route."),
    TableSpec("NetworkMonitorPolicy", ("NM", "netMonPolicyProperties"), name="NMobjId", strip="NM",
              category="Network", description="Network monitor (probe) policy."),
    TableSpec("DHCPScope", ("prefs_dhdyn",), strip="prefs_dhdyn", name_fn=name_dhcp_scope,
              category="Network", description="Dynamic DHCPv4 server scope."),
    TableSpec("DHCPStaticLease", ("prefs_dhstatic", "prefs_dhStat"), strip="prefs_dhstatic",
              name_fn=name_dhcp_static, category="Network", description="Static DHCPv4 lease."),
    TableSpec("IPHelperApp", ("iphApp",), name="iphAppName", strip="iphApp", category="Network",
              description="IP Helper relayed protocol (DHCP, NetBIOS, DNS, ...)."),
    TableSpec("SplitDNS", ("split_dns",), name="split_dns_domain", strip="split_dns_",
              category="Network", description="Split-DNS domain entry."),
    TableSpec("WWANProfile", ("wwan",), strip="wwan", name_fn=lambda r, i: f"WWAN profile {i}",
              category="Network", description="3G/4G/5G WWAN connection profile."),
    TableSpec("PerformanceClass", ("perfClass",), name="perfClassObjId", strip="perfClassObj",
              category="Network", description="SD-WAN performance class (latency / jitter / loss SLA)."),
    TableSpec("WANAccelerationGroup", ("bandOptGroup",), name="bandOptGroupName", strip="bandOptGroup",
              category="Network", description="WAN acceleration (WXA) group."),
    TableSpec("LLDPProfile", ("lldpProf",), name="lldpProfId", strip="lldpProf", category="Network",
              description="LLDP profile."),

    # ---------------- Objects ----------------
    TableSpec("IPAddress", ("addrObj",), name="addrObjId", strip="addrObj",
              type_field="addrObjType", type_map={"8": "AddressGroup"},
              derive=derive_addr_v4, category="Objects",
              description="IPv4 address object (host, range or network). Rows of type 8 become AddressGroup."),
    TableSpec("IPv6Address", ("addrObjV6",), name="addrObjV6Id", strip="addrObjV6",
              type_field="addrObjV6Type", type_map={"8": "AddressGroup"},
              derive=derive_addr_v6, category="Objects",
              description="IPv6 address object. Rows of type 8 become AddressGroup."),
    TableSpec("MACAddress", ("addrObjMac",), name="addrObjMacId", strip="addrObjMac",
              derive=derive_addr, category="Objects", description="MAC address object."),
    TableSpec("FQDNAddress", ("addrObjFqdn",), name="addrObjFqdnId", strip="addrObjFqdn",
              derive=derive_addr, category="Objects", description="FQDN address object."),
    TableSpec("Service", ("svcObj",), name="svcObjId", strip="svcObj",
              type_field="svcObjType", type_map={"2": "ServiceGroup"}, derive=derive_service,
              category="Objects", description="Service object (protocol + port range). Type 2 rows become ServiceGroup."),
    TableSpec("Schedule", ("schedObj",), name="schedObjId", strip="schedObj",
              type_field="schedObjType", type_map={"2": "ScheduleGroup"}, derive=derive_schedule,
              category="Objects",
              description="Schedule. Type 2 rows become ScheduleGroup."),
    TableSpec("CountryObject", ("countryObj",), name="countryObjId", strip="countryObj",
              keys={"geobit": "countryObjIndex"}, derive=lambda r: derive_country(r), category="Objects",
              description="Geo-IP country object. `countryObjIndex` packs the ISO code (high bytes, reversed) "
                          "and the country's bit number in Geo-IP bitmaps (low 16 bits)."),
    TableSpec("AppObject", ("appObj",), name="appObjId", strip="appObj",
              type_field="appObjType", type_map={"2": "AppObjectGroup"}, category="Objects",
              description="Application match object. Type 2 rows become AppObjectGroup."),
    TableSpec("URLCategoryObject", ("urlObj",), name="urlObjId", strip="urlObj",
              type_field="urlObjType", type_map={"2": "URLCategoryGroup"}, category="Objects",
              description="CFS web-category object. Type 2 rows become URLCategoryGroup."),
    TableSpec("WebsiteObject", ("urlxObj",), name="urlxObjId", strip="urlxObj", category="Objects",
              description="Website (domain list) object."),
    TableSpec("BandwidthObject", ("bwObj",), name="bwObjId", strip="bwObj", category="Objects",
              description="Bandwidth management object."),
    TableSpec("AppFirewallObject", ("afObject",), name="afObjectName", strip="afObject",
              category="Objects", description="Legacy App Rules match object."),

    # ---------------- Policies ----------------
    TableSpec("AccessRule", ("policy", "perPolicyGeoIpBitmap"), name="policyName", strip="policy",
              v6="exclude", derive=derive_policy, caption=caption_policy, category="Policies",
              description="IPv4 security (access) rule."),
    TableSpec("AccessRuleV6", ("policy", "perPolicyGeoIpBitmap"), name="policyName", strip="policy",
              v6="only", derive=derive_policy, caption=caption_policy, category="Policies",
              description="IPv6 security (access) rule. Keys ending in V6; property names have V6 removed."),
    TableSpec("NATRule", ("nat",), name="natPolicyName", strip="natPolicy", v6="exclude",
              derive=derive_nat, caption=caption_nat, category="Policies",
              description="IPv4 NAT policy."),
    TableSpec("NATRuleV6", ("nat",), name="natPolicyName", strip="natPolicy", v6="only",
              derive=derive_nat, caption=caption_nat, category="Policies",
              description="IPv6 NAT policy."),
    TableSpec("DNSPolicy", ("dnsPolicy", "dnsSrcNet", "dnsDstSvc", "dnsTime"), name="dnsPolicyName",
              strip="dnsPolicy", category="Policies", description="DNS proxy / security rule."),
    TableSpec("CFSPolicy", ("cfsPolicy",), name="cfsPolicyName", strip="cfsPolicy", category="Policies",
              description="Content filtering policy."),
    TableSpec("EndpointPolicy", ("cePolicy",), name="cePolicyName", strip="cePolicy", category="Policies",
              description="Capture Client / endpoint enforcement policy."),
    TableSpec("VPNPolicy", ("ipsec", "vpnPolicyType", "vpnTcpAcceleration", "vpnWxaGroup",
                            "vpnPrimaryDetectInterval", "AllowStaticIPToVA", "remoteUnit",
                            "ikePreemptSecGw"),
              name="ipsecName", strip="ipsec", category="Policies",
              description="IPsec VPN policy (site-to-site or GroupVPN)."),

    # ---------------- Security services / profiles ----------------
    TableSpec("SecurityActionProfile", ("peAct", "peAction"), name="peActObjId", strip="peActObj",
              category="Security", description="Security action profile applied by rules (CFS, GAV, IPS, anti-spyware, botnet, BWM)."),
    TableSpec("ThreatProfile", ("threatObj", "threatSigIds", "threatCatIds"), name="threatObjId",
              strip="threatObj", category="Security", description="Intrusion prevention (threat) object."),
    TableSpec("GatewayAVProfile", ("gavObj", "gavSigIds", "gavCatIds"), name="gavObjId", strip="gavObj",
              category="Security", description="Gateway anti-virus object."),
    TableSpec("AntiSpywareProfile", ("aspyObj", "aspySigIds", "aspyCatIds"), name="aspyObjId",
              strip="aspyObj", category="Security", description="Anti-spyware object."),
    TableSpec("CFSAction", ("cfsActionObj", "cfsAction", "cfsActPassphrase"), name="cfsActionObjId",
              strip="cfsAction", category="Security", description="Content filtering action object."),
    TableSpec("CFSProfile", ("cfsProfile", "cfsReputationEnabled", "cfsCustomHdr", "cfsConsent"),
              name="cfsProfileObjId", strip="cfsProfile", category="Security",
              description="Content filtering profile."),
    TableSpec("CFSUrlList", ("cfsUrlList", "cfsUrlObjInstanceId"), name="cfsUrlListObjId",
              strip="cfsUrlList", category="Security", description="CFS allowed/forbidden URL list."),
    TableSpec("CFSReputation", ("cfsReputationObj", "cfsReputationRangeOpr"), name="cfsReputationObjId",
              strip="cfsReputationObj", category="Security", description="CFS reputation object."),
    TableSpec("CFSCustomCategory", ("cfsCustomCategory",), name="cfsCustomCategoryDomain",
              strip="cfsCustomCategory", category="Security", description="CFS custom domain rating."),
    TableSpec("DoSActionProfile", ("dos",), name="dosActObjName", strip="dos", category="Security",
              description="DoS / flood protection action profile."),
    TableSpec("DNSFilterProfile", ("DNSFilterProfile",), name="DNSFilterProfileName",
              strip="DNSFilterProfile", category="Security", description="DNS filtering profile."),
    TableSpec("BlockPage", ("blockPage",), name="blockPageName", strip="blockPage", category="Security",
              description="Block page shown by CFS / app control."),
    TableSpec("ExternalGroup", ("externalGroup",), name="externalGroupName", strip="externalGroup",
              category="Security", description="Dynamic external address group (e.g. botnet feed)."),
    TableSpec("RBLServer", ("rblDomain",), name="rblDomainName", strip="rblDomain", category="Security",
              description="Real-time blacklist (DNSBL) server."),
    TableSpec("EndpointProfile", ("ceProfileObj",), name="ceProfileObjId", strip="ceProfileObj",
              category="Security", description="Endpoint enforcement profile."),
    TableSpec("EndpointService", ("ceSvc",), name="ceSvcId", strip="ceSvc", category="Security",
              description="Endpoint enforcement service licence entry."),
    TableSpec("NACDeviceProfile", ("nacAttr", "nacObj", "nacWlanTunnelIface"), name="nacAttrName",
              strip="nacAttr", category="Security", description="NAC / device profile."),

    # ---------------- Users & authentication ----------------
    TableSpec("User", ("userObj", "userLoginFailNum", "userLoginSuccNum", "userLastLogin", "userOrigPrivMask"),
              name="userObjId", strip="userObj", derive=lambda r: derive_user(r), category="Users",
              description="Local or LDAP-imported user account, including its login statistics "
                          "(failed / successful logins, last login time and address)."),
    TableSpec("UserGroup", ("userGroupObj",), name="userGroupObjId", strip="userGroupObj", category="Users",
              description="User group (local or LDAP-mirrored)."),
    TableSpec("GuestProfile", ("guestProfileObj",), name="guestProfileObjId", strip="guestProfileObj",
              category="Users", description="Guest services account profile."),
    TableSpec("LDAPServer", ("ldapSrvr",), name="ldapSrvrHostName", strip="ldapSrvr", category="Users",
              description="LDAP / AD server."),
    TableSpec("LDAPUserTree", ("ldapUsrsTree",), name="ldapUsrsTreeName", strip="ldapUsrsTree",
              category="Users", description="LDAP tree searched for users."),
    TableSpec("LDAPGroupTree", ("ldapUsrGrpsTree",), name="ldapUsrGrpsTreeName", strip="ldapUsrGrpsTree",
              category="Users", description="LDAP tree searched for user groups."),
    TableSpec("SSOAgent", ("ciaAuth",), name="ciaAuthAgentIP", strip="ciaAuth", category="Users",
              description="SSO (Directory Connector / CIA) agent."),
    TableSpec("AuthPartition", ("authPartition",), name="authPartitionName", strip="authPartition",
              category="Users", description="Authentication partition."),
    TableSpec("AuthPartitionSettings", ("partAuth",), name="partAuthSettingsPartName", strip="partAuth",
              category="Users", description="Per-partition authentication / SSO method settings."),
    TableSpec("AutoLoginBypass", ("autoLognBypass",), name="autoLognBypassObjName", strip="autoLognBypass",
              category="Users", description="Object excluded from SSO auto-login."),
    TableSpec("ClearPassServer", ("clearPass",), name="clearPassServerAddr", strip="clearPass",
              category="Users", description="Aruba ClearPass server."),
    TableSpec("SNMPv3View", ("Snmp3_View", "Snmp3_OID", "Snmp3_isDefOID"), name="Snmp3_View_Name",
              strip="Snmp3_", category="Users", description="SNMPv3 view."),
    TableSpec("SNMPv3Access", ("Snmp3_acc",), name="Snmp3_acc_name", strip="Snmp3_acc_", category="Users",
              description="SNMPv3 group access entry."),

    # ---------------- Wireless ----------------
    TableSpec("WLANVirtualAP", ("wlanVap",), name="wlanVapObjId", strip="wlanVap",
              type_field="wlanVapObjType", type_map={"1": "WLANVirtualAPGroup", "4": "WLANVirtualAPProfile"},
              category="Wireless",
              description="Wireless virtual access point (SSID). ObjType 1 rows become WLANVirtualAPGroup, "
                          "ObjType 4 rows become WLANVirtualAPProfile."),
    TableSpec("SonicPointProfile", ("sonicPoint",), name="sonicPointObjId", strip="sonicPoint",
              category="Wireless", description="Legacy SonicPoint (a/b/g) provisioning profile."),
    TableSpec("SonicPointNProfile", ("sonicPointN", "ssonicPoint", "spN1", "spW2", "sonicPointATF", "sonicPointW2",
                                     "sonicWave", "ssonicWave"), name="sonicPointNObjId",
              strip="sonicPointN", category="Wireless",
              description="SonicPoint-N / SonicWave provisioning profile."),

    # ---------------- Switching ----------------
    TableSpec("ExternalSwitch", ("extSwInstance",), name="extSwInstanceSwitchName", strip="extSwInstance",
              name_fn=lambda r, i: f"Switch {i}", category="Switching",
              description="Managed external SonicWall switch."),
    TableSpec("ExternalSwitchNetwork", ("extSwNtw",), strip="extSwNtw",
              name_fn=lambda r, i: f"Switch {r.get('extSwNtwSwID', '?')} VLAN {r.get('extSwNtwVlanID', '?')}",
              category="Switching", description="Network (VLAN) on a managed switch."),
    TableSpec("ExternalSwitchUser", ("extSwUserAcc",), name="extSwUserAccountUserName", strip="extSwUserAccount",
              name_fn=lambda r, i: f"Switch user {i}", category="Switching",
              description="User account on a managed switch."),
]

# Tables keyed by signature / category / event ID rather than by row.
# Each becomes ONE object whose properties are lists of "key=value".
@dataclass
class KeyedSpec:
    type: str
    prefixes: Tuple[str, ...]
    description: str = ""

    def matches(self, base):
        return max((len(p) for p in self.prefixes if base.startswith(p)), default=0)


KEYED_SPECS = [
    KeyedSpec("IPSSignatureSettings", ("idp",), "Intrusion prevention per-signature, per-category and "
              "per-database overrides. Index = signature / category / DB id."),
    KeyedSpec("AntiSpywareSignatureSettings", ("asSigId", "asCatId"), "Anti-spyware enabled signatures and categories."),
    KeyedSpec("AppControlOverrides", ("acApplication", "acUseGlobalLRT"), "App Control per-application overrides."),
    KeyedSpec("LogEventSettings", ("logEvtAttrs",), "Per-event log attributes (priority, colour, email...)."),
    KeyedSpec("DPISSLCategorySettings", ("sslSpyContentCatMask",), "DPI-SSL per-content-category exclusions."),
    KeyedSpec("QoSDSCPMap", ("if_l2cfg_qos_dscpmap",), "DSCP to queue mapping."),
]


# ---------------- Group membership tables ----------------
@dataclass
class GroupSpec:
    prefix: str                         # "<prefix>_atomToGrp" / "<prefix>_grpToGrp"
    link_type: str
    member_types: Tuple[str, ...]
    group_types: Tuple[str, ...]
    synth_member_type: Optional[str] = None   # create built-in member objects if unresolved
    description: str = ""


ADDRESS_TYPES_ALL = ("IPAddress", "IPv6Address", "MACAddress", "FQDNAddress", "AddressGroup")
SERVICE_TYPES_ALL = ("Service", "ServiceGroup")

GROUP_SPECS = [
    GroupSpec("addro", "InAddressGroup", ADDRESS_TYPES_ALL, ("AddressGroup",),
              description="Address (any family) or nested group -> address group"),
    GroupSpec("so", "InServiceGroup", SERVICE_TYPES_ALL, ("ServiceGroup",),
              description="Service or nested service group -> service group"),
    GroupSpec("sched", "InScheduleGroup", ("Schedule", "ScheduleGroup"), ("ScheduleGroup",),
              description="Schedule -> schedule group"),
    GroupSpec("uo", "InUserGroup", ("User", "UserGroup"), ("UserGroup",),
              description="User or nested user group -> user group"),
    GroupSpec("appo", "InAppGroup", ("AppObject", "AppObjectGroup"), ("AppObjectGroup",),
              description="Application object -> application object group"),
    GroupSpec("urlo", "InURLCategoryGroup", ("URLCategoryObject", "URLCategoryGroup", "URLCategory"),
              ("URLCategoryGroup",), synth_member_type="URLCategory",
              description="Web category -> category group (built-in categories are created as URLCategory objects)"),
    GroupSpec("wvo", "InVirtualAPGroup", ("WLANVirtualAP",), ("WLANVirtualAPGroup",),
              description="Virtual AP -> virtual AP group"),
]


# ---------------- Settings (un-indexed keys) ----------------
@dataclass
class SettingsSpec:
    """Global (un-indexed) keys -> one settings object. First matching spec wins."""
    type: str
    name: str
    patterns: Tuple[str, ...]          # regexes matched against the config key (re.match)
    derive: Optional[Callable] = None  # (raw dict) -> OrderedDict of decoded properties
    name_key: Optional[str] = None     # config key that names the object, if any
    description: str = ""

    def matches(self, key):
        return any(re.match(p, key) for p in self.patterns)


def num(raw, key):
    v = raw.get(key, "")
    return int(v) if re.fullmatch(r"-?\d+", v or "") else v


def decode(raw, fields):
    """fields: (property, config key(s), kind) with kind num | bool | nonzero | text.
    A property is only produced when one of its keys exists, so absent settings are never reported as off."""
    out = OrderedDict()
    for prop, keys, kind in fields:
        keys = (keys,) if isinstance(keys, str) else keys
        present = [k for k in keys if k in raw]
        if not present:
            continue
        v = raw[present[0]]
        if kind == "num":
            out[prop] = num(raw, present[0])
        elif kind == "bool":
            out[prop] = any(on(raw[k]) for k in present)
        elif kind == "nonzero":
            out[prop] = v not in ("", "0", "off")
        else:
            out[prop] = v
    return out


PASSWORD_FIELDS = [("MinLength", "minPasswordLength", "num"), ("ComplexityRequired", "passwordComplexity", "nonzero"),
                   ("MinUppercase", "pwdUpperCaseNum", "num"), ("MinLowercase", "pwdLowerCaseNum", "num"),
                   ("MinDigits", "pwdDigitalNum", "num"), ("MinSymbols", "pwdSymbolicNum", "num"),
                   ("ChangeRequiredEvery", "passwordUpdtPeriod", "num"),
                   ("ChangeBlockedFor", "passwordNonUpdtPeriod", "num"), ("HistoryCount", "passwordUniqueNum", "num"),
                   ("MustDifferOnChange", "enablePwdModifyEnforceDiff", "bool"),
                   ("ReloginAfterChange", "reloginAfterPasswordChg", "bool")]
LOGIN_FIELDS = [("LockoutEnabled", "loginFailLockoutEnable", "bool"), ("MaxFailedAttempts", "loginFailMaxRate", "num"),
                ("FailureWindow", "loginFailDuration", "num"), ("LockoutPeriod", "loginFailLockoutTime", "num"),
                ("AccountLockoutEnabled", "loginFailAcctLockoutEnable", "bool"),
                ("CLIMaxAttempts", "loginAttemptCLI", "num")]
ADMIN_FIELDS = [("OTPRequired", ("adminOtpReq", "adminLoginOtpRequire"), "bool"),
                ("TOTPBound", "adminObjTotpBindState", "bool"),
                ("FailedLogins", "adminLoginFailNum", "num"), ("SuccessfulLogins", "adminLoginSuccNum", "num"),
                ("LastLoginTime", "adminLastLoginTime", "text"), ("LastLoginIPv4", "adminLastLoginIpv4", "text")]
USER_FIELDS = [("FailedLogins", "userLoginFailNum", "num"), ("SuccessfulLogins", "userLoginSuccNum", "num"),
               ("LastLoginTime", "userLastLoginTime", "text"), ("LastLoginIPv4", "userLastLoginIpv4", "text"),
               ("OTPRequired", "userObjOtpReq", "bool")]
ADMIN_SETTINGS_FIELDS = [("SessionTimeout", "adminLoginTimeout", "num"), ("MultipleAdminsAllowed", "multipleAdmin", "bool"),
                         ("HTTPManagementAllowed", "allowHttpMgmt", "bool"), ("CLIIdleTimeout", "cli_idleTimeout", "num"),
                         ("APIBasicAuth", "sonicOsApi_basicAuth", "bool"), ("APIDigestAuth", "sonicOsApi_dgstAuth", "bool"),
                         ("APIPublicKeyAuth", "sonicOsApi_pubKeyAuth", "bool")]
USER_AUTH_FIELDS = [("InactivityTimeout", "userInactivity", "num"), ("MaxSessionTime", "userMaxTime", "num"),
                    ("UniqueLoginEnforced", "userLoginEnforceUnique", "bool"),
                    ("UserNamesCaseSensitive", "userNamesCaseSensitive", "bool"),
                    ("RedirectToHTTP", "userRedirectToHttp", "bool")]


def derive_password_policy(raw):
    return decode(raw, PASSWORD_FIELDS)


def derive_login_security(raw):
    return decode(raw, LOGIN_FIELDS)


def derive_admin(raw):
    return decode(raw, ADMIN_FIELDS)


def derive_user(raw):
    return decode(raw, USER_FIELDS)


def derive_admin_settings(raw):
    return decode(raw, ADMIN_SETTINGS_FIELDS)


def derive_user_auth(raw):
    return decode(raw, USER_AUTH_FIELDS)


ADMIN_PATTERNS = (r"^adminName$", r"^adminPass", r"^adminPwd", r"^adminOtp", r"^adminObj", r"^adminClearPass",
                  r"^adminLogin(Otp|Fail|Succ)", r"^adminLast", r"^adminOrig")

SETTINGS_SPECS: List[SettingsSpec] = [
    SettingsSpec("PasswordPolicy", "Password Policy",
                 (r"^password", r"^pwd", r"^minPassword", r"^maxPassword", r"^enablePwd", r"^reloginAfterPassword",
                  r"^applyPwdConstraints$", r"^OtpPwd"), derive_password_policy,
                 description="Local account password rules: length, complexity, character classes, expiry, "
                             "history and which account classes they apply to (`applyPwdConstraints` list)."),
    SettingsSpec("LoginSecurityPolicy", "Login Security",
                 (r"^loginFail", r"^loginAttempt", r"^cmprCredsDtct"), derive_login_security,
                 description="Failed-login lockout and compromised-credential detection."),
    SettingsSpec("AdministratorAccount", "admin", ADMIN_PATTERNS, derive_admin, name_key="adminName",
                 description="The built-in administrator account: name, OTP/TOTP state, login statistics."),
    SettingsSpec("MFASettings", "Multi-Factor Authentication", (r"^[Oo]tp", r"^totp"),
                 description="One-time password / TOTP settings."),
    SettingsSpec("RADIUSSettings", "RADIUS", (r"^[Rr]adius", r"^userRadius", r"^xauthUseRadius", r"^cacUserGroup"),
                 description="Global RADIUS authentication and accounting settings."),
    SettingsSpec("TACACSSettings", "TACACS+", (r"^[Tt]acacs", r"^userTac"),
                 description="Global TACACS+ settings."),
    SettingsSpec("LDAPSettings", "LDAP", (r"^ldap",), description="Global LDAP, TLS, relay and group mirroring settings."),
    SettingsSpec("SSOSettings", "Single Sign-On", (r"^sso", r"^cia", r"^autoLogn", r"^radiusAcctAuth"),
                 description="SSO agents, TSA, NTLM, RADIUS accounting SSO and auto-login bypass settings."),
    SettingsSpec("UserAuthSettings", "User Authentication",
                 (r"^user(?!IV$)", r"^users", r"^logoutAction", r"^logoutUsrs", r"^inactiv", r"^InactivityTimeout",
                  r"^externalUser", r"^unknownUser", r"^showLoginStatus", r"^loginStatus", r"^autoRedirectToAuth",
                  r"^enableHttpsLognRdrct", r"^authPartitionsEnable", r"^guiShow(Unauth|Inactive)Users",
                  r"^authPage", r"^showGuestLoginStatus", r"^guest"), derive_user_auth,
                 description="User login, session, inactivity, acceptable-use and logout settings."),
    SettingsSpec("AdministrationSettings", "Administration",
                 (r"^adminLoginTimeout", r"^adminPreempt", r"^adminMessaging", r"^multipleAdmin", r"^gui",
                  r"^cli", r"^sonicOsApi", r"^ssh(?!Dpi)", r"^https?[A-Z]", r"^allow(Mgmt|Http)",
                  r"^enforceHttpHostCheck", r"^showFwName", r"^loginmessage", r"^useRuleWizard", r"^isEnableHttp",
                  r"^firewall(Name|DnsName)$", r"^autoAppendSuffixName$", r"^tooltip"),
                 derive_admin_settings,
                 description="Management access: web/CLI/SSH/API settings, admin session timeout, banners."),
    SettingsSpec("SSLVPNSettings", "SSL VPN", (r"^[Ss]slvpn",), description="SSL VPN server settings."),
    SettingsSpec("VPNSettings", "VPN", (r"^vpn", r"^ipsec", r"^ike", r"^IdleVpn", r"^L2TP", r"^xauth",
                                         r"^DisableVpnMgmtRules", r"^wg[A-Z]"),
                 description="Global IPsec / IKE / L2TP / WireGuard settings."),
    SettingsSpec("SNMPSettings", "SNMP", (r"^[Ss]nmp",), description="SNMP agent settings."),
    SettingsSpec("LoggingSettings", "Logging", (r"^log", r"^syslog"), description="Log, syslog and log-category settings."),
    SettingsSpec("EmailSettings", "Email", (r"^smtp", r"^mail", r"^email", r"^pop"),
                 description="Mail server used for alerts, OTP and reports."),
    SettingsSpec("TimeSettings", "Time", (r"^ntp", r"^time", r"^tz", r"^dst", r"^useNtp"),
                 description="System time and NTP."),
    SettingsSpec("DNSSettings", "DNS", (r"^dns", r"^v6dns"), description="DNS servers, proxy and caching."),
    SettingsSpec("DHCPSettings", "DHCP", (r"^dhcp",), description="Global DHCP server / relay settings."),
    SettingsSpec("HASettings", "High Availability", (r"^ha[A-Z_]",), description="High availability settings."),
    SettingsSpec("CentralManagementSettings", "Central Management",
                 (r"^gms", r"^globalMgt", r"^sgms", r"^cloud", r"^remoteBkup", r"^npcs", r"^swarm", r"^nsm"),
                 description="GMS / NSM / cloud management and backup."),
    SettingsSpec("GatewayAVSettings", "Gateway Anti-Virus", (r"^gav",), description="Global gateway anti-virus."),
    SettingsSpec("IPSSettings", "Intrusion Prevention", (r"^idp",), description="Global IPS."),
    SettingsSpec("AntiSpywareSettings", "Anti-Spyware", (r"^as[A-Z]", r"^asp"), description="Global anti-spyware."),
    SettingsSpec("AppControlSettings", "App Control", (r"^ac[A-Z]", r"^app[A-Z]", r"^af[A-Z]"),
                 description="Global application control / app rules."),
    SettingsSpec("ContentFilterSettings", "Content Filter", (r"^cfs", r"^cf[A-Z]", r"^webcfs", r"^wse", r"^url"),
                 description="Global content filtering."),
    SettingsSpec("BotnetGeoIPSettings", "Botnet and Geo-IP",
                 (r"^botnet", r"^geo", r"^sysMgmt(Botnet|BlockUnknownGeo|CountryExc)"),
                 description="Botnet filter and Geo-IP filter."),
    SettingsSpec("DPISSLSettings", "DPI-SSL", (r"^ssl", r"^dpi", r"^Dpi(?!Ssh)"), description="DPI-SSL client/server."),
    SettingsSpec("DPISSHSettings", "DPI-SSH", (r"^DpiSsh", r"^sshDpi"), description="DPI-SSH."),
    SettingsSpec("CaptureATPSettings", "Capture ATP", (r"^gcp", r"^sse", r"^capture"), description="Capture ATP sandboxing."),
    SettingsSpec("FloodProtectionSettings", "Flood Protection",
                 (r"^dos", r"^syn", r"^flood", r"^icmp", r"^udp", r"^tcp", r"^[Dd]rop", r"^arp"),
                 description="SYN/UDP/ICMP flood, DoS and TCP/UDP/ICMP handling."),
    SettingsSpec("WirelessSettings", "Wireless", (r"^wlan", r"^sonicPoint", r"^wid", r"^rfm", r"^spg"),
                 description="Wireless controller, WIDS and RF monitoring."),
    SettingsSpec("WANLoadBalancingSettings", "WAN Load Balancing", (r"^wlb",), description="Failover & load balancing."),
    SettingsSpec("RoutingSettings", "Routing", (r"^Z[A-Z]", r"^zebos", r"^rt[A-Z_]"), description="OSPF/RIP/BGP routing."),
    SettingsSpec("AWSSettings", "AWS", (r"^aws",), description="AWS integration (address object mapping, logs)."),
]

GENERIC_FAMILIES = {"enable", "is", "def", "use", "select", "show", "allow", "disable", "max", "min",
                    "last", "global", "num", "has", "do", "no", "un", "Un", "set", "get", "sel"}
MIN_FAMILY_SIZE = 3


def scalar_family(key):
    m = re.match(r"^[a-z0-9]+|^[A-Z][a-z0-9]+|^[A-Z]+(?=[A-Z][a-z]|$|_|\d)", key)
    return m.group(0) if m else key


# --------------------------------------------------------------------------
# Object model
# --------------------------------------------------------------------------

# Short property names that would be confusing inside an object's Properties map
RESERVED_PROPS = {"ObjectName", "Index", "Properties", "Type", "Caption", "ID", "Links", "From", "To"}


@dataclass
class Obj:
    type: str
    caption: str
    props: "OrderedDict[str, object]"
    keys: Dict[str, str] = field(default_factory=dict)
    source: str = ""          # table / spec that produced the object (for docs)
    derived: frozenset = frozenset()   # decoded property names (aliases of raw columns)
    raw: dict = field(default_factory=dict)   # config key -> property holding its value (provenance, not emitted)
    id: int = 0


# ---------------- Automatic discovery of unknown tables ----------------
NAME_COLUMN_RE = re.compile(r"(ObjId|ObjName|Id|ID|Name|_display_name|_name)$")
# Canonical type names for SonicOS 7 object tables recognised by their name column
DISCOVERED_TYPE_HINTS = [
    (r"email", "EmailAddressObject"),
    (r"dhcp.?opt", "DHCPOptionObject"),
    (r"cust(om)?match", "CustomMatchObject"),
    (r"^uri|urilist", "URIListObject"),
    (r"matchpat", "MatchPattern"),
    (r"log.?alert|reportprof|logprof", "LogAlertProfile"),
    (r"aws", "AWSObject"),
    (r"deag|dynext|dyngrp|dynamicgroup", "DynamicExternalGroup"),
    (r"apprule.?act|^act(ion)?obj", "AppRuleActionObject"),
    (r"qos.?mark", "QoSMarkingProfile"),
    (r"pdf", "PDFObject"),
    (r"devprof|devicecat", "DeviceProfileObject"),
    (r"^os", "OSObject"),
    (r"country.?gr", "CountryGroup"),
    (r"winsvcusr", "SSOServiceAccount"),
]


def discovered_type(name_base):
    stem = NAME_COLUMN_RE.sub("", name_base)
    stem = re.sub(r"Obj$", "", stem).rstrip("_")
    low = stem.lower()
    for pat, t in DISCOVERED_TYPE_HINTS:
        if re.search(pat, low):
            return t, stem
    pascal = "".join(w[:1].upper() + w[1:] for w in re.split(r"[_\W]+", stem) if w)
    return (pascal or "Discovered") + "Object", stem


def find_name_column(cfg, bases):
    for b in bases:
        if not NAME_COLUMN_RE.search(b):
            continue
        vals = [v for v in cfg.indexed[b].values() if v]
        if not vals:
            continue
        textual = sum(1 for v in vals if not re.fullmatch(r"[-\d.:]+", v)) / len(vals)
        unique = len(set(vals)) / len(vals)
        if textual >= 0.8 and unique >= 0.7:
            return b
    return None


def build_table_rows(cfg, spec, bases, objects, prop_sources):
    rows = sorted({i for b in bases for i in cfg.indexed[b]})
    for i in rows:
        raw = OrderedDict((b, cfg.indexed[b][i]) for b in bases if i in cfg.indexed[b])
        otype = spec.type_map.get(raw.get(spec.type_field, ""), spec.type) if spec.type_field else spec.type
        name = raw.get(spec.name, "") if spec.name else ""
        if not name:
            name = spec.name_fn(raw, i) if spec.name_fn else f"{otype} {i}"
        props = OrderedDict([("ObjectName", name), ("Index", i)])
        prop_of = {}
        if spec.derive:
            props.update(spec.derive(raw))
        for b, v in raw.items():
            key = spec.prop_key(b)
            if key in props or key in RESERVED_PROPS:   # never shadow standard/derived properties
                key = b
            props[key] = v
            prop_of[b] = key
            prop_sources[otype][key] = b
        derived = frozenset(spec.derive(raw)) if spec.derive else frozenset()
        caption = spec.caption(props) if spec.caption else name
        keys = {k: raw.get(src, "") for k, src in spec.keys.items()}
        if "geobit" in keys:
            bit = country_bit(keys["geobit"])
            keys["geobit"] = "" if bit is None else str(bit)
        obj = Obj(otype, caption, props, keys, source=spec.type, derived=derived)
        for b, v in raw.items():
            obj.raw[f"{b}_{i}"] = prop_of[b]
        objects.append(obj)


def build_objects(cfg: Config):
    objects: List[Obj] = []
    claimed = {}                        # base -> spec
    prop_sources = defaultdict(OrderedDict)
    discovered_specs = []

    group_bases = {f"{gs.prefix}_{s}": gs for gs in GROUP_SPECS for s in ("atomToGrp", "grpToGrp")}
    # any other <prefix>_atomToGrp / <prefix>_grpToGrp pair is a membership table too
    auto_groups = {}
    for base in cfg.indexed:
        m = re.match(r"^(.+)_atomToGrp$", base)
        if m and f"{m.group(1)}_grpToGrp" in cfg.indexed and base not in group_bases:
            auto_groups[m.group(1)] = GroupSpec(m.group(1), "InGroup", (), (),
                                                description="discovered membership table")
    for pfx, gs in auto_groups.items():
        group_bases[f"{pfx}_atomToGrp"] = gs
        group_bases[f"{pfx}_grpToGrp"] = gs

    # ---- assign each indexed base to the most specific spec ----
    for base in cfg.indexed:
        if base in group_bases:
            claimed[base] = group_bases[base]
            continue
        best, best_len = None, 0
        for spec in SPECS + KEYED_SPECS:
            n = spec.matches(base)
            if n > best_len:
                best, best_len = spec, n
        if best:
            claimed[base] = best

    # ---- table specs: one object per row ----
    for spec in SPECS:
        bases = [b for b, sp in claimed.items() if sp is spec]
        if bases:
            build_table_rows(cfg, spec, bases, objects, prop_sources)

    # ---- keyed specs: one object per spec ----
    for kspec in KEYED_SPECS:
        bases = [b for b, sp in claimed.items() if sp is kspec]
        if not bases:
            continue
        props = OrderedDict([("ObjectName", kspec.type)])
        for b in bases:
            props[b] = [f"{k}={v}" for k, v in cfg.indexed[b].items()]
            prop_sources[kspec.type][b] = b
        obj = Obj(kspec.type, kspec.type, props, source=kspec.type)
        obj.raw.update({f"{b}_{k}": b for b in bases for k in cfg.indexed[b]})
        objects.append(obj)

    # ---- built-in web categories from the CFS catalogue ----
    for cid, cname in category_catalogue(cfg).items():
        objects.append(Obj("URLCategory", cname,
                           OrderedDict([("ObjectName", cname), ("CategoryID", cid), ("BuiltIn", True)]),
                           keys={"catid": str(cid)}, source="URLCategory"))

    # ---- settings buckets (scalars, plus single-column lists that belong to a settings area) ----
    buckets = OrderedDict((ss.type, OrderedDict()) for ss in SETTINGS_SPECS)
    family_buckets = OrderedDict()

    def settings_spec_for(key):
        return next((ss for ss in SETTINGS_SPECS if ss.matches(key)), None)

    # ---- discovered object tables: a name column plus every unclaimed column sharing its prefix ----
    unclaimed = [b for b in cfg.indexed if b not in claimed]
    for b in unclaimed:
        if b in claimed or not NAME_COLUMN_RE.search(b):
            continue
        stem = re.sub(r"Obj$", "", NAME_COLUMN_RE.sub("", b)).rstrip("_")
        if len(stem) < 3 or stem.lower().startswith("uuid"):
            continue
        members = [x for x in unclaimed if x not in claimed and x.startswith(stem)]
        if find_name_column(cfg, [b]) != b:
            continue
        rows = {i for x in members for i in cfg.indexed[x]}
        if len(members) < 2:
            continue          # a single column is a list, not an object table
        otype, _stem = discovered_type(b)
        strip = stem + "Obj" if all(x.startswith(stem + "Obj") for x in members) else stem
        spec = TableSpec(otype, tuple(members), name=b, strip=strip, category="Discovered",
                         description=f"Discovered automatically: columns `{stem}*`, named by `{b}`.")
        discovered_specs.append(spec)
        for x in members:
            claimed[x] = spec
        build_table_rows(cfg, spec, members, objects, prop_sources)

    list_sources = defaultdict(dict)       # settings type -> list property -> config keys it holds

    # ---- leftovers: generic tables and lists ----
    clusters = OrderedDict()
    for base, d in cfg.indexed.items():
        if base in claimed:
            continue
        clusters.setdefault((scalar_family(base), min(d), max(d), len(d)), []).append(base)
    for (fam, _lo, _hi, _n), bases in clusters.items():
        if len(bases) == 1:
            b = bases[0]
            values = [f"{k}={v}" for k, v in cfg.indexed[b].items()]
            ss = settings_spec_for(b)
            if ss:
                buckets[ss.type][b] = values
                list_sources[ss.type][b] = [f"{b}_{k}" for k in cfg.indexed[b]]
                continue
            props = OrderedDict([("ObjectName", b), ("Table", fam), ("Values", values)])
            obj = Obj("ConfigList", b, props, source="ConfigList")
            obj.raw.update({f"{b}_{k}": "Values" for k in cfg.indexed[b]})
            objects.append(obj)
            continue
        rows = sorted({i for b in bases for i in cfg.indexed[b]})
        if len(rows) > GENERIC_ROW_LIMIT:
            props = OrderedDict([("ObjectName", f"{fam} table"), ("Table", fam), ("Rows", len(rows))])
            for b in bases:
                props[b] = [f"{k}={v}" for k, v in cfg.indexed[b].items()]
            obj = Obj("ConfigTable", f"{fam} table", props, source="ConfigTable")
            obj.raw.update({f"{b}_{k}": b for b in bases for k in cfg.indexed[b]})
            objects.append(obj)
            continue
        for i in rows:
            props = OrderedDict([("ObjectName", f"{fam}[{i}]"), ("Table", fam), ("Index", i)])
            for b in bases:
                if i in cfg.indexed[b]:
                    props[b] = cfg.indexed[b][i]
            obj = Obj("ConfigTableRow", f"{fam}[{i}]", props, source="ConfigTableRow")
            obj.raw.update({f"{b}_{i}": b for b in bases if i in cfg.indexed[b]})
            objects.append(obj)

    # ---- scalars ----
    for key, value in cfg.scalars.items():
        ss = settings_spec_for(key)
        if ss:
            buckets[ss.type][key] = value
        else:
            family_buckets.setdefault(scalar_family(key), OrderedDict())[key] = value

    for ss in SETTINGS_SPECS:
        raw = buckets[ss.type]
        if not raw:
            continue
        name = raw.get(ss.name_key, "") if ss.name_key else ""
        props = OrderedDict([("ObjectName", name or ss.name)])
        flat = {k: v for k, v in raw.items() if isinstance(v, str)}
        if ss.derive:
            props.update(ss.derive(flat))
        obj = Obj(ss.type, name or ss.name, props, source=ss.type,
                  derived=frozenset(ss.derive(flat)) if ss.derive else frozenset())
        for k, v in raw.items():
            prop = k if k not in props else f"raw_{k}"
            props[prop] = [x for x in v] if isinstance(v, list) else v
            prop_sources[ss.type][k] = k
            if isinstance(v, list):
                obj.raw.update({ck: prop for ck in list_sources[ss.type][k]})
            else:
                obj.raw[k] = prop
        objects.append(obj)

    general = OrderedDict()
    for fam, keys in list(family_buckets.items()):
        if fam in GENERIC_FAMILIES or len(keys) < MIN_FAMILY_SIZE:
            general.update(keys)
            del family_buckets[fam]
    if general:
        family_buckets["General"] = general
    for fam, keys in family_buckets.items():
        props = OrderedDict([("ObjectName", fam)])
        for k, v in keys.items():
            props[k] = v
        obj = Obj("SystemSettings", f"Settings: {fam}", props, source="SystemSettings")
        obj.raw.update({k: k for k in keys})
        objects.append(obj)

    # ---- group membership rows (kept for linking) ----
    memberships = []
    for gs in GROUP_SPECS + list(auto_groups.values()):
        members = cfg.indexed.get(f"{gs.prefix}_atomToGrp", {})
        groups = cfg.indexed.get(f"{gs.prefix}_grpToGrp", {})
        for i in members:
            if i in groups:
                memberships.append((gs, members[i], groups[i]))

    # ---- membership tables mirrored as-is (the links and group member lists are derived from these) ----
    for gs in GROUP_SPECS + list(auto_groups.values()):
        cols = [f"{gs.prefix}_atomToGrp", f"{gs.prefix}_grpToGrp"]
        if not any(c in cfg.indexed for c in cols):
            continue
        props = OrderedDict([("ObjectName", gs.prefix), ("Table", gs.prefix),
                             ("Rows", len(cfg.indexed.get(cols[0], {})))])
        obj = Obj("MembershipTable", f"Membership table {gs.prefix}", props, source="MembershipTable")
        for c in cols:
            props[c] = [f"{k}={v}" for k, v in cfg.indexed.get(c, {}).items()]
            obj.raw.update({f"{c}_{k}": c for k in cfg.indexed.get(c, {})})
        objects.append(obj)

    for n, obj in enumerate(objects, start=1):
        obj.id = n
    return objects, memberships, prop_sources, discovered_specs


DEVICE_KEYS = ("firewallName", "shortProdName", "sourceFirewallModel", "buildNum", "serialNumber",
               "serial", "localeVersionStr", "checksumVersion")


def build_device(cfg: Config):
    props = OrderedDict([("ObjectName", cfg.scalars.get("firewallName", "").strip() or "SonicWall")])
    for k in DEVICE_KEYS:
        if k in cfg.scalars:
            props[k] = cfg.scalars[k]
    return props


# --------------------------------------------------------------------------
# Links
# --------------------------------------------------------------------------

@dataclass
class LinkSpec:
    type: str
    from_types: Tuple[str, ...]
    prop: str                                   # property key on the referencing object
    targets: Tuple[str, ...]                    # allowed target object types
    by: str = "name"                            # "name" (ObjectName) or an object lookup key ("ifnum")
    reverse: bool = False                       # emit target -> referencing object
    pattern: Optional[str] = None               # regex; group 1 is the reference. Non-matching values are skipped
    ignore: Tuple[str, ...] = ()                # values meaning "none" for this field
    loose_at: bool = False                      # also match "name" against "name@domain" targets
    expand: Optional[Callable] = None           # value -> list of references (e.g. bitmap -> bit numbers)
    when: Optional[Callable] = None             # props -> bool; the field is only a reference when this holds
    note: str = ""


ADDR = ADDRESS_TYPES_ALL
SVC = SERVICE_TYPES_ALL
ZONE = ("Zone",)
IFACE = ("Interface",)
SCHED = ("Schedule", "ScheduleGroup")
USERS = ("User", "UserGroup")
APPS = ("AppObject", "AppObjectGroup")
URLCAT = ("URLCategoryObject", "URLCategoryGroup", "URLCategory")
BW = ("BandwidthObject",)
RULES = ("AccessRule", "AccessRuleV6")
NATS = ("NATRule", "NATRuleV6")
WHOM = r"^(?:\d+,)?(.+)$"
ALL_SETTINGS = tuple(ss.type for ss in SETTINGS_SPECS) + ("SystemSettings",)      # user refs are "<type>,<name>" or a bare name; "0" = everyone

LINK_SPECS: List[LinkSpec] = [
    # ---- Access rules ----
    LinkSpec("HasSourceZone", RULES, "SrcZone", ZONE),
    LinkSpec("HasDestinationZone", RULES, "DstZone", ZONE),
    LinkSpec("HasSourceAddress", RULES, "SrcNet", ADDR),
    LinkSpec("HasDestinationAddress", RULES, "DstNet", ADDR),
    LinkSpec("HasSourceService", RULES, "SrcSvc", SVC),
    LinkSpec("HasService", RULES, "DstSvc", SVC),
    LinkSpec("HasSourceInterface", RULES, "SrcIf", IFACE, by="ifnum"),
    LinkSpec("HasDestinationInterface", RULES, "DstIf", IFACE, by="ifnum"),
    LinkSpec("HasSchedule", RULES, "Time", SCHED),
    LinkSpec("AppliesToUser", RULES, "Whom", USERS, pattern=WHOM, ignore=("0",), loose_at=True),
    LinkSpec("ExcludesUser", RULES, "WhomExcl", USERS, pattern=WHOM, ignore=("0",), loose_at=True),
    LinkSpec("HasEgressBandwidth", RULES, "BwmEgrsObj", BW),
    LinkSpec("HasIngressBandwidth", RULES, "BwmIgrsObj", BW),
    LinkSpec("MatchesApplication", RULES, "NgApp", APPS),
    LinkSpec("MatchesURLCategory", RULES, "NgUrl", URLCAT),
    LinkSpec("MatchesWebsite", RULES, "NgUrlx", ("WebsiteObject",)),
    LinkSpec("MatchesCountry", RULES, "NgCountry", ("CountryObject",)),
    LinkSpec("BlocksCountry", RULES, "perPolicyGeoIpBitmap", ("CountryObject",), by="geobit", expand=bitmap_bits,
             note="Per-rule Geo-IP blocklist bitmap (bit = CountryObject BitmapBit)"),
    LinkSpec("HasActionProfile", RULES, "NgAction", ("SecurityActionProfile",)),

    # ---- NAT ----
    LinkSpec("HasOriginalSource", NATS, "OrigSrc", ADDR),
    LinkSpec("HasTranslatedSource", NATS, "TransSrc", ADDR),
    LinkSpec("HasOriginalDestination", NATS, "OrigDst", ADDR),
    LinkSpec("HasTranslatedDestination", NATS, "TransDst", ADDR),
    LinkSpec("HasOriginalService", NATS, "OrigSvc", SVC),
    LinkSpec("HasTranslatedService", NATS, "TransSvc", SVC),
    LinkSpec("HasInboundInterface", NATS, "SrcIface", IFACE, by="ifnum"),
    LinkSpec("HasOutboundInterface", NATS, "DstIface", IFACE, by="ifnum"),

    # ---- Other policies ----
    LinkSpec("HasSourceZone", ("CFSPolicy", "EndpointPolicy", "DNSPolicy"), "SrcZone", ZONE),
    LinkSpec("HasDestinationZone", ("CFSPolicy",), "DstZone", ZONE),
    LinkSpec("IncludesAddress", ("CFSPolicy", "EndpointPolicy"), "InclusionAO", ADDR),
    LinkSpec("ExcludesAddress", ("CFSPolicy", "EndpointPolicy"), "ExclusionAO", ADDR),
    LinkSpec("AppliesToUser", ("CFSPolicy",), "InclWhom", USERS, pattern=WHOM, ignore=("0",), loose_at=True),
    LinkSpec("ExcludesUser", ("CFSPolicy",), "ExclWhom", USERS, pattern=WHOM, ignore=("0",), loose_at=True),
    LinkSpec("HasSchedule", ("CFSPolicy", "DNSPolicy"), "SchedObj", SCHED),
    LinkSpec("UsesProfile", ("CFSPolicy",), "ProfileObj", ("CFSProfile",)),
    LinkSpec("UsesProfile", ("EndpointPolicy",), "ProfileObj", ("EndpointProfile",)),
    LinkSpec("UsesAction", ("CFSPolicy",), "ActionObj", ("CFSAction",)),
    LinkSpec("HasSourceAddress", ("DNSPolicy",), "dnsSrcNet", ADDR),
    LinkSpec("HasService", ("DNSPolicy",), "dnsDstSvc", SVC),
    LinkSpec("HasSourceInterface", ("DNSPolicy",), "SrcIf", IFACE, by="ifnum"),
    LinkSpec("UsesProfile", ("DNSPolicy",), "ProfileName", ("DNSFilterProfile",)),
    LinkSpec("HasSourceAddress", ("RoutePolicy",), "Src", ADDR),
    LinkSpec("HasDestinationAddress", ("RoutePolicy",), "Dst", ADDR),
    LinkSpec("HasService", ("RoutePolicy",), "Svc", SVC),
    LinkSpec("HasGateway", ("RoutePolicy",), "Gw", ADDR),
    LinkSpec("HasGateway", ("RoutePolicy",), "Gw2", ADDR),
    LinkSpec("HasGateway", ("RoutePolicy",), "Gw3", ADDR),
    LinkSpec("HasGateway", ("RoutePolicy",), "Gw4", ADDR),
    LinkSpec("RoutesVia", ("RoutePolicy",), "Iface", IFACE, by="ifnum"),
    LinkSpec("RoutesVia", ("RoutePolicy",), "Iface2", IFACE, by="ifnum"),
    LinkSpec("RoutesVia", ("RoutePolicy",), "Iface3", IFACE, by="ifnum"),
    LinkSpec("RoutesVia", ("RoutePolicy",), "Iface4", IFACE, by="ifnum"),
    LinkSpec("UsesProbe", ("RoutePolicy",), "Probe", ("NetworkMonitorPolicy",)),
    LinkSpec("MatchesApplication", ("RoutePolicy",), "pbrNgApp", APPS),

    # ---- VPN ----
    LinkSpec("HasLocalNetwork", ("VPNPolicy",), "LocalNetwork", ADDR),
    LinkSpec("HasRemoteNetwork", ("VPNPolicy",), "RemoteNetwork", ADDR),
    LinkSpec("HasTranslatedLocalNetwork", ("VPNPolicy",), "NatLocalNetwork", ADDR),
    LinkSpec("HasTranslatedRemoteNetwork", ("VPNPolicy",), "NatRemoteNetwork", ADDR),
    LinkSpec("AuthenticatesGroup", ("VPNPolicy",), "XauthUserGroup", USERS),
    LinkSpec("BoundToZone", ("VPNPolicy",), "BoundToIfnumOrZone", ZONE, pattern=r"^Z_(.+)$",
             note="Value format Z_<zone name>"),
    LinkSpec("BoundToInterface", ("VPNPolicy",), "BoundToIfnumOrZone", IFACE, by="ifnum",
             pattern=r"^I_(\d+)$", note="Value format I_<ifnum>"),

    # ---- Interfaces / zones / addressing ----
    LinkSpec("HasInterface", IFACE, "interface_Zone", ZONE, reverse=True,
             note="Zone -> Interface; IPv4 zone assignment"),
    LinkSpec("HasInterface", IFACE, "interface_Zone6", ZONE, reverse=True,
             note="Zone -> Interface; IPv6 zone assignment (deduplicated with IPv4)"),
    LinkSpec("HasParentInterface", IFACE, "vlan_parent", IFACE, by="ifnum",
             note="VLAN sub-interface -> physical parent"),
    LinkSpec("UsesLLDPProfile", IFACE, "if_l2cfg_l2d_profile", ("LLDPProfile",)),
    LinkSpec("SharesInterfaceSubnet", IFACE, "lan_trans_shared_if", IFACE, by="ifnum",
             when=lambda p: p.get("lan_transparent") == "on",
             note="Transparent Mode: the interface whose subnet this interface shares (only when lan_transparent is on)"),
    *[LinkSpec("HasReconnectSchedule", IFACE, k, SCHED, note="WAN dial-up reconnect schedule")
      for k in ("pppoe_sched_reconnect", "l2tp_sched_reconnect", "pptp_sched_reconnect", "pppoe6_sched_recon")],
    LinkSpec("InZone", ("IPAddress", "IPv6Address", "MACAddress", "FQDNAddress", "AddressGroup"),
             "Zone", ZONE),
    LinkSpec("AppliesToInterface", ("MacIpAntiSpoof", "MacIpAntiSpoofV6"), "Iface", IFACE, by="ifnum"),
    LinkSpec("UsesInterface", ("LoadBalancingMember",), "display_name", IFACE),
    LinkSpec("InLoadBalancingGroup", ("LoadBalancingMember",), "group_name", ("LoadBalancingGroup",)),
    LinkSpec("HasLastResortInterface", ("LoadBalancingGroup",), "lbtype_lastresort", IFACE),
    LinkSpec("MonitorsAddress", ("NetworkMonitorPolicy",), "dstAOHandle", ADDR),
    LinkSpec("HasGateway", ("NetworkMonitorPolicy",), "gwAOHandle", ADDR),
    LinkSpec("HasSourceAddress", ("NetworkMonitorPolicy",), "localIpAOHandle", ADDR),
    LinkSpec("UsesInterface", ("NetworkMonitorPolicy",), "iface", IFACE, by="ifnum"),
    LinkSpec("AcceleratesService", ("WANAccelerationGroup",), "TcpAcSvcHandle", SVC),
    LinkSpec("CachesService", ("WANAccelerationGroup",), "WebCacheServ", SVC),
    LinkSpec("IncludesAddress", ("WANAccelerationGroup",), "WebCacheIncAddr", ADDR),
    LinkSpec("ExcludesAddress", ("WANAccelerationGroup",), "WebCacheExcAddr", ADDR),

    # ---- Security profiles ----
    LinkSpec("BlocksCategory", ("CFSProfile",), "UrlCategoryOpt", ("URLCategory",), by="catid",
             expand=category_flags,
             note="Per-category flag list; position n = category id n+1 (from cfsCategoryStr), 1 = blocked"),
    LinkSpec("AllowsURLList", ("CFSProfile",), "AllowedUrlsObj", ("CFSUrlList",)),
    LinkSpec("ForbidsURLList", ("CFSProfile",), "ForbiddenUrlsObj", ("CFSUrlList",)),
    LinkSpec("UsesReputation", ("CFSProfile",), "ReputationObj", ("CFSReputation",)),
    LinkSpec("ConsentRequiredFor", ("CFSProfile",), "cfsConsentMandatoryAO", ADDR),
    LinkSpec("HasEgressBandwidth", ("CFSAction",), "BwmEgrsObj", BW),
    LinkSpec("HasIngressBandwidth", ("CFSAction",), "BwmIgrsObj", BW),
    LinkSpec("HasEgressBandwidth", ("SecurityActionProfile",), "BwmEgrsObj", BW),
    LinkSpec("HasIngressBandwidth", ("SecurityActionProfile",), "BwmIgrsObj", BW),
    LinkSpec("UsesBlockPage", ("SecurityActionProfile",), "BlockPageObj", ("BlockPage",)),
    # IPS / anti-spyware / GAV profile objects are applied through security action profiles (Policy mode)
    *[LinkSpec("UsesThreatProfile", ("SecurityActionProfile",), k, ("ThreatProfile",), ignore=("on", "off", "0"),
               note="IPS profile applied by the action profile")
      for k in ("Threat", "ThreatPreventObj", "ThreatLogObj", "ThreatPmonObj", "ThreatLogRedObj")],
    *[LinkSpec("UsesAntiSpywareProfile", ("SecurityActionProfile",), k, ("AntiSpywareProfile",),
               ignore=("on", "off", "0"), note="Anti-spyware profile applied by the action profile")
      for k in ("Aspy", "AspyPreventObj", "AspyLogObj", "AspyPmonObj", "AspyLogRedObj")],
    *[LinkSpec("UsesGatewayAVProfile", ("SecurityActionProfile",), k, ("GatewayAVProfile",),
               ignore=("on", "off", "0"), note="Gateway AV profile applied by the action profile")
      for k in ("GavPreventObj", "GavLogObj", "GavPmonObj")],
    LinkSpec("ConsentRequiredFor", ("SecurityActionProfile",), "CfsConsentMdtrAO", ADDR),
    LinkSpec("HasAddress", ("NACDeviceProfile",), "AddrObj", ADDR),
    LinkSpec("HasAddress", ("NACDeviceProfile",), "AddrObjv6", ADDR),
    LinkSpec("HasClientRoute", ("NACDeviceProfile",), "ClientRoutes", ADDR),
    LinkSpec("HasClientRoute", ("NACDeviceProfile",), "Clientv6Routes", ADDR),

    # ---- Users / auth ----
    LinkSpec("HasVPNAccessTo", USERS, "VpnDestNet", ADDR),
    LinkSpec("MirroredFromLDAP", ("UserGroup",), "LdapLocn", ("LDAPGroupTree", "LDAPUserTree")),
    LinkSpec("OnLDAPServer", ("LDAPUserTree", "LDAPGroupTree"), "Srvr", ("LDAPServer",)),
    LinkSpec("BindsInTree", ("LDAPServer",), "BindTree", ("LDAPUserTree", "LDAPGroupTree")),
    LinkSpec("BackupFor", ("LDAPServer",), "BackupFor", ("LDAPServer",)),
    LinkSpec("InPartition", ("LDAPServer",), "AuthPartition", ("AuthPartition",)),
    LinkSpec("InPartition", ("SSOAgent",), "Partition", ("AuthPartition",)),
    LinkSpec("ConfiguresPartition", ("AuthPartitionSettings",), "SettingsPartName", ("AuthPartition",)),
    LinkSpec("ChildOfPartition", ("AuthPartition",), "Parent", ("AuthPartition",)),
    LinkSpec("Bypasses", ("AutoLoginBypass",), "ObjName", ADDR + SVC + ("IPHelperApp",)),
    LinkSpec("ReadView", ("SNMPv3Access",), "rview", ("SNMPv3View",), ignore=("none",)),
    LinkSpec("WriteView", ("SNMPv3Access",), "wview", ("SNMPv3View",), ignore=("none",)),

    # ---- Wireless ----
    LinkSpec("UsesProfile", ("WLANVirtualAP", "WLANVirtualAPGroup"), "ProfileId", ("WLANVirtualAPProfile",)),
    LinkSpec("AllowsMAC", ("WLANVirtualAP",), "AllowAclObjHandle", ADDR),
    LinkSpec("DeniesMAC", ("WLANVirtualAP",), "DenyAclObjHandle", ADDR),
    LinkSpec("ProvisionsVAPGroup", ("SonicPointNProfile",), "VapOGHandle", ("WLANVirtualAPGroup", "WLANVirtualAP")),
    LinkSpec("ProvisionsVAPGroup", ("SonicPointNProfile",), "ssonicPointNVapOGHandle",
             ("WLANVirtualAPGroup", "WLANVirtualAP"), note="Second radio"),
    LinkSpec("HasScanSchedule", ("SonicPointNProfile",), "SchedScan", SCHED),
    LinkSpec("HasScanSchedule", ("SonicPointNProfile",), "ssonicPointNSchedScan", SCHED, note="Second radio"),
    LinkSpec("DeniesMAC", ("SonicPointNProfile",), "spN1DenyAclObjHandle", ADDR),
    LinkSpec("HasOnOffSchedule", ("WLANVirtualAP", "WLANVirtualAPGroup"), "SchedOnOff", SCHED,
             note="Times the virtual AP is broadcast"),
    LinkSpec("HasOnOffSchedule", ("SonicPointNProfile",), "SchedOnOff", SCHED, note="Radio on/off"),
    LinkSpec("HasOnOffSchedule", ("SonicPointNProfile",), "ssonicPointNSchedOnOff", SCHED, note="Second radio on/off"),
    LinkSpec("HasSensorSchedule", ("SonicPointNProfile",), "WIDPSchedSensor", SCHED, note="WIDP sensor schedule"),
    LinkSpec("HasScanSchedule", ("SonicPointProfile",), "ASchedScan", SCHED, note="802.11a radio"),
    LinkSpec("HasScanSchedule", ("SonicPointProfile",), "GSchedScan", SCHED, note="802.11g radio"),
    LinkSpec("HasOnOffSchedule", ("SonicPointProfile",), "ASchedOnOff", SCHED, note="802.11a radio"),
    LinkSpec("HasOnOffSchedule", ("SonicPointProfile",), "GSchedOnOff", SCHED, note="802.11g radio"),
    LinkSpec("ProvisionsWith", ZONE, "SonicPointProfHandle", ("SonicPointProfile",)),
    LinkSpec("ProvisionsWith", ZONE, "SP11NProfHandle", ("SonicPointNProfile",)),
    LinkSpec("ProvisionsWith", ZONE, "SPNDRProfHandle", ("SonicPointNProfile",)),
    LinkSpec("ProvisionsWith", ZONE, "SPACProfHandle", ("SonicPointNProfile",)),
    LinkSpec("ProvisionsWith", ZONE, "SPACW2ProfHandle", ("SonicPointNProfile",)),
    LinkSpec("ProvisionsWith", ZONE, "SPWAVEAXProfHandle", ("SonicPointNProfile",)),
    LinkSpec("WiFiExceptionFor", ZONE, "WiFiExceptionHandle", ADDR),
    LinkSpec("AuthBypassFor", ZONE, "BypassAuthMacObj", ADDR),
    LinkSpec("UsesAAAServer", ZONE, "ExtAAAAServerAo", ADDR),
    LinkSpec("UsesAAAServer", ZONE, "ExtAAAAServer2Ao", ADDR),

    # ---- Global settings referencing objects ----
    *[LinkSpec("ExcludesAddress", ALL_SETTINGS, k, ADDR, note="Global exclusion object")
      for k in ("acExclusionObj", "asExclusionObj", "botnetExcludeObjectName", "ceExclusionObj",
                "cfsExclusionObj", "gavExclusionObj", "geoIpExcludeObjectName", "idpExclusionObj",
                "sslSpyPolObjExID")],
    LinkSpec("IncludesAddress", ALL_SETTINGS, "sslSpyPolObjInID", ADDR, note="DPI-SSL inclusion"),
    LinkSpec("IncludesService", ALL_SETTINGS, "sslSpyPolObjInSvcID", SVC, note="DPI-SSL inclusion"),
    LinkSpec("TrustsAddress", ALL_SETTINGS, "dhcpTrustedAgentObj", ADDR, note="Trusted DHCP relay agents"),
    LinkSpec("AuthorizedAPs", ALL_SETTINGS, "wlanWidsAuthApAddrObjHandle", ADDR),
    LinkSpec("RogueAPs", ALL_SETTINGS, "wlanWidsRogApAddrObjHandle", ADDR),
    LinkSpec("RogueDevices", ALL_SETTINGS, "wlanWidsRogDevIPObjHandle", ADDR),
    *[LinkSpec("UsesService", ALL_SETTINGS, k, SVC, note="ALG / acceleration service")
      for k in ("bandOptTcpAccelSvcHandle", "sipAlgSvcHandle", "ftpAlgSvcHandle")],
    LinkSpec("DefaultUserGroup", ALL_SETTINGS, "radiusDfltUserGroup", USERS, note="Group given to RADIUS users"),
    LinkSpec("AuthenticatesGroup", ALL_SETTINGS, "L2TPsUserGroup", USERS, note="L2TP server users"),
    *[LinkSpec("UsesUserGroup", ALL_SETTINGS, k, USERS, note="LDAP relay legacy group")
      for k in ("ldapRelayLegacyVpnUsrGrp", "ldapRelayLegacyVpnClientGrp", "ldapRelayLegacyL2TPUsrGrp",
                "ldapRelayLegacyInetUsrGrp")],
    LinkSpec("ExcludesService", ALL_SETTINGS, "inactivitySvcObj", SVC, note="Traffic not counted as user activity"),
    LinkSpec("ExcludesAddress", ALL_SETTINGS, "gavHTTPConfigExclusionObj", ADDR),
    LinkSpec("ExcludesAddress", ALL_SETTINGS, "sysMgmtCountryExcHandle", ADDR, note="Geo-IP exclusion"),
    LinkSpec("ExcludesAddress", ALL_SETTINGS, "sshDpiPolObjExID", ADDR, ignore=("None", "All"), note="DPI-SSH exclusion"),
    LinkSpec("IncludesAddress", ALL_SETTINGS, "sshDpiPolObjInID", ADDR, ignore=("None", "All"), note="DPI-SSH inclusion"),
    LinkSpec("ExcludesService", ALL_SETTINGS, "sshDpiPolObjExSvcID", SVC, ignore=("None", "All"), note="DPI-SSH exclusion"),
    LinkSpec("IncludesService", ALL_SETTINGS, "sshDpiPolObjInSvcID", SVC, ignore=("None", "All"), note="DPI-SSH inclusion"),
    LinkSpec("ExcludesUser", ALL_SETTINGS, "sshDpiPolUsrExID", USERS, pattern=r"^(?:\d+\^)?(.+)$",
             ignore=("None", "All"), loose_at=True, note="DPI-SSH exclusion; value `<n>^<name>`"),
    LinkSpec("IncludesUser", ALL_SETTINGS, "sshDpiPolUsrInID", USERS, pattern=r"^(?:\d+\^)?(.+)$",
             ignore=("None", "All"), loose_at=True, note="DPI-SSH inclusion; value `<n>^<name>`"),
    LinkSpec("BlocksCountry", ALL_SETTINGS, "geoInitBitmap", ("CountryObject",), by="geobit", expand=bitmap_bits,
             note="Global Geo-IP blocklist bitmap (bit = CountryObject BitmapBit)"),
    LinkSpec("PrimaryWANInterface", ALL_SETTINGS, "primary_wan_if", IFACE, by="ifnum"),
    LinkSpec("PrimaryWANInterface", ALL_SETTINGS, "wlb_PriWanIf", IFACE, by="ifnum"),
    LinkSpec("HAControlInterface", ALL_SETTINGS, "haControlIf", IFACE, by="ifnum"),
    LinkSpec("HAStateSyncInterface", ALL_SETTINGS, "haStateSyncIf", IFACE, by="ifnum"),
]

STRUCTURAL_LINKS = [
    ("HasInterface", "Device", "Interface", "Every interface belongs to the device"),
    ("HasZone", "Device", "Zone", "Every zone belongs to the device"),
    ("HasAdministrator", "Device", "AdministratorAccount", "The built-in administrator"),
    ("HasUser", "Device", "User", "Every local / imported user"),
    *[("HasSettings", "Device", t, "Global settings area") for t in ALL_SETTINGS if t != "AdministratorAccount"],
]

# (link type, object type, property holding an IPv4 address) -> most specific Interface subnet containing it
SUBNET_LINKS = [
    ("ServedOnInterface", "DHCPScope", "start"),
    ("ServedOnInterface", "DHCPStaticLease", "ip"),
]

# Heuristic links for fields no LinkSpec covers (other firmware, discovered tables)
AUTO_LINK_TOKENS = {"obj", "ao", "handle", "zone", "net", "svc", "service", "sched", "schedule", "grp", "group",
                    "profile", "whom", "user", "list", "action", "act", "gw", "gateway", "dst", "src",
                    "dest", "member", "tree", "partition", "view", "app", "url", "urlx", "country", "excl",
                    "incl", "exclusion", "inclusion", "bwm", "page", "agent"}
NOT_REFERENCEABLE = {"Device", "ConfigTableRow", "ConfigTable", "ConfigList", "MembershipTable", "AccessRule", "AccessRuleV6",
                     "NATRule", "NATRuleV6", "DNSPolicy", "CFSPolicy", "EndpointPolicy", "RoutePolicy",
                     "DHCPScope", "DHCPStaticLease"} | set(ALL_SETTINGS) | {ks.type for ks in KEYED_SPECS}


def as_values(value):
    return value if isinstance(value, list) else [value]


def build_links(objects: List[Obj], memberships, auto_links=True):
    by_type = defaultdict(list)
    name_index = defaultdict(list)       # (type, name) -> [obj]
    loose_index = defaultdict(list)      # (type, name-before-@) -> [obj]
    key_index = defaultdict(list)        # (type, key, value) -> [obj]

    def index(o):
        by_type[o.type].append(o)
        name = o.props.get("ObjectName")
        if isinstance(name, str) and name:
            name_index[(o.type, name)].append(o)
            if "@" in name:
                loose_index[(o.type, name.split("@", 1)[0])].append(o)
        for k, v in o.keys.items():
            if v not in ("", None):
                key_index[(o.type, k, str(v))].append(o)

    for o in objects:
        index(o)

    links, seen, unresolved = [], set(), []

    def add(link_type, value, a, b):
        key = (link_type, a.id, b.id)
        if a.id != b.id and key not in seen:
            seen.add(key)
            links.append((link_type, value, a.id, b.id))

    def resolve(spec, value):
        if spec.by == "name":
            hits = [t for tt in spec.targets for t in name_index.get((tt, value), ())]
            if not hits and spec.loose_at:
                hits = [t for tt in spec.targets for t in loose_index.get((tt, value), ())]
            return hits
        return [t for tt in spec.targets for t in key_index.get((tt, spec.by, value), ())]

    for spec in LINK_SPECS:
        for ftype in spec.from_types:
            for o in by_type.get(ftype, ()):
                if spec.prop not in o.props or (spec.when and not spec.when(o.props)):
                    continue
                values = as_values(o.props[spec.prop])
                if spec.expand:
                    values = [x for v in values for x in spec.expand(str(v))]
                for raw in values:
                    value = str(raw)
                    if (value in NULL_REFS or value in spec.ignore
                            or SENTINEL_RE.match(value) or "\ufffd" in value):
                        continue
                    if spec.pattern:
                        m = re.match(spec.pattern, value)
                        if not m:
                            continue
                        value = m.group(1)
                        if value in spec.ignore or value in NULL_REFS:
                            continue
                    targets = resolve(spec, value)
                    if not targets:
                        unresolved.append((o, spec.prop, value, spec.targets))
                        continue
                    for t in targets:
                        if spec.reverse:
                            add(spec.type, value, t, o)
                        else:
                            add(spec.type, value, o, t)

    # Group membership (member -> group); optionally synthesise built-in members
    next_id = max((o.id for o in objects), default=0) + 1
    synthesized = []
    def any_named(name):
        return [t for (tt, n), objs in name_index.items() if n == name and tt not in NOT_REFERENCEABLE
                for t in objs]

    for gs, member, group in memberships:
        if gs.group_types:
            groups = [t for tt in gs.group_types for t in name_index.get((tt, group), ())]
            members = [t for tt in gs.member_types for t in name_index.get((tt, member), ())]
        else:
            groups, members = any_named(group), any_named(member)
        if not members and gs.synth_member_type:
            obj = Obj(gs.synth_member_type, member,
                      OrderedDict([("ObjectName", member), ("BuiltIn", True)]), source=gs.synth_member_type)
            obj.id = next_id
            next_id += 1
            synthesized.append(obj)
            index(obj)
            members = [obj]
        if not groups:
            unresolved.append((None, f"{gs.prefix}_grpToGrp", group, gs.group_types or ("any",)))
        if not members:
            unresolved.append((None, f"{gs.prefix}_atomToGrp", member, gs.member_types or ("any",)))
        for m in members:
            for g_ in groups:
                add(gs.link_type, member, m, g_)

    # Subnet-derived links: SonicWall binds DHCP scopes / static leases to the interface whose subnet holds them
    import ipaddress
    nets = []
    for o in by_type.get("Interface", ()):
        ip, mask = o.props.get("IPAddress", ""), o.props.get("SubnetMask", "")
        try:
            nets.append((ipaddress.IPv4Network(f"{ip}/{mask}", strict=False), o))
        except (ValueError, TypeError):
            continue
    for link_type, otype, prop in SUBNET_LINKS:
        for o in by_type.get(otype, ()):
            try:
                addr = ipaddress.IPv4Address(str(o.props.get(prop, "")))
            except ValueError:
                continue
            hits = sorted((n for n in nets if addr in n[0]), key=lambda n: -n[0].prefixlen)
            if hits:
                add(link_type, str(addr), o, hits[0][1])

    # Heuristic links: uncovered fields whose value is exactly the name of a referenceable object
    auto_fields = defaultdict(int)
    if auto_links:
        covered = {(ft, ls.prop) for ls in LINK_SPECS for ft in ls.from_types}
        by_name = defaultdict(list)
        for (tt, n), objs in name_index.items():
            if tt not in NOT_REFERENCEABLE:
                by_name[n].extend(objs)
        for o in objects + synthesized:
            if o.type in ("Device", "MembershipTable"):   # membership rows are already the In*Group links
                continue
            own = o.props.get("ObjectName")
            for k, raw_v in o.props.items():
                if k in ("ObjectName", "Index", "Table") or k in o.derived or (o.type, k) in covered:
                    continue
                tokens = {t.lower() for t in KEY_TOKEN_RE.findall(k)}
                if not tokens & AUTO_LINK_TOKENS:
                    continue
                for raw in as_values(raw_v):
                    value = str(raw)
                    if isinstance(raw_v, list) and "=" in value:
                        value = value.split("=", 1)[1]
                    m = re.match(r"^\d+,(.+)$", value)
                    if m:
                        value = m.group(1)
                    if (value == own or value in NULL_REFS or SENTINEL_RE.match(value)
                            or TRIVIAL_VALUE_RE.match(value) or re.fullmatch(r"[\d.:/]+", value)):
                        continue
                    for t in by_name.get(value, ()):
                        if t is not o:
                            add("References", value, o, t)
                            auto_fields[(o.type, k, t.type)] += 1

    # Structural links from the Device root
    for link_type, ftype, ttype, _note in STRUCTURAL_LINKS:
        for root in by_type.get(ftype, ()):
            for t in by_type.get(ttype, ()):
                add(link_type, t.props.get("ObjectName", ""), root, t)

    return links, unresolved, synthesized, auto_fields


# --------------------------------------------------------------------------
# YAML output
# --------------------------------------------------------------------------

YAML_SAFE_KEY = re.compile(r"^[A-Za-z0-9_.\-]+$")


def yaml_scalar(value):
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        return str(value)
    s = "" if value is None else str(value)
    s = s.replace("\u2028", " ").replace("\u2029", " ").replace("\x85", " ")
    return json.dumps(s, ensure_ascii=False)


def yaml_key(key):
    return key if YAML_SAFE_KEY.match(key) else json.dumps(key)


def emit_object(out, o: Obj):
    out.append("  - Object:")
    out.append(f"      Type: {yaml_scalar(o.type)}")
    out.append(f"      Caption: {yaml_scalar(o.caption)}")
    out.append(f"      ID: {o.id}")
    out.append("      Properties:")
    for k, v in o.props.items():
        if isinstance(v, list):
            if not v:
                out.append(f"        {yaml_key(k)}: []")
            else:
                out.append(f"        {yaml_key(k)}:")
                out.extend(f"          - {yaml_scalar(x)}" for x in v)
        else:
            out.append(f"        {yaml_key(k)}: {yaml_scalar(v)}")
    out.append("")


def emit_link(out, link_type, name, a, b):
    out.append("  - Link:")
    out.append(f"      Type: {yaml_scalar(link_type)}")
    out.append("      Properties:")
    out.append(f"        ObjectName: {yaml_scalar(name)}")
    out.append(f"      From: {a}")
    out.append(f"      To: {b}")
    out.append("")


# Property that lists a group's members, per group type (raw member names from the membership table)
GROUP_MEMBER_PROPERTY = {"AddressGroup": "Addresses", "ServiceGroup": "Services", "ScheduleGroup": "Schedules",
                         "UserGroup": "Members", "AppObjectGroup": "Applications", "URLCategoryGroup": "Categories",
                         "WLANVirtualAPGroup": "VirtualAPs"}


def add_group_members(objects, memberships):
    """Write each group's members onto the group object, in configuration order, so the group node itself
    shows its contents. Names are copied exactly as configured, including members that resolve to no object."""
    names = defaultdict(list)
    for gs, member, group in memberships:
        names[(gs.prefix, group)].append(member)
    by_name = defaultdict(list)
    for o in objects:
        by_name[o.props.get("ObjectName")].append(o)
    for gs in GROUP_SPECS + [g for g, _m, _g in memberships if g not in GROUP_SPECS]:
        for (prefix, group), members in names.items():
            if prefix != gs.prefix:
                continue
            targets = [o for o in by_name.get(group, ()) if not gs.group_types or o.type in gs.group_types]
            for o in targets:
                prop = GROUP_MEMBER_PROPERTY.get(o.type, "Members")
                if prop not in o.props:
                    o.props[prop] = list(members)
                    o.props[prop + "Count"] = len(members)
    for o in objects:                                   # groups with no membership rows: explicit empty list
        prop = GROUP_MEMBER_PROPERTY.get(o.type)
        if prop and prop not in o.props:
            o.props[prop] = []
            o.props[prop + "Count"] = 0


def parse(path, auto_links=True):
    cfg = Config.load(path)
    objects, memberships, prop_sources, discovered = build_objects(cfg)
    add_group_members(objects, memberships)
    device = Obj("Device", "", build_device(cfg), source="Device")
    device.caption = f"{device.props['ObjectName']} ({cfg.scalars.get('shortProdName', 'SonicWall')})"
    objects.insert(0, device)
    for n, o in enumerate(objects, start=1):
        o.id = n
    links, unresolved, synthesized, auto_fields = build_links(objects, memberships, auto_links)
    objects.extend(synthesized)
    return cfg, objects, links, unresolved, prop_sources, discovered, auto_fields


def render_yaml(objects, links):
    out = [META_YAML.format(version=PARSER_VERSION), "Objects:", ""]
    for o in objects:
        emit_object(out, o)
    out.append("Links:")
    out.append("")
    for link in links:
        emit_link(out, *link)
    return "\n".join(out).rstrip() + "\n"


def report(objects, links, unresolved, stream=sys.stderr, limit=40):
    counts = defaultdict(int)
    for o in objects:
        counts[o.type] += 1
    lcounts = defaultdict(int)
    for lt, *_ in links:
        lcounts[lt] += 1
    print(f"objects: {len(objects)} across {len(counts)} types", file=stream)
    print(f"links:   {len(links)} across {len(lcounts)} types", file=stream)
    for lt, n in sorted(lcounts.items(), key=lambda x: -x[1]):
        print(f"  {lt:28} {n}", file=stream)
    if unresolved:
        print(f"unresolved references: {len(unresolved)}", file=stream)
        for o, prop, value, targets in unresolved[:limit]:
            where = f"{o.type} ID {o.id}" if o else "group table"
            print(f"  {where}: {prop} = {value!r} (looked in {', '.join(targets)})", file=stream)
        if len(unresolved) > limit:
            print(f"  ... {len(unresolved) - limit} more (use --all-unresolved)", file=stream)


# --------------------------------------------------------------------------
# Documentation generator (--doc)
# --------------------------------------------------------------------------

DERIVED_DOCS = {
    "AccessRule": [
        ("ActionName", "`Action` decoded: 0 Deny, 1 Discard, 2 Allow"),
        ("Enabled", "Boolean from `Enabled`"),
        ("SourceZone / DestZone", "Copies of `SrcZone` / `DstZone`"),
        ("SourceNet / DestNet", "`SrcNet` / `DstNet`, empty shown as `Any`"),
        ("SourceService / DestService", "`SrcSvc` / `DstSvc`, empty shown as `Any`"),
    ],
    "NATRule": [
        ("Enabled / Reflexive", "Booleans"),
        ("OriginalSource / OriginalDest / OriginalService", "`OrigSrc` / `OrigDst` / `OrigSvc`, empty shown as `Any`"),
        ("TranslatedSource / TranslatedDest / TranslatedService",
         "`TransSrc` / `TransDst` / `TransSvc`, empty shown as `Original`"),
    ],
    "IPAddress": [("AddressType", "Host, Range or Network (from `Type`: 1, 2, 4)"), ("Family", "`IPv4`")],
    "IPv6Address": [("AddressType", "Host, Range or Network (from `Type`: 512, 1024, 2048)"), ("Family", "`IPv6`")],
    "AddressGroup": [("AddressType", "`Group`"), ("Family", "`IPv4` or `IPv6`: the table the group row came from")],
    "MACAddress": [("AddressType", "`MAC`")],
    "FQDNAddress": [("AddressType", "`FQDN`")],
    "Service": [("ProtocolName", "IP protocol decoded from `IpType` (TCP, UDP, ICMP, GRE, ESP, ...)")],
    "ServiceGroup": [("ProtocolName", "`Group`")],
    "Schedule": [
        ("Days", "List of weekdays from the `DaysOfWeek` bitmask (bit 0 = Sun ... bit 6 = Sat)"),
        ("StartTime / EndTime", "`TimeBegin` / `TimeEnd`, minutes after midnight, as HH:MM"),
        ("OneTimeStart / OneTimeEnd", "Only for one-time schedules: the `Start*` / `End*` date fields"),
    ],
    "Interface": [
        ("IPAddress / SubnetMask", "First non-zero of `lan_ip`, `static_ip`, `mgmt_ip`, with its mask"),
        ("Zone", "Copy of `interface_Zone`"),
        ("IsVLAN", "True for VLAN sub-interfaces (`phys_type` 2, or interface number >= 0x10000000)"),
    ],
    "User": [
        ("FailedLogins / SuccessfulLogins", "Login counters (`userLoginFailNum`, `userLoginSuccNum`)"),
        ("LastLoginTime / LastLoginIPv4", "From `userLastLoginTime`, `userLastLoginIpv4`"),
        ("OTPRequired", "From `userObjOtpReq`"),
    ],
    "PasswordPolicy": [
        ("MinLength", "`minPasswordLength`"),
        ("ComplexityRequired", "`passwordComplexity` is non-zero"),
        ("MinUppercase / MinLowercase / MinDigits / MinSymbols",
         "`pwdUpperCaseNum`, `pwdLowerCaseNum`, `pwdDigitalNum`, `pwdSymbolicNum`"),
        ("ChangeRequiredEvery", "`passwordUpdtPeriod` (0 = never), in the unit the UI shows"),
        ("ChangeBlockedFor", "`passwordNonUpdtPeriod`: minimum time before a password can be changed again"),
        ("HistoryCount", "`passwordUniqueNum`: how many previous passwords cannot be reused"),
        ("MustDifferOnChange", "`enablePwdModifyEnforceDiff`"),
        ("ReloginAfterChange", "`reloginAfterPasswordChg`"),
        ("applyPwdConstraints", "Raw list `<account class>=on/off`: which account classes the rules apply to"),
    ],
    "LoginSecurityPolicy": [
        ("LockoutEnabled", "`loginFailLockoutEnable`"),
        ("MaxFailedAttempts", "`loginFailMaxRate`: failed attempts allowed within the window"),
        ("FailureWindow", "`loginFailDuration`"),
        ("LockoutPeriod", "`loginFailLockoutTime`"),
        ("AccountLockoutEnabled", "`loginFailAcctLockoutEnable`: lock the account, not only the source IP"),
        ("CLIMaxAttempts", "`loginAttemptCLI`"),
    ],
    "AdministratorAccount": [
        ("OTPRequired", "`adminOtpReq` or `adminLoginOtpRequire`"),
        ("TOTPBound", "`adminObjTotpBindState`"),
        ("FailedLogins / SuccessfulLogins", "`adminLoginFailNum`, `adminLoginSuccNum`"),
        ("LastLoginTime / LastLoginIPv4", "`adminLastLoginTime`, `adminLastLoginIpv4`"),
    ],
    "AdministrationSettings": [
        ("SessionTimeout", "`adminLoginTimeout`"),
        ("MultipleAdminsAllowed", "`multipleAdmin`"),
        ("HTTPManagementAllowed", "`allowHttpMgmt`"),
        ("CLIIdleTimeout", "`cli_idleTimeout`"),
        ("APIBasicAuth / APIDigestAuth / APIPublicKeyAuth", "SonicOS API authentication methods enabled"),
    ],
    "UserAuthSettings": [
        ("InactivityTimeout", "`userInactivity`"),
        ("MaxSessionTime", "`userMaxTime`"),
        ("UniqueLoginEnforced", "`userLoginEnforceUnique`"),
        ("UserNamesCaseSensitive", "`userNamesCaseSensitive`"),
        ("RedirectToHTTP", "`userRedirectToHttp`"),
    ],
}
for _gt, _prop in {"AddressGroup": "Addresses", "ServiceGroup": "Services", "ScheduleGroup": "Schedules",
                   "UserGroup": "Members", "AppObjectGroup": "Applications", "URLCategoryGroup": "Categories",
                   "WLANVirtualAPGroup": "VirtualAPs"}.items():
    DERIVED_DOCS.setdefault(_gt, []).append(
        (f"{_prop} / {_prop}Count", "Member names exactly as listed in the group's membership table "
         "(`<prefix>_atomToGrp` rows whose `<prefix>_grpToGrp` is this group), in configuration order, and their count. "
         "Empty list when the group has no members."))
DERIVED_DOCS["AccessRuleV6"] = DERIVED_DOCS["AccessRule"]
DERIVED_DOCS["NATRuleV6"] = DERIVED_DOCS["NATRule"]

SPLIT_TYPE_DESCRIPTIONS = {
    "AddressGroup": "Address group (IPv4 or IPv6 table row with type 8). Members come from the `addro_` "
                    "membership table and can be any address type, including nested groups.",
    "ServiceGroup": "Service group (`svcObjType=2`). Members come from the `so_` membership table.",
    "ScheduleGroup": "Schedule group (`schedObjType=2`). Members come from the `sched_` membership table.",
    "AppObjectGroup": "Application object group (`appObjType=2`). Members come from the `appo_` table.",
    "URLCategoryGroup": "Web category group (`urlObjType=2`). Members (built-in categories) come from the "
                        "`urlo_` table.",
    "WLANVirtualAPGroup": "Virtual AP group (`wlanVapObjType=1`), provisioned to SonicPoints. Members come "
                          "from the `wvo_` table.",
    "WLANVirtualAPProfile": "Virtual AP security profile (`wlanVapObjType=4`) used by virtual APs.",
}

# SonicOS 7.0 "Objects" guide sections -> parser types.
# Declared = key names confirmed against a SonicOS 7 export; Discovered = created by table discovery
# (the table needs a name column), with the canonical type name chosen by DISCOVERED_TYPE_HINTS.
SONICOS7_COVERAGE = [
    ("Match Objects", "Zones", "Zone", "Declared"),
    ("Match Objects", "Addresses: objects (host, range, network, IPv6, MAC, FQDN)",
     "IPAddress, IPv6Address, MACAddress, FQDNAddress", "Declared"),
    ("Match Objects", "Addresses: groups", "AddressGroup + InAddressGroup links", "Declared"),
    ("Match Objects", "Addresses: dynamic (MAC / FQDN DAOs)", "MACAddress, FQDNAddress", "Declared"),
    ("Match Objects", "Services: objects, custom IP protocols", "Service", "Declared"),
    ("Match Objects", "Services: groups", "ServiceGroup + InServiceGroup links", "Declared"),
    ("Match Objects", "URI Lists: objects and groups", "URIListObject (+ InGroup links)", "Discovered"),
    ("Match Objects", "Schedules", "Schedule, ScheduleGroup", "Declared"),
    ("Match Objects", "Dynamic Group (DEAG / DEAO)", "ExternalGroup", "Declared"),
    ("Match Objects", "Email Addresses", "EmailAddressObject", "Discovered"),
    ("Match Objects", "Match Objects (app rules)", "AppFirewallObject", "Declared"),
    ("Match Objects", "Application objects / category objects", "AppObject", "Declared"),
    ("Match Objects", "Countries: objects", "CountryObject", "Declared"),
    ("Match Objects", "Countries: groups", "CountryGroup (+ InGroup links)", "Discovered"),
    ("Match Objects", "Applications: groups", "AppObjectGroup + InAppGroup links", "Declared"),
    ("Match Objects", "Web Categories: objects and groups",
     "URLCategory (from the `cfsCategoryStr` catalogue), URLCategoryGroup; CFSProfile BlocksCategory links", "Declared"),
    ("Match Objects", "Websites: objects", "WebsiteObject", "Declared"),
    ("Match Objects", "Websites: groups", "InGroup links from a discovered membership table", "Discovered"),
    ("Match Objects", "Match Patterns", "MatchPattern", "Discovered"),
    ("Match Objects", "Custom Match: objects and groups", "CustomMatchObject (+ InGroup links)", "Discovered"),
    ("Profile Objects", "Endpoint Security", "EndpointProfile, EndpointPolicy, EndpointService", "Declared"),
    ("Profile Objects", "Bandwidth", "BandwidthObject", "Declared"),
    ("Profile Objects", "QoS Marking", "Properties on AccessRule (`Qos*`) and SecurityActionProfile (`Qos*`)", "Declared"),
    ("Profile Objects", "Content Filter profiles", "CFSProfile, CFSUrlList, CFSReputation, CFSCustomCategory", "Declared"),
    ("Profile Objects", "DHCP Option objects", "DHCPOptionObject", "Discovered"),
    ("Profile Objects", "Block Page", "BlockPage", "Declared"),
    ("Profile Objects", "Anti-Spyware profiles", "AntiSpywareProfile", "Declared"),
    ("Profile Objects", "Gateway Anti-Virus profiles", "GatewayAVProfile", "Declared"),
    ("Profile Objects", "Log and Alerts profiles", "LogAlertProfile", "Discovered"),
    ("Profile Objects", "Intrusion Prevention profiles", "ThreatProfile", "Declared"),
    ("Profile Objects", "AWS", "AWSSettings (+ AWSObject if the export has an AWS mapping table)", "Declared / Discovered"),
    ("Action Profiles", "Security Action Profile", "SecurityActionProfile", "Declared"),
    ("Action Profiles", "DoS Action Profile", "DoSActionProfile", "Declared"),
    ("Action Objects", "App Rule Actions", "AppRuleActionObject", "Discovered"),
    ("Action Objects", "Content Filter Actions", "CFSAction", "Declared"),
    ("Object Viewer", "UI view of the above, no config of its own", "n/a", "n/a"),
]

EXTRA_COVERAGE = [
    ("Users", "Local and LDAP users, user groups, guest profiles", "User, UserGroup, GuestProfile", "Declared"),
    ("Users", "Built-in administrator", "AdministratorAccount", "Declared"),
    ("Users", "Password policy", "PasswordPolicy", "Declared"),
    ("Users", "Login lockout, compromised-credential detection", "LoginSecurityPolicy", "Declared"),
    ("Users", "MFA / OTP, RADIUS, TACACS+, LDAP, SSO", "MFASettings, RADIUSSettings, TACACSSettings, LDAPSettings, "
     "SSOSettings, LDAPServer, LDAPUserTree, LDAPGroupTree, SSOAgent, AuthPartition", "Declared"),
    ("Users", "User session / login settings", "UserAuthSettings", "Declared"),
    ("Device", "Management access (HTTPS, SSH, CLI, API)", "AdministrationSettings, per-Interface `*_mgmt` properties", "Declared"),
    ("Policy", "Access rules (IPv4 / IPv6)", "AccessRule, AccessRuleV6", "Declared"),
    ("Policy", "NAT (IPv4 / IPv6)", "NATRule, NATRuleV6", "Declared"),
    ("Policy", "Routing, VPN, DNS, CFS, endpoint policies", "RoutePolicy, VPNPolicy, DNSPolicy, CFSPolicy, EndpointPolicy",
     "Declared"),
    ("Network", "Interfaces, VLANs, load balancing, DHCP, IP helper, network monitor",
     "Interface, LoadBalancingGroup/Member, DHCPScope, DHCPStaticLease, IPHelperApp, NetworkMonitorPolicy", "Declared"),
    ("System", "All other global settings", "One *Settings type per area (see section 6), rest in SystemSettings",
     "Declared"),
]

CATEGORY_ORDER = ["Network", "Objects", "Policies", "Security", "Users", "Wireless", "Switching", "Other"]


def md_escape(text):
    return str(text).replace("|", "\\|")


def render_docs(cfg=None, objects=None, prop_sources=None, discovered=None, auto_fields=None):
    spec_types = OrderedDict()
    for spec in SPECS:
        for t in [spec.type] + list(spec.type_map.values()):
            spec_types.setdefault(t, []).append(spec)

    def tnames(types):
        types = tuple(types)
        if not types:
            return "any named object"
        if set(types) == set(ADDR):
            return "any address type"
        if set(ADDR) < set(types):
            return "any address type/" + "/".join(t for t in types if t not in ADDR)
        if set(types) == set(ALL_SETTINGS):
            return "any settings type"
        return "/".join(types)

    def via(ls):
        return "ObjectName" if ls.by == "name" else ls.by

    def settings_owner(key):
        ss = next((x for x in SETTINGS_SPECS if x.matches(key)), None)
        return ss.type if ss else "SystemSettings"

    def applies(ls, t):
        if tuple(ls.from_types) == ALL_SETTINGS:
            return settings_owner(ls.prop) == t
        return t in ls.from_types

    def out_links(t):
        rows = []
        for ls in LINK_SPECS:
            if applies(ls, t) and not ls.reverse:
                rows.append(f"{ls.type} -> {tnames(ls.targets)} (`{ls.prop}` = target {via(ls)})")
            if t in ls.targets and ls.reverse:
                rows.append(f"{ls.type} -> {tnames(ls.from_types)} (their `{ls.prop}` = this {via(ls)})")
        for gs in GROUP_SPECS:
            if t in gs.member_types:
                rows.append(f"{gs.link_type} -> {tnames(gs.group_types)} (`{gs.prefix}_atomToGrp`/`{gs.prefix}_grpToGrp`)")
        rows += [f"{lt} -> {tt}" for lt, f, tt, _n in STRUCTURAL_LINKS if f == t]
        return list(OrderedDict.fromkeys(rows))

    def in_links(t):
        rows = []
        for ls in LINK_SPECS:
            if t in ls.targets and not ls.reverse:
                src = settings_owner(ls.prop) if tuple(ls.from_types) == ALL_SETTINGS else tnames(ls.from_types)
                rows.append(f"{ls.type} from {src} `{ls.prop}`")
            if t in ls.from_types and ls.reverse:
                rows.append(f"{ls.type} from {tnames(ls.targets)} (this object's `{ls.prop}`)")
        for gs in GROUP_SPECS:
            if t in gs.group_types:
                rows.append(f"{gs.link_type} from {tnames(gs.member_types)} (`{gs.prefix}_*` membership)")
        rows += [f"{lt} from {f}" for lt, f, tt, _n in STRUCTURAL_LINKS if tt == t]
        return list(OrderedDict.fromkeys(rows))

    def match_desc(ls):
        how = ("`ObjectName`" if ls.by == "name" else
               "Interface `ifnum`" if ls.by == "ifnum" else
               "CountryObject `BitmapBit` (one link per set bit, MSB-first)" if ls.by == "geobit" else
               "URLCategory `CategoryID` (one link per flag set to 1)" if ls.by == "catid" else f"`{ls.by}` key")
        extra = []
        if ls.pattern:
            extra.append(f"value parsed with `{ls.pattern}`")
        if ls.loose_at:
            extra.append("also matches `name@domain`")
        if ls.ignore:
            extra.append("ignores " + ", ".join(f"`{v}`" for v in ls.ignore))
        return how + (" (" + "; ".join(extra) + ")" if extra else "")

    def links_block(t, w):
        ol, il = out_links(t), in_links(t)
        if ol:
            w("- **Links out:**")
            for row in ol:
                w(f"  - {row}")
        if il:
            w("- **Links in:**")
            for row in il:
                w(f"  - {row}")

    L = []
    w = L.append
    w("# SonicWall Parser: Object and Link Reference\n")
    w(f"Parser version {PARSER_VERSION}. This reference describes how *any* SonicWall configuration export is "
      "turned into RuleHound objects and links. It is generated from the parser's own rule tables, so it always "
      "matches the code. Run `sonicwall_parser.py --doc FILE` to regenerate it; add a config "
      "(`sonicwall_parser.py config.exp -o out.yaml --doc FILE`) to append a coverage report for that config.\n")

    w("## 1. Supported input\n")
    w("- **Base64 `.exp` export** (System > Settings > Export): decoded, split on `&`, values URL-decoded.")
    w("- **Decoded plaintext dump**: `key=value` lines, values used literally. Some values span several lines "
      "(CFS URL lists hold one domain per line; block, confirm, login and SSL VPN portal pages hold HTML documents "
      "with blank lines and script lines that look like keys). A line starts a new key only when it matches the "
      "SonicWall key pattern (a letter, then letters, digits or underscores, then `=`) and no HTML document opened "
      "by `<html` or `<!DOCTYPE` is still open; every other line, blank or not, belongs to the current value. "
      "Joining the parsed pairs reproduces the file byte for byte.")
    w("- The format is detected automatically (two or more `key=value` lines in the first 50 means plaintext).")
    w("- SonicOS 6.x and 7.x exports share the same key format. Keys the parser does not know are never dropped "
      "(see sections 2.6 and 3.4).\n")

    w("## 2. How objects are extracted\n")
    w("### 2.1 Keys\nA key ending in `_<number>` is a table cell: `addrObjId_12=WEB_SERVER` is column `addrObjId`, "
      "row 12. Every other key is a global setting.\n")
    w("### 2.2 Declared tables\nEach column is given to the declared type (section 5) whose key prefix matches it "
      "most specifically, so `addrObjFqdnId` goes to FQDNAddress, not IPAddress. All columns of a type with the "
      "same row number form one object. Several SonicWall tables can feed one type: every per-interface table "
      "(Ethernet, HA, OSPF/RIP, management, PPPoE, link aggregation) becomes part of the Interface object with "
      "the same row.\n")
    w("### 2.3 IPv6 tables\nIPv6 rule tables reuse the IPv4 column names with a `V6` suffix (`policySrcZoneV6`). "
      "They become the separate `...V6` types and the suffix is removed from property names.\n")
    w("### 2.4 Type splits\nSome tables hold objects and groups together. The type column decides the object "
      "type: `addrObjType=8` -> AddressGroup, `svcObjType=2` -> ServiceGroup, `schedObjType=2` -> ScheduleGroup, "
      "`appObjType=2` -> AppObjectGroup, `urlObjType=2` -> URLCategoryGroup, `wlanVapObjType` 1/4 -> "
      "WLANVirtualAPGroup / WLANVirtualAPProfile.\n")
    w("### 2.5 Properties\n")
    w("| Property | Meaning |\n|---|---|")
    w("| `ObjectName` | The object's name from its name column (generated when a table has none). Links match on it. |")
    w("| `Index` | Row number in the SonicWall table (table types only). |")
    w("| decoded properties | Readable values added by the parser, listed per type. |")
    w("| raw properties | Every column of the row with the type's prefix removed (`policySrcZone` -> `SrcZone`). "
      "A column keeps its full key when it does not start with the prefix, or when the short name would clash "
      "with a standard or decoded property or a confusing name such as `Type`. Values are strings exactly as "
      "configured. |\n")
    w("### 2.6 Discovered tables\nA table that no declared type claims is checked for a name column: a column "
      "ending in `Id`, `ObjId`, `Name` or `_name`, sharing the table's key prefix, whose values are mostly unique "
      "and non-numeric. If found, every row becomes an object. The type name comes from the name column "
      "(`emailObjId` -> EmailAddressObject via the hint list below, otherwise `<Prefix>Object`). This is how "
      "SonicOS object types that are not declared, or that only exist on other firmware, still become real "
      "objects with names that links can resolve.\n")
    w("| Name column contains | Type |\n|---|---|")
    for pat, t in DISCOVERED_TYPE_HINTS:
        w(f"| `{md_escape(pat)}` (regex, case-insensitive) | {t} |")
    w("")
    w("### 2.7 Global settings\nUn-indexed keys are grouped into settings objects by area (section 6): the first "
      "settings type whose key patterns match the key wins. Single-column tables that match a settings area "
      "(for example `applyPwdConstraints_<n>`) are added to it as a `row=value` list. Keys that match no area "
      "go to SystemSettings objects grouped by the key's leading word.\n")
    w("### 2.8 Catch-all\nAnything still unclaimed becomes `ConfigTableRow` (one object per row), `ConfigTable` "
      f"(one object when a table has more than {GENERIC_ROW_LIMIT} rows) or `ConfigList` (single-column table). "
      "Signature- and category-keyed tables become one object each (section 7). Nothing in the config is dropped.\n")
    w("### 2.8b Every row is kept\nEvery row of every table is mirrored, including pre-allocated rows that hold only "
      "default values (unused managed-switch accounts, WWAN profiles, ClearPass servers). Nothing in the "
      "configuration is filtered out.\n")
    w("### 2.9 Raw values\nEvery value is written exactly as it appears in the export, including passwords, "
      "keys and SonicWall-encrypted values (`<n>,<hex>`). Nothing is redacted or rewritten; decoded properties "
      "are added alongside the raw columns, never in place of them.\n")
    w("### 2.10 IDs\nObjects are numbered from 1: Device first, then declared tables, keyed tables, discovered and "
      "generic tables, settings, then built-in objects created during linking.\n")

    w("## 3. How links are extracted\n")
    w("### 3.1 Declared links\nEvery link rule (section 8) says: *for objects of type A, take property P; if its "
      "value equals the `ObjectName` of an object of one of the allowed target types, create a link A -> target*. "
      "Interfaces are referenced by interface number, so those rules match the Interface `ifnum` property. "
      "VLAN sub-interfaces have encoded numbers (`0x10000000 + (vlan << 8) + parent`).\n")
    w("- **Direction**: from the object holding the reference to the object referenced. Rules marked "
      "*reversed* point the other way where it reads more naturally (Zone -> Interface).")
    w("- **Link properties**: `ObjectName` is the value that matched.")
    w("- **Allowed targets only**: a value is matched only against the listed types, so a zone and a service "
      "with the same name cannot be confused.")
    w("- **Ignored values**: empty, `-1`, `4294967295` (SonicWall \"any\"), sentinels like "
      "`__RemoteNatUseOriginalAddress__`, plus per-rule values such as `0`, `None`, `All`.")
    w("- **Encoded values**: `Z_<zone>` / `I_<ifnum>` (VPN binding), `<n>,<name>` and `<n>^<name>` (users) are "
      "parsed before matching. User references also match imported `name@domain` groups.\n")
    w("### 3.1b Encoded references\nGeo-IP blocklists are hex bitmaps, not names. `geoInitBitmap` (global) and "
      "`perPolicyGeoIpBitmap` (per rule) produce one `BlocksCountry` link per set bit. Bit *n*, read MSB-first "
      "within each byte, is the country whose `countryObjIndex` has *n* in its low 16 bits; the high bytes hold "
      "the ISO code reversed, exposed as `CountryCode`.\n")
    w("CFS profiles select web categories positionally: `cfsProfileUrlCategoryOpt` is a comma-separated flag "
      "list where position *n* is category id *n+1* and `1` means blocked. Each flag set to 1 produces a "
      "`BlocksCategory` link from the CFSProfile to that URLCategory.\n")
    w("### 3.1c Subnet-derived links\nSonicWall binds DHCP scopes and static leases to the interface whose subnet "
      "contains them; there is no interface field. The parser does the same: " +
      "; ".join(f"{t}.`{p}` -> most specific Interface subnet ({lt})" for lt, t, p in SUBNET_LINKS) + ".\n")
    w("### 3.2 Group membership\nSonicWall stores membership in two-column tables: `<prefix>_atomToGrp` (member) "
      "and `<prefix>_grpToGrp` (group). Each row is a member -> group link. Known tables use the typed link "
      "names in section 8. **Any other** `<prefix>_atomToGrp` / `<prefix>_grpToGrp` pair (URI list groups, "
      "website groups, country groups, custom match groups, ...) produces `InGroup` links, resolving member "
      "and group names against every named object. Built-in web categories referenced by category groups are "
      "created as `URLCategory` objects with `BuiltIn: true`.\n")
    w("### 3.3 Structural links\n" + "; ".join(sorted({f"Device {lt} -> {tt}" for lt, f, tt, _n in STRUCTURAL_LINKS
                                                    if tt not in ALL_SETTINGS}))
      + "; Device HasSettings -> every settings object. These let several firewalls share one graph.\n")
    w("### 3.4 Heuristic links\nTo cover firmware and tables the rules do not know, every property that no "
      "declared rule covers is also checked: if its key contains a reference word (" +
      ", ".join(f"`{t}`" for t in sorted(AUTO_LINK_TOKENS)) +
      ") and its value is exactly the name of a named object (not a rule, setting or catch-all), a `References` "
      "link is created. Decoded properties, numbers, IPs and the object's own name are never used. "
      "`--discover` lists which fields produced them; `--no-auto-links` turns them off.\n")
    w("### 3.5 Unresolved references\nA declared reference whose value matches nothing is listed on stderr, "
      "never guessed.\n")
    w("### 3.6 Objects without links\nAn object can legitimately have no links. `--orphans` classifies every type "
      "that has unlinked objects:\n")
    w("- **standalone**: top-level config that nothing in SonicOS references (settings, signature tables, "
      "RBL servers, IPS/GAV/anti-spyware category objects outside Policy mode, ...).")
    w("- **unused here**: the type can be referenced, but every field that could reference it is empty in this "
      "config (e.g. bandwidth objects when no rule enables BWM).")
    w("- **not referenced**: the fields that use the type are populated, but not with these objects (default "
      "services, address objects and groups that no rule, NAT policy or group uses).")
    w("- **POSSIBLE BLIND SPOT**: the object's name appears as a value in a config key that no link rule reads. "
      "Group tables, settings areas, hostnames and IPs are excluded from this search because they collide by "
      "value, not by reference. A flagged key should get a LinkSpec.\n")

    w("## 4. SonicOS 7.0 object coverage\n")
    w("Every section of the SonicOS 7.0 *Objects* guide, and the other configuration areas, mapped to parser "
      "types. **Declared**: key names are known and the type, properties and links are defined in the parser. "
      "**Discovered**: the export keys for this object were not available when the parser was written; the "
      "object is created by table discovery (2.6) and linked by group discovery (3.2) and heuristic links "
      "(3.4). Promote it to a declared type once you have an export containing it (section 10).\n")
    w("| Guide area | Object | Parser type | Status |\n|---|---|---|---|")
    for area, obj, t, st in SONICOS7_COVERAGE + EXTRA_COVERAGE:
        w(f"| {area} | {md_escape(obj)} | {md_escape(t)} | {st} |")
    w("")

    w("## 5. Object types\n")
    by_cat = defaultdict(list)
    for t, specs in spec_types.items():
        by_cat[specs[0].category].append((t, specs))
    for cat in CATEGORY_ORDER:
        if cat not in by_cat:
            continue
        w(f"### {cat}\n")
        for t, specs in by_cat[cat]:
            spec = specs[0]
            w(f"#### {t}\n")
            w(f"{SPLIT_TYPE_DESCRIPTIONS.get(t, spec.description)}\n")
            for sp in specs:
                v6 = (" (keys ending in `V6`)" if sp.v6 == "only" else
                      " (excluding keys ending in `V6`)" if sp.v6 == "exclude" else "")
                src = ", ".join(f"`{p}*`" for p in sp.prefixes) + v6
                name = f"ObjectName from `{sp.name}`" if sp.name else "ObjectName generated (no name column)"
                rule = ""
                if sp.type_field:
                    if t == sp.type:
                        rule = f"; rows where `{sp.type_field}` is not " + ", ".join(f"`{v}`" for v in sp.type_map)
                    else:
                        rule = f"; rows where `{sp.type_field}` = " + ", ".join(
                            f"`{v}`" for v, tt in sp.type_map.items() if tt == t)
                w(f"- **Source:** {src}{rule}; {name}")
            if sp.strip:
                w(f"- **Raw properties:** every column, prefix `{spec.strip}` removed")
            for k, src in spec.keys.items():
                w(f"- **Lookup key** `{k}` from `{src}` (used by links that reference this type by number)")
            if t in DERIVED_DOCS:
                w("- **Decoded properties:**")
                for n, d in DERIVED_DOCS[t]:
                    w(f"  - `{n}`: {d}")
            links_block(t, w)
            w("")

    w("## 6. Settings types\n")
    w("One object per area, holding every matching global key under its full name plus decoded properties. "
      "ObjectName is the area name (AdministratorAccount uses `adminName` when present).\n")
    for ss in SETTINGS_SPECS:
        w(f"#### {ss.type}\n")
        w(f"{ss.description}\n")
        w("- **Keys:** " + ", ".join(f"`{md_escape(p)}`" for p in ss.patterns))
        if ss.type in DERIVED_DOCS:
            w("- **Decoded properties:**")
            for n, d in DERIVED_DOCS[ss.type]:
                w(f"  - `{n}`: {d}")
        links_block(ss.type, w)
        w("")
    w("#### SystemSettings\nGlobal keys matching no area above, grouped by leading word (`foo` for `fooBarBaz`). "
      f"Words that are not features (`enable`, `is`, `use`, ...) and groups under {MIN_FAMILY_SIZE} keys go to "
      "`General`.\n")
    links_block("SystemSettings", w)
    w("")

    w("## 7. Other object types\n")
    w("#### Device\nOne per config, the graph root. ObjectName is `firewallName`. Properties: " +
      ", ".join(f"`{k}`" for k in DEVICE_KEYS) + " (when present).\n")
    links_block("Device", w)
    w("\n#### Keyed settings\nOne object per type; each property is a config column whose value is a list of "
      "`key=value` strings (key = signature, category or event id).\n")
    w("| Type | Config keys | Description |\n|---|---|---|")
    for ks in KEYED_SPECS:
        w(f"| {ks.type} | {', '.join(f'`{p}*`' for p in ks.prefixes)} | {ks.description} |")
    w("\n#### MembershipTable\nOne object per membership table (`addro`, `so`, `sched`, `uo`, `appo`, `urlo`, `wvo` and "
      "any discovered pair): the raw `<prefix>_atomToGrp` and `<prefix>_grpToGrp` rows as `row=value` lists, exactly "
      "as configured. The In*Group links and the group member lists are built from these rows. Not a link target.\n")
    w("\n#### URLCategory\nBuilt-in SonicOS web category. One object per entry in the CFS category catalogue "
      "(`cfsCategoryStr`, a JSON list of id/name pairs). Properties: `ObjectName`, `CategoryID`, `BuiltIn: true`. "
      "Links in: BlocksCategory from CFSProfile (positional flags). Links out: InURLCategoryGroup -> "
      "URLCategoryGroup. If an export has no catalogue, categories named by a group are still created, without "
      "`CategoryID`.\n")
    w("#### Discovered types\nCreated by table discovery (2.6). Properties: `ObjectName`, `Index`, every column "
      "(name-column prefix removed). Links: InGroup (3.2) and References (3.4).\n")
    w("#### ConfigTableRow / ConfigTable / ConfigList\nTables with no name column. `ConfigTableRow`: `ObjectName` "
      "`<family>[<row>]`, `Table`, `Index`, every column under its full key. `ConfigTable`: `Rows` plus one "
      "`row=value` list per column. `ConfigList`: `Table` plus `Values`. Links: References (3.4) only.\n")

    w("## 8. Link reference\n")
    w("| Link type | From | Property | To | Match | Notes |\n|---|---|---|---|---|---|")
    for ls in LINK_SPECS:
        src = settings_owner(ls.prop) if tuple(ls.from_types) == ALL_SETTINGS else tnames(ls.from_types)
        frm, to = (tnames(ls.targets), src) if ls.reverse else (src, tnames(ls.targets))
        prop = f"`{ls.prop}` on {tnames(ls.from_types)}" if ls.reverse else f"`{ls.prop}`"
        note = ls.note + (" (reversed: the property is on the To object)" if ls.reverse else "")
        w(f"| {ls.type} | {frm} | {prop} | {to} | {match_desc(ls)} | {md_escape(note)} |")
    for gs in GROUP_SPECS:
        w(f"| {gs.link_type} | {tnames(gs.member_types)} | `{gs.prefix}_atomToGrp` | {tnames(gs.group_types)} "
          f"| membership row (`{gs.prefix}_grpToGrp` = group) | {md_escape(gs.description)} |")
    w("| InGroup | any named object | `<prefix>_atomToGrp` | any named object | any other membership table | 3.2 |")
    w("| References | any object | any uncovered reference-like property | any named object | `ObjectName` | 3.4 |")
    seen = set()
    for lt, f, tt, note in STRUCTURAL_LINKS:
        key = (lt, f, tt if tt not in ALL_SETTINGS else "settings")
        if key in seen:
            continue
        seen.add(key)
        w(f"| {lt} | {f} | (structural) | {tt if tt not in ALL_SETTINGS else 'every settings type'} | every object | {note} |")

    w("\n## 9. Command line\n")
    w("```\nsonicwall_parser.py CONFIG [-o out.yaml] [--no-auto-links]\n"
      "                    [--discover] [--orphans] [--verify] [--all-unresolved] [-q] [--doc FILE]\n"
      "sonicwall_parser.py --doc FILE\n```\n")
    w("The stderr summary lists object and link counts per type and unresolved references; `--discover` adds "
      "discovered types and heuristic link fields. `--verify` proves the mirror: the parsed pairs reproduce the file "
      "byte for byte, and every configuration key is stored unchanged on exactly one object under the property "
      "recorded for it (exit code 2 otherwise).\n")

    w("## 10. Extending\n")
    w("- **Declare a discovered type:** add a `TableSpec` to `SPECS` (prefixes, name column, description). "
      "Its columns stop being discovered automatically.")
    w("- **Declare a link:** add a `LinkSpec` to `LINK_SPECS`. That field stops producing `References` links.")
    w("- **New settings area:** add a `SettingsSpec` to `SETTINGS_SPECS`.")
    w("- Re-run `--doc` afterwards.\n")

    if cfg is not None:
        counts = defaultdict(int)
        for o in objects:
            counts[o.type] += 1
        w(f"## Appendix: coverage for the supplied config\n")
        w(f"SonicOS {cfg.scalars.get('buildNum', '?')} ({cfg.scalars.get('shortProdName', '?')}). "
          "Key names only; no configuration values are included.\n")
        w("| Type | Objects |\n|---|---|")
        for t, n in sorted(counts.items()):
            w(f"| {t} | {n} |")
        if discovered:
            w("\n**Discovered types:** " + ", ".join(f"{sp.type} (`{sp.name}`)" for sp in discovered))
        if auto_fields:
            w("\n**Fields that produced References links:** " + ", ".join(
                f"{f}.`{p}` -> {t}" for (f, p, t) in auto_fields))
        w("\n**Raw properties observed per type:**\n")
        for t in sorted(prop_sources):
            props = prop_sources[t]
            w(f"<details><summary>{t} ({len(props)})</summary>\n")
            w(", ".join(f"`{md_escape(k)}`" for k in props))
            w("\n</details>\n")
    return "\n".join(L) + "\n"


def report_orphans(cfg, objects, links, prop_sources, stream=sys.stderr):
    """Explain every object type that has unlinked objects: standalone by nature, referenceable but unused in
    this config, or a possible blind spot (its name appears as a value somewhere no rule reads)."""
    linked = set()
    for lt, _v, a, b in links:
        if lt in {x[0] for x in STRUCTURAL_LINKS}:
            continue
        linked.update((a, b))
    orphans = defaultdict(list)
    totals = defaultdict(int)
    for o in objects:
        totals[o.type] += 1
        if o.id not in linked and o.type != "Device":
            orphans[o.type].append(o)

    # fields that could reference each type, and whether they hold anything in this config
    by_type_objs = defaultdict(list)
    for o in objects:
        by_type_objs[o.type].append(o)
    def field_usage(ls):
        n = 0
        for ft in ls.from_types:
            for o in by_type_objs.get(ft, ()):
                for v in as_values(o.props.get(ls.prop, "")):
                    if str(v) not in NULL_REFS and str(v) not in ls.ignore and str(v) not in EMPTY_VALUES:
                        n += 1
        return n

    # raw config values -> keys, to spot names used in fields no rule reads
    name_cols = {sp.name for sp in SPECS if sp.name}
    # raw config keys that some link rule already reads
    read_raw = {prop_sources.get(ft, {}).get(ls.prop, ls.prop) for ls in LINK_SPECS for ft in ls.from_types}
    read_raw |= {b for b in cfg.indexed if b.endswith(("_atomToGrp", "_grpToGrp"))}   # membership tables
    no_name_search = set(ALL_SETTINGS) | {ks.type for ks in KEYED_SPECS} | {
        "ConfigTableRow", "ConfigTable", "ConfigList", "AccessRule", "AccessRuleV6", "NATRule", "NATRuleV6"}
    value_keys = defaultdict(set)
    for k, v in cfg.scalars.items():
        value_keys[v].add(k)
    for b, d in cfg.indexed.items():
        if b in name_cols or b.endswith(("IdDisp", "InstanceId")):
            continue
        for v in d.values():
            value_keys[v].add(b)

    print("unlinked objects by type (structural Device links ignored):", file=stream)
    for t in sorted(orphans, key=lambda t: -len(orphans[t])):
        objs = orphans[t]
        suspects = defaultdict(int)
        for o in objs:
            name = o.props.get("ObjectName")
            if (t in no_name_search or not isinstance(name, str) or len(name) < 3
                    or re.fullmatch(r"[\w.-]+\.[a-zA-Z]{2,}|[\d.:/-]+", name)):   # hostnames / IPs match by value
                continue
            own_raw = set(prop_sources.get(o.type, {}).values())
            for k in value_keys.get(name, ()):
                if k not in own_raw and k not in read_raw:
                    suspects[k] += 1
        incoming = [ls for ls in LINK_SPECS if t in ls.targets and not ls.reverse] + \
                   [ls for ls in LINK_SPECS if t in ls.from_types and ls.reverse]
        member = [gs for gs in GROUP_SPECS if t in gs.member_types]
        if not incoming and not member:
            verdict = "standalone: top-level config, nothing in SonicOS references this type"
        else:
            used = sorted(((f"{'settings' if tuple(ls.from_types) == ALL_SETTINGS else '/'.join(ls.from_types)}.{ls.prop}",
                            field_usage(ls)) for ls in incoming), key=lambda x: -x[1])
            busy = [(k, n) for k, n in used if n]
            if busy:
                verdict = ("not referenced by any rule/object that uses this type here (" +
                           ", ".join(f"{k}: {n}" for k, n in busy[:3]) + (", ..." if len(busy) > 3 else "") + ")")
            else:
                verdict = "unused here: every field that can reference this type is empty"
            if member:
                verdict += "; not in any group"
        print(f"  {t:28} {len(objs):4}/{totals[t]:<4} {verdict}", file=stream)
        if suspects:
            print(f"  {'':28} POSSIBLE BLIND SPOT, name also found in: "
                  + ", ".join(f"{k} ({n})" for k, n in sorted(suspects.items(), key=lambda x: -x[1])[:6]),
                  file=stream)


def verify_mirror(cfg, objects, path, stream=sys.stderr):
    """Prove the object model mirrors the configuration: the parsed pairs reproduce the file, and every
    key=value pair is stored, unchanged, on exactly one object under the property recorded for that key."""
    ok = True
    if path:
        with open(path, "r", encoding="utf-8", errors="replace", newline="") as f:
            raw = f.read()
        if sum(1 for line in raw.splitlines()[:50] if "=" in line) >= 2:
            rebuilt = "\n".join(f"{k}={v}" if k else v for k, v in cfg.pairs) + ("\n" if raw.endswith("\n") else "")
            same = rebuilt == raw
            print(f"round trip: {len(cfg.pairs)} pairs reproduce the file byte for byte: {same}", file=stream)
            ok &= same
    owners = defaultdict(list)
    for o in objects:
        for key, prop in o.raw.items():
            owners[key].append((o, prop))
    missing, wrong, multiple = [], [], []
    list_cache = {}
    for key, value in cfg.pairs:
        held = owners.get(key, [])
        if not held:
            missing.append(key)
            continue
        if len(held) > 1:
            multiple.append(key)
        o, prop = held[0]
        stored = o.props.get(prop)
        if isinstance(stored, list):
            m = INDEXED_KEY_RE.match(key)
            entry = f"{m.group(2)}={value}" if m else value
            cache_key = (id(o), prop)
            if cache_key not in list_cache:
                list_cache[cache_key] = set(stored)
            good = entry in list_cache[cache_key]
        else:
            good = stored == value
        if not good:
            wrong.append((key, o.type, prop))
    config_keys = {k for k, _v in cfg.pairs}
    extra = [k for k in owners if k not in config_keys]
    print(f"mirror: {len(cfg.pairs)} configuration keys | stored unchanged: {len(cfg.pairs) - len(missing) - len(wrong)} | "
          f"missing: {len(missing)} | changed: {len(wrong)} | on more than one object: {len(multiple)} | "
          f"object properties with no configuration key: {len(extra)}", file=stream)
    for label, items in (("missing", missing), ("changed", wrong), ("duplicated", multiple), ("unknown", extra)):
        for item in items[:10]:
            print(f"  {label}: {item}", file=stream)
    return ok and not (missing or wrong or multiple or extra)


def report_discovery(discovered, auto_fields, stream=sys.stderr):
    if discovered:
        print(f"discovered object types: {len(discovered)}", file=stream)
        for sp in discovered:
            print(f"  {sp.type:28} name column {sp.name}", file=stream)
    if auto_fields:
        print(f"heuristic 'References' links by field: {len(auto_fields)} field(s)", file=stream)
        for (ftype, prop, ttype), n in sorted(auto_fields.items(), key=lambda x: -x[1]):
            print(f"  {ftype}.{prop} -> {ttype}: {n}", file=stream)


def main():
    ap = argparse.ArgumentParser(description="Convert any SonicWall configuration to RuleHound YAML")
    ap.add_argument("config", nargs="?", help="SonicWall .exp export or decoded plaintext dump")
    ap.add_argument("-o", "--output", help="output YAML file (default: stdout)")
    ap.add_argument("--no-auto-links", action="store_true",
                    help="only create links from the declared link rules (no heuristic 'References' links)")
    ap.add_argument("--doc", metavar="FILE",
                    help="write the Markdown reference (works without a config; with one, adds a coverage appendix)")
    ap.add_argument("--discover", action="store_true",
                    help="list discovered tables and heuristic link fields on stderr")
    ap.add_argument("--all-unresolved", action="store_true", help="list every unresolved reference")
    ap.add_argument("--verify", action="store_true",
                    help="prove every configuration key is mirrored unchanged onto exactly one object (exit 2 if not)")
    ap.add_argument("--orphans", action="store_true",
                    help="explain unlinked objects: standalone, unused in this config, or possible blind spot")
    ap.add_argument("-q", "--quiet", action="store_true", help="no summary on stderr")
    args = ap.parse_args()

    if not args.config:
        if not args.doc:
            ap.error("a config file is required unless only --doc is given")
        with open(args.doc, "w", encoding="utf-8") as f:
            f.write(render_docs())
        return

    cfg, objects, links, unresolved, prop_sources, discovered, auto_fields = parse(
        args.config, not args.no_auto_links)
    output = render_yaml(objects, links)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(output)
    else:
        sys.stdout.write(output)
    if args.doc:
        with open(args.doc, "w", encoding="utf-8") as f:
            f.write(render_docs(cfg, objects, prop_sources, discovered, auto_fields))
    if not args.quiet:
        report(objects, links, unresolved, limit=10**9 if args.all_unresolved else 40)
        if args.discover:
            report_discovery(discovered, auto_fields)
        if args.orphans:
            report_orphans(cfg, objects, links, prop_sources)
    if args.verify and not verify_mirror(cfg, objects, args.config):
        sys.exit(2)


if __name__ == "__main__":
    main()