---
title: "Proxy Registration of Self-Generated IPv6 Addresses Using DHCPv6"
abbrev: "DHCPv6 Proxy Address Registration"
category: std

docname: draft-buraglio-6man-proxy-9686-latest
submissiontype: IETF
number:
date:
consensus: true
v: 3
area: INT
workgroup: 6man
keyword:
 - IPv6
 - DHCPv6
 - SLAAC
 - IoT
 - address registration
 - proxy

venue:
  group: 6man
  type: Working Group
  mail: ipv6@ietf.org
  arch: https://mailarchive.ietf.org/arch/browse/ipv6/
  github: buraglio/draft-buraglio-6man-update-9686
  latest: https://buraglio.github.io/draft-buraglio-6man-update-9686/

author:
 -
    fullname: Nick Buraglio
    organization: Energy Sciences Network
    email: buraglio@forwardingplane.net

normative:
  RFC2119:
  RFC8174:
  RFC4861:
  RFC4862:
  RFC9915:
  RFC9686:
  RFC6939:
  RFC7513:
  RFC8505:

informative:
  RFC8929:
  RFC8981:
  RFC8344:
  RFC8213:
  I-D.ietf-6man-ipv6-neighbor-discovery-yang:

...

--- abstract

A prior RFC defines a method for IPv6 hosts to register their
self-generated or statically configured addresses with a DHCPv6 server,
restoring the address-to-host traceability that network operators rely on
for troubleshooting and forensic investigation.  That mechanism requires
a conformant client implementation on the registering host.  Many
devices, including IoT sensors, legacy endpoints, and constrained
6LoWPAN nodes, do not and will not implement such a client.

This document defines the behavior of a Proxy Registrar: a first-hop
IPv6 router that observes address assignment events on its links and
performs DHCPv6 address registrations on behalf of hosts that have not
registered their addresses.  The mechanism reuses existing DHCPv6
message types and relay infrastructure with the addition of one new
DHCPv6 relay option to signal proxy origin.  It is designed so that
existing DHCPv6 servers that support address registration require no
changes to interoperate with a Proxy Registrar.

--- middle

# Introduction {#intro}

{{RFC9686}} defines ADDR-REG-INFORM and ADDR-REG-REPLY message types
that allow an IPv6 host to inform a DHCPv6 server of its self-generated
or statically configured addresses.  This provides parity with IPv4
DHCP logging and enables operators to correlate IPv6 addresses with
hosts for troubleshooting and security forensics.

The mechanism in {{RFC9686}} requires a conformant implementation on the
host.  A first-hop router, however, already observes every address that
appears on its links: it processes Duplicate Address Detection (DAD)
traffic ({{RFC4861}}), may maintain a Source Address Validation
Improvement (SAVI) binding table ({{RFC7513}}), and in 6LoWPAN networks
receives explicit Address Registration Options (ARO) from devices
({{RFC8505}}).  This document defines a Proxy Registrar role for
first-hop routers, enabling them to register addresses on behalf of
hosts that have not performed self-registration, using the same
DHCPv6 relay infrastructure already deployed in most networks.

The remainder of this document is organized as follows.
{{problem}} describes the problem in detail.
{{overview}} provides a protocol overview.
{{option}} defines the new OPTION_ADDR_REG_PROXY relay option.
{{proxy-behavior}} specifies Proxy Registrar behavior.
{{server}} specifies DHCPv6 server behavior.
{{iot}} discusses IoT and constrained-network considerations.
{{security}} and {{privacy}} address security and privacy.
{{iana}} contains IANA considerations.

# Conventions and Definitions {#conventions}

{::boilerplate bcp14-tagged}

Terms defined in {{RFC9686}} are used as defined therein, including
ADDR-REG-INFORM, ADDR-REG-REPLY, and OPTION_ADDR_REG_ENABLE.

This document defines the following additional terms:

Proxy Registrar:
: A first-hop IPv6 router that sends ADDR-REG-INFORM messages on
  behalf of hosts that have not performed self-registration per
  {{RFC9686}}.

Proxy Registration:
: An address registration performed by a Proxy Registrar on behalf
  of a Registering Host.

Proxy Registration Table:
: A per-interface data structure maintained by the Proxy Registrar
  tracking registered addresses and their current state.

Registering Host:
: An IPv6 node whose self-generated address is being registered by
  a Proxy Registrar.  The Registering Host need not be aware that
  registration is occurring.

Self-Registration:
: Address registration performed directly by the host per {{RFC9686}}.

# Problem Statement {#problem}

It is common operational practice, particularly in enterprise and
campus networks, to use DHCP logs for troubleshooting and forensic
investigation.  When a security event is detected -- a suspicious
outbound connection, an unauthorized access attempt -- operators
consult DHCP records to identify which host held a given IP address
at the time of interest.  For IPv4, this practice works well because
most addresses are assigned by DHCP {{?RFC2131}} or statically
configured by the operator.

For IPv6, this practice is complicated by SLAAC {{RFC4862}}, which
allows hosts to self-configure addresses without any interaction with
network infrastructure.  {{RFC9686}} addresses this gap by defining
ADDR-REG-INFORM and ADDR-REG-REPLY messages that allow a host to
inform the DHCPv6 server of its self-configured addresses, mirroring
the information that DHCP leases provide for IPv4.

{{RFC9686}} requires a client implementation on the host.  Many
categories of device will never carry such an implementation:

*  IoT sensors and actuators running minimal firmware with no DHCPv6
   stack.

*  Legacy enterprise equipment from vendors who will not ship
   {{RFC9686}} support.

*  Constrained 6LoWPAN devices (IEEE 802.15.4, BLE mesh, etc.) where
   DHCPv6 client complexity exceeds platform capabilities.

*  Devices where the firmware update supply chain has effectively
   ended.

For these devices, the traceability gap that {{RFC9686}} was designed
to close remains open.

Streaming telemetry of the IPv6 neighbor cache -- available today via
gNMI with paths defined in {{RFC8344}} and
{{I-D.ietf-6man-ipv6-neighbor-discovery-yang}} -- provides real-time
operational visibility of IPv6 neighbor state.  However, this approach
requires a separate telemetry collection and storage pipeline,
currently exposes no address-creation timestamp in any standardized
YANG model (only elapsed age since last reachability confirmation),
does not persist records after a device leaves the network, and does
not integrate with the DHCPv6-based IPAM infrastructure that operators
already use for IPv4 forensics.

The first-hop router is in a privileged position to fill this gap.
It observes every address that appears on its directly attached links
via DAD ({{RFC4861}}), SAVI binding tables ({{RFC7513}}), and -- in
6LoWPAN networks -- explicit ARO messages ({{RFC8505}}).  It is also
the DHCPv6 relay node for those links in most deployments, giving it
direct access to the DHCPv6 relay infrastructure.  This document
defines behavior for a Proxy Registrar that exploits this position to
register addresses on behalf of non-capable hosts, placing the
resulting records in the same DHCPv6 server that operators already
consult for address-to-host correlation.

# Protocol Overview {#overview}

The Proxy Registrar monitors its directly attached links for new
globally-scoped IPv6 addresses appearing on Registering Hosts (see
{{detection}}).  Upon detecting a new address, the Proxy Registrar
first verifies that the DHCPv6 server supports address registration
({{capability}}), then constructs an ADDR-REG-INFORM message on
behalf of the Registering Host and delivers it to the DHCPv6 server
via the existing relay infrastructure ({{procedure}}).

The key protocol element is the choice of relay encapsulation.
{{RFC9686}} Section 4.2.1 specifies that when an ADDR-REG-INFORM is
relayed, the server validates the registered address against the
peer-address field of the innermost Relay-Forward message.  The Proxy
Registrar exploits this by acting as the innermost relay, setting
peer-address to the Registering Host's address, and including a new
relay option, OPTION_ADDR_REG_PROXY ({{option}}), that identifies the
encapsulated message as a Proxy Registration.  An
OPTION_CLIENT_LINKLAYER_ADDR option {{RFC6939}} carries the
Registering Host's link-layer address.

Existing RFC 9686-compliant DHCPv6 servers that do not recognize
OPTION_ADDR_REG_PROXY silently ignore it and process the inner
ADDR-REG-INFORM normally, requiring no server-side changes for
basic interoperability.

~~~
+----------+        +------------------+        +---------------+
|REGISTERING|        | PROXY REGISTRAR  |        | DHCPv6 SERVER |
|   HOST   |        | (first-hop router)|        |               |
+----------+        +------------------+        +---------------+
     |                        |                         |
     | DAD (NS/NA) or ARO     |                         |
     |----------------------->|                         |
     |                        | Information-Request     |
     |                        | [OPTION_ADDR_REG_ENABLE]|
     |                        |------------------------>|
     |                        |<------------------------|
     |                        | Reply                   |
     |                        | [OPTION_ADDR_REG_ENABLE]|
     |                        |                         |
     |                        | Relay-Forward           |
     |                        |  peer-addr: host's addr |
     |                        |  link-addr: router intf |
     |                        |  OPTION_ADDR_REG_PROXY  |
     |                        |  OPTION_CLIENT_LL_ADDR  |
     |                        |  [inner: ADDR-REG-INFORM|
     |                        |   client-id: DUID-LL    |
     |                        |   IA Addr: host's addr] |
     |                        |------------------------>|
     |                        |                  Register/log
     |                        |<------------------------|
     |                        | Relay-Reply             |
     |                        |  [inner: ADDR-REG-REPLY]|
~~~
{: #fig-overview title="Proxy Registration Procedure Overview"}

If the Proxy Registrar detects that the Registering Host has
performed Self-Registration (by snooping ADDR-REG-INFORM traffic
on the link), it suppresses or withdraws its Proxy Registration to
avoid duplicate entries at the server ({{dedup}}).  The Proxy
Registrar tracks registered addresses in a Proxy Registration Table
({{table}}) and issues refreshes and expirations as the address
lifetime evolves ({{refresh}}).

# The OPTION_ADDR_REG_PROXY Option {#option}

The OPTION_ADDR_REG_PROXY option is a zero-length DHCPv6 option
carried in a Relay-Forward message to signal that the encapsulated
ADDR-REG-INFORM was constructed by a Proxy Registrar rather than by
the Registering Host.

~~~
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|       option-code (TBD1)      |          option-len (0)       |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
~~~
{: #fig-option title="OPTION_ADDR_REG_PROXY Format"}

option-code:
: OPTION_ADDR_REG_PROXY (TBD1)

option-len:
: 0

This option MUST only appear in a Relay-Forward message.  It MUST
NOT appear in any other DHCPv6 message type.  At most one instance
of this option MUST be present in a Relay-Forward message.

A DHCPv6 server or relay agent that does not recognize this option
MUST silently ignore it, per {{RFC9915}} Section 10.  The
encapsulated ADDR-REG-INFORM is processed according to {{RFC9686}}
regardless of whether the server recognizes OPTION_ADDR_REG_PROXY.
This ensures backward compatibility: a Proxy Registrar interoperates
with any existing {{RFC9686}}-compliant server.

A DHCPv6 server that does recognize this option SHOULD record the
proxy-origin of the registration (see {{server}}).  The presence of
this option MUST NOT cause the server to alter its validation of the
inner ADDR-REG-INFORM; validation follows {{RFC9686}} Section 4.2.1
unchanged.

# Proxy Registrar Behavior {#proxy-behavior}

## Address Detection {#detection}

The Proxy Registrar MUST register each globally-scoped unicast
address independently.  Registration MUST NOT be performed for
link-local addresses, addresses assigned by DHCPv6 (identifiable
by the presence of a matching IA address in a DHCPv6 Reply observed
on the link), or loopback addresses.

The Proxy Registrar MUST initiate registration upon observing any of
the following events for a globally-scoped unicast address:

1.  **DAD completion.**  The Proxy Registrar observes a Neighbor
    Solicitation for a tentative address (DAD NS per {{RFC4861}}
    Section 5.4) and no Neighbor Advertisement conflicting with that
    address is received within the DAD timeout.  The Proxy Registrar
    SHOULD wait until the full DAD timeout has elapsed before
    initiating registration.

2.  **FCFS SAVI binding creation.**  An entry in the First-Come
    First-Served Source Address Validation Improvement binding table
    ({{RFC7513}}) transitions to BOUND state for a new globally-scoped
    address.  Implementations SHOULD use this trigger when SAVI is
    deployed, as it provides stronger address-ownership evidence than
    DAD snooping alone.

3.  **ARO receipt (6LoWPAN context).**  The Proxy Registrar receives
    a Neighbor Solicitation carrying an Address Registration Option
    ({{RFC8505}}) that creates or updates a binding for a
    globally-scoped address.  This is the normative trigger when
    operating as a 6LoWPAN Backbone Router; see {{iot}}.

4.  **Neighbor cache REACHABLE transition.**  A new globally-scoped
    unicast address appears in the neighbor cache in REACHABLE state.
    This MAY be used as a fallback trigger on routers that have no
    access to DAD timing or SAVI state, with the understanding that
    it provides lower address-ownership assurance than the triggers
    above.

Triggers 1, 2, and 3 are preferred over trigger 4 wherever available.
A Proxy Registrar MUST implement trigger 1.  Triggers 2, 3, and 4 are
implementation options subject to their applicability conditions.

## Capability Discovery {#capability}

The Proxy Registrar MUST verify that the DHCPv6 server supports
address registration before sending any Proxy Registration.  It does
so by including OPTION_ADDR_REG_ENABLE ({{RFC9686}} Section 4.4) in
the Option Request Option of a DHCPv6 Information-Request.  If the
server includes OPTION_ADDR_REG_ENABLE in its Reply, the Proxy
Registrar MAY send Proxy Registrations.  If the server does not
include OPTION_ADDR_REG_ENABLE, the Proxy Registrar MUST NOT send
Proxy Registrations on that link.

This reuses the capability negotiation defined in {{RFC9686}} without
any new option or exchange.  The Proxy Registrar acts as a DHCPv6
client for the purpose of this check.

The Proxy Registrar MAY cache the capability result and reuse it
for subsequent registrations.  The cache MUST be invalidated if the
DHCPv6 server address changes or if the Proxy Registrar receives a
Reply that does not include OPTION_ADDR_REG_ENABLE.

## Proxy Registration Procedure {#procedure}

Upon detecting a new address per {{detection}} and confirming server
support per {{capability}}, the Proxy Registrar sends a Relay-Forward
message with the following field values.

The outer Relay-Forward uses msg-type RELAY-FORW (12) per {{RFC9915}}.
The hop-count MUST be set to 0; the Proxy Registrar is always the
innermost relay, which ensures its peer-address field is the value the
server validates against per {{RFC9686}} Section 4.2.1.  Any upstream
relay agents encapsulate the message per {{RFC9915}} Section 19,
incrementing hop-count normally.  The link-address is set to the Proxy
Registrar's global unicast address on the client-facing interface,
identifying the client's link to the server.  The peer-address MUST be
set to the IPv6 address being registered; this value MUST equal the
address in the IA Address option of the encapsulated ADDR-REG-INFORM.

The Relay-Forward MUST include OPTION_ADDR_REG_PROXY ({{option}}) to
signal proxy origin, OPTION_CLIENT_LINKLAYER_ADDR ({{RFC6939}}) set to
the Registering Host's link-layer address as observed from the detection
trigger (DAD, SAVI binding, or ARO) with the hardware type set from the
interface type, and OPTION_RELAY_MSG ({{RFC9915}}) containing the
encapsulated ADDR-REG-INFORM.

The encapsulated ADDR-REG-INFORM (message type 36, {{RFC9686}}) MUST
include a Client Identifier option containing a DUID-LL derived from the
Registering Host's link-layer address per {{RFC9915}} Section 11.4.
This derivation is deterministic from the link-layer address and requires
no DHCPv6 snooping.  The IA Address option contains the address being
registered; the valid-lifetime MUST be set to the remaining valid-lifetime
of the prefix containing the registered address at the time of
registration, as advertised in the most recent Router Advertisement sent
by the Proxy Registrar for that prefix.  The preferred-lifetime and
valid-lifetime are described further in {{refresh}}.  The inner
ADDR-REG-INFORM MUST NOT contain a Server Identifier option or an Option
Request Option.

The Relay-Forward is sent to the All_DHCP_Relay_Agents_and_Servers
multicast address (ff02::1:2) or unicast to the server if the server
address is known from a prior DHCPv6 exchange.  Per {{RFC9915}}
Section 19.1, ADDR-REG-REPLY is returned unicast to the Proxy
Registrar's source address.

If the DHCPv6 server holds an existing binding for the Registering Host
with a different DUID type (e.g., DUID-UUID from a prior stateful DHCPv6
exchange), the server MAY correlate the two records using the link-layer
address in OPTION_CLIENT_LINKLAYER_ADDR.

The Proxy Registrar MUST register each globally-scoped unicast address
of a Registering Host independently.  A host with addresses from
multiple prefixes will have one Proxy Registration Table entry per
address, each managed with its own procedure and lifetime.

## Proxy Registrar State Machine {#state-machine}

The Proxy Registrar maintains per-address state in the Proxy
Registration Table ({{table}}).  Each entry transitions through the
following states:

PENDING:
: An ADDR-REG-INFORM has been sent; the Proxy Registrar is awaiting
  an ADDR-REG-REPLY.

REGISTERED:
: An ADDR-REG-REPLY with a success status was received.  The
  address is registered at the server.

FAILED:
: Retransmission was exhausted (MRC reached) or the server returned
  a non-zero Status Code (e.g., NotOnLink, UnspecFail).  The
  registration did not succeed.

SUPPRESSED:
: Self-Registration by the Registering Host was detected.  The
  Proxy Registrar has yielded and MUST NOT send further
  registrations or refreshes for this address.

State transitions are as follows:

*  PENDING -> REGISTERED: an ADDR-REG-REPLY is received with success
   status (Status Code absent or Success).  The Proxy Registrar
   updates the registration timestamp and schedules the next refresh
   per {{refresh}}.

*  PENDING -> FAILED: retransmission count reaches MRC (3) without
   receiving an ADDR-REG-REPLY, or an ADDR-REG-REPLY with a
   non-zero Status Code is received.  The Proxy Registrar logs the
   failure and suppresses further attempts until the next address
   detection event for this address.

*  PENDING -> SUPPRESSED: host Self-Registration is detected while
   the ADDR-REG-INFORM is in flight (see {{dedup}}).  The Proxy
   Registrar waits for the ADDR-REG-REPLY (or retransmission
   timeout), then sends a final ADDR-REG-INFORM with
   preferred-lifetime=0 and valid-lifetime=0 to withdraw the Proxy
   Registration, and transitions to SUPPRESSED.

*  REGISTERED -> PENDING: a refresh is due per {{refresh}}.  The
   Proxy Registrar sends a new ADDR-REG-INFORM.

*  REGISTERED -> SUPPRESSED: host Self-Registration is detected.
   The Proxy Registrar immediately sends an ADDR-REG-INFORM with
   preferred-lifetime=0 and valid-lifetime=0 to withdraw the Proxy
   Registration, then transitions to SUPPRESSED.

*  REGISTERED -> (removed): an expiry trigger fires per {{refresh}}.
   The Proxy Registrar sends an ADDR-REG-INFORM with
   preferred-lifetime=0 and valid-lifetime=0, then removes the
   entry from the Proxy Registration Table.

*  FAILED -> PENDING: the next address detection event for this
   address.  The Proxy Registrar retries registration.

*  SUPPRESSED -> (removed): an address expiry event occurs.  No
   expiry registration is sent (the server will expire the
   host's own registration); the entry is removed.

**Reboot recovery:**

The Proxy Registration Table is in-memory and is lost on restart.
On restart, the Proxy Registrar recovers naturally: as neighbor
cache entries are repopulated via ND ({{RFC4861}}), DAD-completion
events re-trigger detection and registration for each active
address.  A transient gap exists between restart and repopulation
during which the server's proxy-registration records may be more
current than the Proxy Registrar's table.  This gap is bounded by
ND reachability timescales and is acceptable for the operational
use cases described in {{problem}}.

## Retransmission {#retransmission}

The Proxy Registrar follows the retransmission procedure of
{{RFC9915}} Section 15 for each ADDR-REG-INFORM it sends, with the
following parameters:

IRT (Initial Retransmission Time):
: 1 second

MRT (Maximum Retransmission Time):
: 120 seconds

MRC (Maximum Retransmission Count):
: 3

MRD (Maximum Retransmission Duration):
: 0 (no maximum duration)

The same transaction ID MUST be used across all retransmissions of a
single ADDR-REG-INFORM for a given registration event.  Per
{{RFC9686}} Section 4.5, the preferred-lifetime and valid-lifetime
fields in the IA Address option MUST be updated to reflect the
current remaining lifetimes in each retransmission.

Upon exhausting retransmissions (MRC reached) without receiving an
ADDR-REG-REPLY, the Proxy Registrar MUST transition the entry to
FAILED state ({{state-machine}}) and cease retransmission.  It MUST
NOT retry until the next address detection event for that address.

## Duplicate Avoidance {#dedup}

The Proxy Registrar MUST snoop ADDR-REG-INFORM messages sent by
hosts on its directly attached links.  These messages are sent to
the All_DHCP_Relay_Agents_and_Servers multicast address (ff02::1:2)
and are observable by the Proxy Registrar as a relay node.  Receipt
of an ADDR-REG-INFORM from a source address matching an address in
the Proxy Registration Table constitutes detection of a
Self-Registration for that address.

The timing of detection relative to the state of the Proxy Registration
Table entry determines the appropriate response.

If the Proxy Registrar detects a Self-Registration before it has sent
any Proxy Registration for that address (i.e., before the entry
transitions to PENDING), it MUST NOT send a Proxy Registration for that
address.  The entry transitions directly to SUPPRESSED.

If the Self-Registration is detected while a Proxy Registration is in
PENDING state, the Proxy Registrar MUST wait for the in-flight
ADDR-REG-REPLY (or retransmission timeout, whichever comes first).
Upon receiving the reply or on timeout, it MUST send a final
ADDR-REG-INFORM with preferred-lifetime=0 and valid-lifetime=0 to
withdraw the Proxy Registration from the server.  The entry then
transitions to SUPPRESSED.

If the Self-Registration is detected while the entry is in REGISTERED
state, the Proxy Registrar MUST immediately send an ADDR-REG-INFORM
with preferred-lifetime=0 and valid-lifetime=0 to withdraw the Proxy
Registration.  The entry transitions to SUPPRESSED.

In all cases, once an entry is in SUPPRESSED state, the Proxy
Registrar MUST NOT send further registrations or refreshes for that
address.  The Registering Host's own registration becomes the
authoritative entry at the server.

## Refresh and Expiry {#refresh}

For an address configured using SLAAC ({{RFC4862}}), the Proxy
Registrar computes the refresh interval as:

~~~
  refresh_interval = floor(0.8 * valid_lifetime * desync_factor)
~~~

where desync_factor is a uniformly distributed random value in the
range \[0.9, 1.1\], re-drawn at each refresh cycle.  This matches the
refresh computation of {{RFC9686}} Section 4.6.1.  The Proxy
Registrar reschedules refresh only if the remaining valid-lifetime
has changed by more than 1% since the last registration, to avoid
churn from minor lifetime fluctuations.

The valid-lifetime used in refresh ADDR-REG-INFORM messages MUST
be the remaining valid-lifetime of the prefix containing the
registered address at the time of the refresh, as advertised in
the most recent Router Advertisement sent by the Proxy Registrar.

Temporary addresses generated per {{RFC8981}} MUST be registered and
refreshed using the same procedure as other SLAAC addresses.  The
privacy properties of {{RFC8981}} protect against cross-site tracking
by external observers; they do not preclude operator-internal address
management.  The network operator already has visibility of the host's
topological location at the /64 boundary from the prefix assignment, so
registering the specific /128 in the DHCPv6 server adds no information
to external parties (see {{privacy}}).  When a host generates a new
temporary address, DAD for the new address triggers a new Proxy
Registration entry; expiry of the old address follows the triggers
described below.

When the Proxy Registrar cannot determine the remaining lifetime from
its own RA prefix state, it MUST use a refresh interval of 14400
seconds (4 hours), consistent with {{RFC9686}} Section 4.6.2.

The Proxy Registrar MUST send an ADDR-REG-INFORM with
preferred-lifetime=0 and valid-lifetime=0 and remove the entry from
the Proxy Registration Table upon any of the following:

*  The neighbor cache entry for the registered address transitions
   to INCOMPLETE state or is removed (host unreachable or departed).

*  The FCFS SAVI binding for the address expires.

*  The ARO binding for the address expires, or an ARO with
   Registration Lifetime=0 is received (see {{iot}}).

*  The valid-lifetime of the prefix containing the address reaches
   zero in the most recently sent Router Advertisement.

## Proxy Registration Table {#table}

The Proxy Registrar MUST maintain a Proxy Registration Table per
interface.  Each entry MUST contain at minimum:

*  Registering Host link-layer address

*  Registered IPv6 address

*  Current state (per {{state-machine}}: PENDING, REGISTERED,
   FAILED, or SUPPRESSED)

*  Next refresh time (for REGISTERED entries)

*  Transaction ID of the last sent ADDR-REG-INFORM

The table is implementation-internal; no wire format is defined.
The Proxy Registrar MUST consult the table before sending any Proxy
Registration to enforce duplicate avoidance per {{dedup}}.

A Registering Host with multiple globally-scoped unicast addresses
has one entry per address.  Entries are independent: a SUPPRESSED
entry for one address does not affect registration of other addresses
held by the same host.

# DHCPv6 Server Behavior {#server}

A DHCPv6 server that receives a Relay-Forward containing an
encapsulated ADDR-REG-INFORM MUST process it using the validation
rules of {{RFC9686}} Section 4.2.1.  Specifically, the peer-address
field of the innermost Relay-Forward is used as the source address
for validation.  Since the Proxy Registrar sets peer-address to the
Registering Host's address and sets the IA Address option to that
same address, this validation passes as it would for a natively
relayed ADDR-REG-INFORM from the host.

A server that recognizes OPTION_ADDR_REG_PROXY in a Relay-Forward
SHOULD record that the registration is proxy-sourced, alongside the
Proxy Registrar's link-layer address available from
OPTION_CLIENT_LINKLAYER_ADDR ({{RFC6939}}).  This information MAY be
used for auditing or logging but MUST NOT affect the validation outcome
for the inner ADDR-REG-INFORM.

When a server receives a native Self-Registration (a direct
ADDR-REG-INFORM from the host per {{RFC9686}}, without proxy relay
encapsulation) for an address that is already proxy-registered, the
server SHOULD update its record to reflect the native registration and
clear any proxy-origin flag.  The Self-Registration is authoritative;
the Proxy Registration entry MUST NOT take precedence.

A server that does not recognize OPTION_ADDR_REG_PROXY MUST silently
ignore the option per {{RFC9915}} Section 10 and process the inner
ADDR-REG-INFORM exactly as it would any relayed ADDR-REG-INFORM per
{{RFC9686}}.  Proxy Registrars therefore interoperate with any existing
{{RFC9686}}-compliant server without server-side changes.

A server MUST NOT use Proxy Registrations for client authentication or
authorization, per {{RFC9686}} Section 6.  The constraint that applies
to self-generated registrations applies equally to proxy-generated ones.

The server MUST respond with ADDR-REG-REPLY wrapped in a Relay-Reply
per {{RFC9686}} and {{RFC9915}}, addressed unicast to the Proxy
Registrar's source address.

# IoT and Constrained Network Considerations {#iot}

This section is informative.

The IPv6 Backbone Router (6BBR) defined in {{RFC8929}} is the
natural implementation vehicle for the Proxy Registrar role in
networks with 6LoWPAN ({{RFC8505}}) or other constrained-device
access links.  The 6BBR:

*  Already maintains a binding table populated from NS ARO messages
   ({{RFC8505}}), which constitutes the normative ARO trigger
   described in {{detection}}.

*  Already acts as a Neighbor Discovery proxy for 6LoWPAN devices
   on its access link, performing proxy NS/NA on the backbone on
   their behalf.

*  Participates in DHCPv6 as a relay for the backbone network,
   giving it direct access to the relay infrastructure used by
   this document.

When a 6BBR receives an NS ARO from a 6LoWPAN device that creates
or updates a binding for a globally-scoped address, it SHOULD send
a Proxy Registration for that address.  The valid-lifetime used in
the IA Address option MUST be derived from the ARO Registration
Lifetime field (in units of 60 seconds per {{RFC8505}}) rather than
from SLAAC prefix lifetimes from a Router Advertisement, as the ARO
lifetime is the authoritative source for 6LoWPAN address bindings.

When a 6BBR ARO binding expires or when an ARO with Registration
Lifetime=0 is received, the 6BBR SHOULD immediately send an expiry
registration (preferred-lifetime=0, valid-lifetime=0) for the
corresponding address.

After a 6BBR restart, ARO re-registrations from 6LoWPAN devices
naturally repopulate the binding table, triggering new Proxy
Registrations.  This is the same recovery path described in
{{state-machine}} for the general case.

Similar patterns apply to Thread border routers, Bluetooth mesh
gateways, and other constrained-network access routers that
maintain equivalent binding tables.  This document does not
normatively update {{RFC8929}}; if the 6lo Working Group wishes to
adopt the Proxy Registrar role as a normative extension to the
6BBR specification, a separate document is the appropriate path.

# Security Considerations {#security}

The security considerations of {{RFC9686}} apply in full to this
document.  In particular, this mechanism is not intended to be a
strong security access mechanism: a malicious device can decline to
trigger DAD or suppress its traffic, thereby preventing the Proxy
Registrar from observing and registering its address.  Registrations
MUST NOT be used for client authentication or authorization.

The Proxy Registrar is a privileged network device capable of
registering arbitrary IPv6 addresses at the DHCPv6 server.  A
compromised or misconfigured Proxy Registrar could register false
address-to-host mappings, undermining the traceability that this
mechanism is designed to provide.  DHCPv6 servers SHOULD restrict
acceptance of Relay-Forward messages containing OPTION_ADDR_REG_PROXY
to trusted relay addresses, using relay authentication mechanisms such
as those described in {{RFC8213}}.  First-hop security mechanisms,
particularly FCFS SAVI ({{RFC7513}}), provide additional assurance that
the Proxy Registrar observed a given address before registering it.

The DUID-LL the Proxy Registrar synthesizes from the Registering Host's
link-layer address is deterministic and does not introduce tracking
capabilities beyond those already inherent in the link-layer address,
which is observable by any on-link device.

In deployments with active-standby first-hop redundancy (e.g., VRRP),
only the active router typically forwards traffic and observes DAD, so
only it acts as Proxy Registrar in practice.  In active-active
deployments, two routers may independently register the same address.
Because the DUID-LL derives from the Registering Host's MAC address
rather than the router's, both registrations appear identical to the
server, which receives idempotent refreshes from each.  Explicit
election mechanisms for this scenario are out of scope.

# Privacy Considerations {#privacy}

Duplicate avoidance snooping ({{dedup}}) requires the Proxy Registrar
to observe ADDR-REG-INFORM messages sent by hosts to ff02::1:2.  On
links without MLD snooping, this multicast traffic is visible to all
on-link observers.  This exposure is identical to the case described in
{{RFC9686}} Section 7 for host-originating registrations and introduces
no additional risk.

The privacy protections of {{RFC8981}} temporary addresses are designed
to prevent cross-site tracking by external observers, who cannot
correlate IPv6 sessions across address rotations.  Those protections are
unaffected by operator-internal registration.  The network operator
already has visibility of the host's topological location at the /64
boundary from the RA prefix assignment, the neighbor cache, and routing
state.  The Proxy Registration adds only the specific /128 to an
internal DHCPv6 record that is not shared with external parties.
Operators who wish to avoid recording temporary addresses for policy
reasons MAY configure the Proxy Registrar to suppress registration for
addresses matching {{RFC8981}} criteria; such configuration is outside
the scope of this document.

As noted in {{RFC9686}} Section 7, the Client DUID enables tracking of
a host across addresses.  The DUID-LL used in Proxy Registrations
derives from the host's link-layer address, which is already visible
to any on-link observer via ND and DAD traffic.

# IANA Considerations {#iana}

IANA is requested to assign one new option code in the "Option
Codes" subregistry of the "Dynamic Host Configuration Protocol for
IPv6 (DHCPv6)" registry
[IANA-DHCPV6](https://www.iana.org/assignments/dhcpv6-parameters):

| Option Name | Code | Description | Client ORO | Singleton | Reference |
|:---|:---:|:---|:---:|:---:|:---:|
| OPTION_ADDR_REG_PROXY | TBD1 | DHCPv6 Proxy Address Registration | No | Yes | This document |
{: #iana-table title="New DHCPv6 Option Code"}

Client ORO:
: "No" -- this option is carried in a Relay-Forward message and
  is not requested by clients in an Option Request Option.

Singleton:
: "Yes" -- at most one instance of this option MUST be present
  in a Relay-Forward message.

--- back

# Acknowledgments
{:numbered="false"}

The authors of {{RFC9686}} (Warren Kumari, Suresh Krishnan,
Rajiv Asati, Lorenzo Colitti, Jen Linkova, and Sheng Jiang)
created the base mechanism that this document extends.  Their work
on address registration provides the protocol foundation on which
the Proxy Registrar role is built.
