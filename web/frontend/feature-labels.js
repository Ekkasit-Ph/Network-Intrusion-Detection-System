// Human-readable names, units and expectations for the 46 model inputs.
//
// The dashboard's whole reason for existing is explainability, and a SHAP
// chart labelled SRC_TO_DST_SECOND_BYTES explains nothing to anyone who
// isn't already fluent in the NetFlow v2 schema. Anything missing here
// falls back to its raw column name, so an unmapped feature degrades to
// the old behaviour instead of rendering blank.
//
// `unit` is what the de-standardized value is measured in. The panel shows
// the feature's real pre-scale quantity (inverted exactly from z with the
// scaler constants /meta serves), and a number without its unit is only
// half an answer: "2,929" and "2,929 B" are not equally useful.
//
// `group` drives the accent in the explanation list. "behavioral" marks
// the three engineered fan-out/fan-in features (see
// source/preprocessing/engineer_features.py) -- worth calling out visually
// since they're this project's own contribution rather than something the
// raw capture handed us.
const FEATURE_LABELS = {
  L7_PROTO: { en: "Application-layer protocol", group: "proto", unit: "" },

  IN_BYTES:  { en: "Bytes in", group: "volume", unit: "B" },
  OUT_BYTES: { en: "Bytes out", group: "volume", unit: "B" },
  IN_PKTS:   { en: "Packets in", group: "volume", unit: "pkt" },
  OUT_PKTS:  { en: "Packets out", group: "volume", unit: "pkt" },

  FLOW_DURATION_MILLISECONDS: { en: "Flow duration", group: "timing", unit: "ms" },
  DURATION_IN:  { en: "Duration, inbound side", group: "timing", unit: "ms" },
  DURATION_OUT: { en: "Duration, outbound side", group: "timing", unit: "ms" },

  TCP_FLAGS:        { en: "TCP flags (both directions)", group: "tcp", unit: "" },
  CLIENT_TCP_FLAGS: { en: "TCP flags, client side", group: "tcp", unit: "" },
  SERVER_TCP_FLAGS: { en: "TCP flags, server side", group: "tcp", unit: "" },
  TCP_WIN_MAX_IN:   { en: "Max TCP window, inbound", group: "tcp", unit: "B" },
  TCP_WIN_MAX_OUT:  { en: "Max TCP window, outbound", group: "tcp", unit: "B" },

  MIN_TTL: { en: "Minimum TTL", group: "path", unit: "hops" },
  MAX_TTL: { en: "Maximum TTL", group: "path", unit: "hops" },

  LONGEST_FLOW_PKT:  { en: "Largest packet in flow", group: "size", unit: "B" },
  SHORTEST_FLOW_PKT: { en: "Smallest packet in flow", group: "size", unit: "B" },
  MIN_IP_PKT_LEN:    { en: "Minimum IP packet length", group: "size", unit: "B" },
  MAX_IP_PKT_LEN:    { en: "Maximum IP packet length", group: "size", unit: "B" },

  // Named as rates by NetFlow, but not rates in this dataset -- see
  // source/extraction/README.md finding 5. The unit reflects what the
  // number actually is, so the panel does not repeat the schema's mistake.
  SRC_TO_DST_SECOND_BYTES:   { en: "Bytes/s, source → destination", group: "rate", unit: "B/s" },
  DST_TO_SRC_SECOND_BYTES:   { en: "Bytes/s, destination → source", group: "rate", unit: "B/s" },
  SRC_TO_DST_AVG_THROUGHPUT: { en: "Avg throughput, source → destination", group: "rate", unit: "bit/s" },
  DST_TO_SRC_AVG_THROUGHPUT: { en: "Avg throughput, destination → source", group: "rate", unit: "bit/s" },

  RETRANSMITTED_IN_BYTES:  { en: "Retransmitted bytes in", group: "retrans", unit: "B" },
  RETRANSMITTED_IN_PKTS:   { en: "Retransmitted packets in", group: "retrans", unit: "pkt" },
  RETRANSMITTED_OUT_BYTES: { en: "Retransmitted bytes out", group: "retrans", unit: "B" },
  RETRANSMITTED_OUT_PKTS:  { en: "Retransmitted packets out", group: "retrans", unit: "pkt" },

  NUM_PKTS_UP_TO_128_BYTES:    { en: "Packets ≤ 128 B", group: "size", unit: "pkt" },
  NUM_PKTS_128_TO_256_BYTES:   { en: "Packets 128–256 B", group: "size", unit: "pkt" },
  NUM_PKTS_256_TO_512_BYTES:   { en: "Packets 256–512 B", group: "size", unit: "pkt" },
  NUM_PKTS_512_TO_1024_BYTES:  { en: "Packets 512–1024 B", group: "size", unit: "pkt" },
  NUM_PKTS_1024_TO_1514_BYTES: { en: "Packets 1024–1514 B", group: "size", unit: "pkt" },

  ICMP_TYPE:            { en: "ICMP type (type×256 + code)", group: "proto", unit: "" },
  ICMP_IPV4_TYPE:       { en: "ICMP type", group: "proto", unit: "" },
  DNS_QUERY_ID:         { en: "DNS query ID", group: "app", unit: "" },
  DNS_QUERY_TYPE:       { en: "DNS query type", group: "app", unit: "" },
  DNS_TTL_ANSWER:       { en: "DNS answer TTL", group: "app", unit: "s" },
  FTP_COMMAND_RET_CODE: { en: "FTP reply code", group: "app", unit: "" },

  // --- engineered behavioural features (this project's own) ---
  SRC_DISTINCT_DST_IPS_LAST_W: {
    en: "Distinct destinations this source touched (last 50 flows)",
    group: "behavioral", unit: "hosts",
    hint: "High = one source fanning out across many targets — the scanning signature.",
  },
  SRC_DISTINCT_DST_PORTS_LAST_W: {
    en: "Distinct destination ports (this source's last 50 flows)",
    group: "behavioral", unit: "ports",
    hint: "High = sweeping many ports — the port-scan signature.",
  },
  DST_DISTINCT_SRC_IPS_LAST_W: {
    en: "Distinct sources hitting this destination (last 50 flows)",
    group: "behavioral", unit: "hosts",
    hint: "High = many sources converging on one target — the DDoS signature.",
  },

  "PROTOCOL_1.0":  { en: "Protocol is ICMP", group: "proto", unit: "" },
  "PROTOCOL_2.0":  { en: "Protocol is IGMP", group: "proto", unit: "" },
  "PROTOCOL_6.0":  { en: "Protocol is TCP", group: "proto", unit: "" },
  "PROTOCOL_17.0": { en: "Protocol is UDP", group: "proto", unit: "" },
  "PROTOCOL_58.0": { en: "Protocol is ICMPv6", group: "proto", unit: "" },
};

function featureLabel(name) {
  return FEATURE_LABELS[name] || { en: name, group: "other", unit: "" };
}

// What each attack class *should* light up, if the model is picking up the
// mechanism rather than some coincidence of this dataset.
//
// These are hypotheses from how each attack works on the wire, written
// down before looking at any particular flow's SHAP output -- that's what
// makes them worth checking against. `expect: []` is a real prediction
// too, not a gap: XSS and injection live in the request *payload*, which
// NetFlow v2 never records, so per-flow metadata has little to latch onto.
// That prediction matches the measured per-class results (xss is the
// weakest class at 74% recall).
//
// Development aid only: this drives the "did the explanation match
// expectation" check in the explanation panel, which needs ground truth
// and so only ever appears for replayed flows.
const ATTACK_EXPECTATIONS = {
  scanning: {
    en: "Scanning",
    why: "one source contacting many destinations and ports in a short span",
    expect: ["SRC_DISTINCT_DST_PORTS_LAST_W", "SRC_DISTINCT_DST_IPS_LAST_W"],
  },
  ddos: {
    en: "DDoS",
    why: "many sources converging on one target at once, volume and rate spiking",
    expect: ["DST_DISTINCT_SRC_IPS_LAST_W", "IN_PKTS", "OUT_PKTS",
             "SRC_TO_DST_AVG_THROUGHPUT", "DST_TO_SRC_AVG_THROUGHPUT"],
  },
  dos: {
    en: "DoS",
    why: "one source hammering one target — many short flows",
    expect: ["IN_PKTS", "OUT_PKTS", "FLOW_DURATION_MILLISECONDS",
             "SRC_TO_DST_AVG_THROUGHPUT", "TCP_FLAGS"],
  },
  password: {
    en: "Password guessing",
    why: "repeated connections to the same service, each one short and carrying little data",
    expect: ["IN_BYTES", "OUT_BYTES", "FLOW_DURATION_MILLISECONDS",
             "CLIENT_TCP_FLAGS", "SERVER_TCP_FLAGS"],
  },
  backdoor: {
    en: "Backdoor",
    why: "a connection held open far longer than normal, or on a port nothing should be using",
    expect: ["FLOW_DURATION_MILLISECONDS", "DURATION_IN", "DURATION_OUT", "L7_PROTO"],
  },
  ransomware: {
    en: "Ransomware",
    why: "an unusually large transfer",
    expect: ["IN_BYTES", "OUT_BYTES", "SRC_TO_DST_SECOND_BYTES", "DST_TO_SRC_SECOND_BYTES"],
  },
  mitm: {
    en: "Man in the middle",
    why: "an extra hop inserted into the path, so TTL differs from that route's normal",
    expect: ["MIN_TTL", "MAX_TTL"],
  },
  xss: {
    en: "XSS",
    why: "the script lives in the HTTP payload, and NetFlow never records payload content",
    expect: [],
  },
  injection: {
    en: "Injection",
    why: "the command lives in the payload, which NetFlow never records",
    expect: [],
  },
};

function attackExpectation(attackClass) {
  return ATTACK_EXPECTATIONS[String(attackClass ?? "").toLowerCase()] || null;
}
