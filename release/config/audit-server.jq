# jq -n -f audit-server.jq
def required($key):
  env[$key] | if . == null or . == "" then error("missing " + $key) else . end;

{enabled: true, certificate_path: required("TLS_CERT"), key_path: required("TLS_KEY")} as $tls |
{
  log: {level: "warn"},
  inbounds: [
    {type: "hysteria2", tag: "hy-in", listen: "::", listen_port: 443,
     users: [{name: "alice", password: required("HY2_PASSWORD")}], tls: $tls},
    {type: "vless", tag: "vless-in", listen: "::", listen_port: 443,
     users: [{name: "alice", uuid: required("VLESS_UUID")}], tls: $tls}
  ],
  outbounds: [{type: "direct", tag: "direct"}],
  dns: {
    servers: [
      {type: "udp", tag: "primary", server: "1.1.1.1"},
      {type: "udp", tag: "secondary", server: "8.8.8.8"}
    ],
    rules: [{domain_suffix: "example.net", action: "route", server: "secondary"}],
    final: "primary"
  },
  route: {
    rules: [
      {inbound: ["hy-in", "vless-in"], port: 53, action: "hijack-dns"},
      {action: "sniff"},
      {inbound: ["hy-in", "vless-in"], protocol: "dns", action: "hijack-dns"}
    ],
    final: "direct", default_domain_resolver: "primary"
  }
}
