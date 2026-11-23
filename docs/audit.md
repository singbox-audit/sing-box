# 部署与使用

审计版保留 sing-box v1.14.4 的配置文件和 CLI。VPS 运行一个二进制文件，本地电脑或 NAS 运行归档工具。首批验收协议为 HY2 和 VLESS。普通连接与明文 DNS 拦截分别计量。

## 构建和启动

在构建机的仓库根目录执行以下命令。示例构建 Linux amd64，ARM VPS 将 `GOARCH` 改为 `arm64`。两个构建标签启用 QUIC 系列协议和 Clash API。使用其他可选协议时，沿用对应的上游构建标签。

```sh
mkdir -p bin
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath \
  -tags 'with_quic with_clash_api' -ldflags '-s -w -checklinkname=0 -X github.com/sagernet/sing-box/constant.Version=1.14.4-audit' \
  -o bin/sing-box-audit ./cmd/sing-box
```

已有配置可以直接使用。将受审计入口的明文 TCP/UDP DNS 交给原版 `hijack-dns` 动作，并在 `dns.rules` 中选择公网解析器。首次部署也可用仓库中的 jq 模板生成配置。以下命令应在新配置目录中执行；先准备证书与私钥，并赋予服务账号读取权限。

```sh
umask 077
export TLS_CERT=/etc/sing-box/tls/fullchain.pem TLS_KEY=/etc/sing-box/tls/privkey.pem
export HY2_PASSWORD="$(openssl rand -hex 24)" VLESS_UUID="$(uuidgen)"
jq -n -f /path/to/singbox/release/config/audit-server.jq > config.json
unset HY2_PASSWORD VLESS_UUID
/usr/local/bin/sing-box-audit check -c config.json --audit-directory /var/log/sb-audit
/usr/local/bin/sing-box-audit run -c config.json --audit-directory /var/log/sb-audit --audit-min-free-mib 256
```

模板在 UDP 443 上接收 HY2，在 TCP 443 上接收 VLESS/TLS。两个入口各有一个名为 alice 的账号。为其他用户增加独立凭据和入口内唯一的名称。模板将 example.net 域名组交给第二个公网解析器，其他查询交给默认解析器，业务连接默认直连。按实际网络修改这些规则。客户端自己完成的解析、第三方加密 DNS 以及服务端为拨号发起的内部查询，均不进入客户端 DNS 明细。

使用仓库提供的 `sing-box.service` 时，安装二进制到 `/usr/local/bin/sing-box-audit`，将 `release/config/sing-box-audit.conf` 安装为 `/etc/systemd/system/sing-box.service.d/audit.conf`，配置放入 `/etc/sing-box/`。执行 `systemctl daemon-reload` 和 `systemctl restart sing-box` 后，用 `journalctl -u sing-box` 检查启动及磁盘告警。drop-in 继承原单元的运行用户、重启和重载行为。

## 同步、查询与导出

归档端需要 Python 3.11 或更高版本、uv、rsync 和 zstd。使用 SSH 拉取时，VPS 需要 rsync；启用源文件清理还需要 VPS 有 python3。首次运行下面的工具时，uv 根据脚本声明安装 DuckDB。在固定的归档目录运行，数据库视图引用该目录的绝对路径。

```sh
uv run tools/audit/archive.py --archive ./history pull user@vps:/var/log/sb-audit
uv run tools/audit/archive.py --archive ./history query \
  'SELECT * FROM daily_usage ORDER BY utc_day, inbound_tag, auth_user' > usage.csv
uv run tools/audit/archive.py --archive ./history query \
  "SELECT first_seen, inbound_tag, auth_user, qname, qtype, resolver, cache_hit, rcode, answers, write_error
   FROM dns_requests WHERE auth_user = 'alice' ORDER BY first_seen DESC" > dns.csv
```

将 pull 命令加入本地定时任务即可周期同步。默认保留 VPS 源卷；确认本地归档路径和备份策略后可加 `--remove-source`。工具仅处理已封卷文件，校验压缩流和内容摘要，将原卷、对应的 Parquet 和卷清单写入归档后，再由源主机按同名文件的 SHA-256 核对并删除。中断后重跑同一命令。若通过对象存储中转，先复制已封卷文件，再用 `import /path/to/downloads` 导入本地归档。

| 数据位置或视图 | 用途 |
| --- | --- |
| `raw/`、`parquet/{conn,dns}/day=YYYY-MM-DD/` | 保留原始压缩卷和按 UTC 日期分区的 Parquet。复制整个归档目录可备份；迁移路径后再运行一次 import 以重建视图。 |
| `audit.duckdb` 中的 `connections` | 每条连接或路由决定一行。包含入站账号、原始目标、嗅探域名、出站组选择链、观察到的拨号结果及累计字节。 |
| `dns_requests` | 每个收到的 DNS 请求一行。qtype 和 rcode 使用 DNS 数值编码。响应码 3 表示 NXDOMAIN，超时无响应码，可查 resolve_error。upstreams 记录实际调用的解析 transport 标签。 |
| `daily_usage` | 按相邻快照的增量统计普通连接，加上客户端 DNS 请求与写回的字节。跨午夜的增量归入后一个快照所在日期。 |
| `accounts` | 可选账号映射表。用 DuckDB 打开 audit.duckdb 后向表中插入入口标签、认证账号和统一账号 ID。原始入口和账号始终保留。 |

连接的 `result` 可以是 routed、connected、packet_session、rejected、selection_error 或 dial_error。UDP 会话建立只说明本地已配置转发。出站组标签数组反映当时的选择，实际目标 IP 只在直连路径能确定时填写。账号为空的记录在明细视图中标记 `missing_identity`。

## 故障与容量

VPS 同时只允许一个写入进程使用同一审计目录。256 条事件的有界队列满时，生产者等待写入。后台每秒或每类累积约 256 KiB 时压缩为独立帧，并同步文件。活跃会话每分钟记录累计快照。使用 debug 级别可观察队列峰值和同步延迟。高峰流量、磁盘阻塞和进程强杀均会扩大最后一个持久化点与故障发生之间的差距。

Linux 上 `--audit-min-free-mib` 控制接收新连接和 DNS 请求所需的最低磁盘余量；默认 0，部署示例为 256 MiB。低于两倍阈值会告警。低于阈值会拒绝新工作，给已有工作留出结算空间。写入失败时保留当前批次，运行期间重试同一文件偏移；持续写盘故障期间退出仍可能损失内存中的数据。释放空间后检查告警是否解除，优先同步已封卷文件。

重启时先验证上次 `.partial` 文件中的每个压缩帧，保留完整帧，将损坏尾部另存为 `.damaged`。不要在服务运行时清理工作文件或 `.run-id`。归档端收到上次进程结束标记后，会把只剩开始或快照的会话标为 interrupted，并保留最后可恢复的计数。尚未归档结束事件或进程结束标记时，报表显示 unfinished。

## 复验

```sh
go test -race ./common/audit ./protocol/dns ./dns ./route
uv run tools/audit/smoke.py ./bin/sing-box-audit
uv run tools/audit/routing_smoke.py ./bin/sing-box-audit --output /tmp/sb-routing-test
uv run --with duckdb==2.0.1 tools/audit/test_archive.py
```

DNS 用例在环回接口启动两种代理入口、两个客户端入口及两个测试解析器，要求 openssl、zstd 和 Linux procfs。可传入同版本官方二进制并加 `--baseline` 对照客户端结果。目标 VPS 的长期吞吐、DNS 延迟、Swap 活动和离线保留天数，需要结合实际用户流量测量。

路由用例要求一个新输出目录，使用 16 个并发客户端完成 512 条短连接，检查切组前后的流量归属、半关闭、拒绝和不支持 UDP 的出站，等待一次快照后强杀并重启测试子进程。脚本仅监听环回地址。
