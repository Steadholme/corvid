# Corvid — Steadholme 主权邮件服务

Corvid 是 Steadholme 栈的自建邮件服务，用 Rust 从零实现，**替换宿主机现有的 Postfix**。
单一进程内含五个协作部件，共享同一个 Postgres 数据层：

1. **入站 SMTP MTA**（`SMTP_ADDR`）：完整 ESMTP 状态机（EHLO/HELO、MAIL FROM、RCPT TO、
   DATA 带 dot-stuffing、RSET/NOOP/QUIT、STARTTLS）。只接收本域可投递收件人，未知收件人回
   `550`；对 `MAIL FROM` 做**建议性 SPF** 检查并写入 `Received-SPF` 头（v1 不硬拒）；解析
   RFC822 后落库。
2. **提交 + 出站中继**：提交监听器（`SUBMISSION_ADDR`，STARTTLS）；出站解析收件人域的 MX
   并经 `:25` 投递（机会式 STARTTLS），Postgres 队列 + 指数退避重试。
3. **DKIM**：**复用宿主机现有 OpenDKIM 私钥** `/etc/opendkim/keys/w33d.xyz/default.private`，
   selector `default`，`d=w33d.xyz`，`relaxed/relaxed` + `rsa-sha256`，签名头
   `From:To:Subject:Date:Message-ID:MIME-Version:Content-Type`。**对 DNS 零改动**——出站签名仍
   可被已发布的 `default._domainkey.w33d.xyz` TXT 校验（已有测试证明）。
4. **Webmail**（axum，`WEBMAIL_ADDR`）：落在网关 SSO 后的 `mail.w33d.xyz`，读取
   `X-Auth-Email` / `X-Auth-Subject` 选邮箱，自身**不做登录**。视图：收件箱、阅读（渲染净化后的
   正文 + 标记已读）、撰写、发送（构造 RFC822 → DKIM 签名 → 入队中继），POST 带 CSRF 双提交。
5. **SSO 临时邮箱**（与 Webmail 共用 `WEBMAIL_ADDR`）：登录用户在 `/temp` 创建、查看和释放
   `temp:{sub}` 绑定的随机地址；自动 TTL GC。自动化客户端可用 Keystone/SSO 签发的 Bearer key
   经 Sluice 调用 `/api/v1/temp-mailboxes` 下的完整管理 API，Corvid 只读取网关注入的
   subject/scope，不解析 token。SMTP 对临时域只接收仍有效且已创建的完整地址，不启用 catch-all；
   API 同样只收信，不提供发送、回复或转发能力。

## 组件 / 源码结构

| 文件 | 职责 |
|------|------|
| `src/config.rs` | 环境变量配置 + 收件人解析（本域/本地部分/catch-all） |
| `src/model.rs` | `Mailbox` / `Message` / `OutboundItem` 等数据类型 |
| `src/store.rs` | `Store` async trait + `InMemoryStore` + `PgStore`（可移植标准 SQL，运行期查询，无宏） |
| `src/smtp.rs` | ESMTP 会话状态机（`Session`）+ 监听器 + `SmtpStream`（Plain/TLS）STARTTLS 升级 |
| `src/relay.rs` | 出站入队（DKIM 签名 + 按域分组）+ 队列 worker + SMTP 客户端投递 |
| `src/dkim.rs` | DKIM 签名 + 独立验证（含从 `default.txt` 解析公钥参数） |
| `src/dns.rs` | 极简 UDP DNS（MX / TXT / A），无重型依赖 |
| `src/spf.rs` | 建议性 SPF（`ip4`/`a`/`mx`/`all` + 限定符） |
| `src/rfc822.rs` | RFC822/MIME 解析（头展开、RFC2047、QP/base64、一层 multipart） |
| `src/sanitize.rs` | 白名单式 HTML 净化（剥离 `<script>`/事件处理器/危险 URL） |
| `src/webmail.rs` | axum 路由 + 渲染 + 身份/CSRF + 邮箱选择 |
| `src/temp_mail.rs` | SSO 临时邮箱 ownership、配额、随机地址、释放与 TTL GC |
| `src/lib.rs` | `AppState`、装配、TLS acceptor、`run()` 启动全部监听器 + 中继 + webmail |

## 配置（环境变量）

| 变量 | 默认 | 说明 |
|------|------|------|
| `SMTP_ADDR` | `0.0.0.0:2525` | 入站 MTA 监听（构建/测试期用 alt 端口，**不绑 :25**） |
| `SUBMISSION_ADDR` | `0.0.0.0:2587` | 提交监听 |
| `WEBMAIL_ADDR` | `0.0.0.0:8800` | Webmail HTTP 监听（内网，网关 SSO 后） |
| `TLS_CERT` / `TLS_KEY` | 空 | STARTTLS 证书/私钥（`mail.w33d.xyz` 的 LE 证书）；为空则不广告 STARTTLS |
| `DKIM_KEY_PATH` | `/etc/opendkim/keys/w33d.xyz/default.private` | 复用的 DKIM 私钥 |
| `DKIM_SELECTOR` | `default` | DKIM selector |
| `MAIL_DOMAIN` | `w33d.xyz` | 规范域（DKIM `d=` + 主邮箱） |
| `MAIL_HOSTS` | `w33d.xyz,mail.w33d.xyz` | 入站可投递的收件人域 |
| `MAIL_LOCAL_PARTS` | `w33d,admin,postmaster` | 可投递本地部分（均投递到主邮箱） |
| `CORVID_CATCHALL` | `0` | 置 `1` 时未知本地部分也投递到主邮箱 |
| `MAIL_SEND_TOKEN` | 空 | 仅用于内部发送 API `/api/send` 的 Bearer key；与临时邮箱无关 |
| `TEMP_MAIL_DOMAINS` | 空 | 临时邮箱域 allowlist（逗号分隔）；仅已 provision 的完整地址可收信 |
| `TEMP_MAIL_MAX_PER_USER` | `10` | 每个 SSO subject 可持有的有效临时邮箱上限 |
| `TEMP_MAIL_TTL_DAYS` | `7` | 临时邮箱有效期（天），到期后立即不可读/不可投递并由 GC 清理 |
| `MAX_MSG_SIZE` / `MAX_RCPTS` | `10MiB` / `100` | 大小/收件人上限 |
| `DATABASE_URL` | — | `CORVID_STORE=postgres` 时必填（`postgres:5432/corvid`） |
| `CORVID_STORE` | `memory` | `memory` \| `postgres` |
| `RELAY_STARTTLS` | `1` | 出站对目标 MX 机会式 STARTTLS（置 `0` 关闭） |

## 邮箱模型

- `mailboxes(addr TEXT PK, owner_sub TEXT)`：地址 → Steadholme 身份 `sub`。启动时幂等 upsert 主邮箱
  `w33d@w33d.xyz`（owner `w33d`）。
- `w33d` / `admin` / `postmaster`（+ 可选 catch-all）均视为投递到**同一个主邮箱**（v1 别名）。
- `messages(id PK, mailbox, msg_from, msg_to, subject, raw_rfc822, body_text, body_html,
  received_at, seen DEFAULT FALSE, folder DEFAULT 'INBOX')`。
- `outbound_queue(id PK, raw, env_from, rcpts, to_domain, attempts, next_at, status)`。
- Webmail 按 `X-Auth-Subject`（owner_sub）选邮箱。
- 临时邮箱各自拥有独立 `mailboxes` 行，owner 为 `temp:{SSO subject}`；Web UI 与 API 共用同一
  listener 和 owner 边界。API 必须经过 Sluice，并使用 Keystone 账户页生成、带精确
  `corvid:temp-mail:manage` scope 的 `pat_...` key：

  ```http
  POST /api/v1/temp-mailboxes
  Authorization: Bearer <Keystone/SSO 生成的用户 key>
  Content-Type: application/json

  {}
  ```

  | 方法与固定路径 | JSON body | 作用 |
  |---|---|---|
  | `GET /api/v1/temp-mailboxes` | 无 | 列出本人仍有效的临时邮箱、到期时间和邮件数 |
  | `POST /api/v1/temp-mailboxes` | `{}` | 自动生成一个随机、只收信的临时邮箱 |
  | `POST /api/v1/temp-mailboxes/renew` | `{"address":"..."}` | 将本人邮箱有效期重置为一个完整 TTL |
  | `POST /api/v1/temp-mailboxes/messages/list` | `{"address":"...","limit":50,"before":null}` | 分页列出 Inbox 摘要，`limit` 最大为 `100` |
  | `POST /api/v1/temp-mailboxes/messages/get` | `{"address":"...","message_id":"..."}` | 读取净化后的正文和附件 metadata，不返回原始 RFC822 |
  | `POST /api/v1/temp-mailboxes/messages/attachments/get` | `{"address":"...","message_id":"...","index":0}` | 下载一个非 inline 附件 |
  | `DELETE /api/v1/temp-mailboxes/messages` | `{"address":"...","message_id":"..."}` | 幂等删除本人邮箱中的一封邮件 |
  | `DELETE /api/v1/temp-mailboxes` | `{"address":"..."}` | 幂等级联删除本人临时邮箱及其数据 |

  邮箱地址、消息 ID 和附件索引都放在小型 JSON body 中，不进入 URL 或 access log。Sluice 校验
  key 后剥离原始 `Authorization`，只注入签名 identity；Corvid 不接受 body 中的 owner/subject。
  读取/续期对不存在、他人、永久或过期邮箱统一返回 `404`；删除统一返回 `204`，避免存在性
  oracle；配额满为 `409`，输入非法为 `400`，鉴权失败为 `401/403`，存储故障为 `503`。所有 API
  响应均为 `Cache-Control: private, no-store` 和 `Vary: Authorization`。

## 构建 / 测试

```bash
cargo build
cargo clippy --all-targets -- -D warnings   # 干净
cargo test                                   # 含真实 DKIM 钥匙与临时邮箱 API 验证
```

- DKIM 往返测试 `tests/dkim_roundtrip.rs` 既用临时生成钥匙验证，也用**真实**
  `default.private` 签名并对**已发布的** `default.txt` 公钥校验通过。
- Postgres 集成测试默认跳过，设置 `TEST_DATABASE_URL` 后运行（见 `tests/pg_store.rs` 头部命令）。

## Alt-port 冒烟（不碰 :25）

`scripts/alt_port_smoke.sh`（或手动）会构建 `steadholme/corvid:dev`，用一次性 Postgres + 真实 DKIM
私钥 + 自签证书，在 `2525/2587/8800` 上跑：SMTP 注入 `w33d@w33d.xyz` → webmail 收件箱出现该信
→ 撰写发送 → 校验出站消息携带**有效 DKIM 签名**。结束后清理一次性容器。

## 部署（compose 片段，切换上线时启用）

```yaml
  corvid:
    build:
      context: ../corvid
    image: steadholme/corvid:dev
    environment:
      CORVID_STORE: postgres
      DATABASE_URL: ${CORVID_DATABASE_URL}   # postgres://steadholme:...@postgres:5432/corvid
      MAIL_DOMAIN: w33d.xyz
      DKIM_KEY_PATH: /run/dkim/default.private
      TLS_CERT: /run/mailcert/fullchain.pem
      TLS_KEY: /run/mailcert/privkey.pem
      SMTP_ADDR: 0.0.0.0:2525
      SUBMISSION_ADDR: 0.0.0.0:2587
      WEBMAIL_ADDR: 0.0.0.0:8800
    volumes:
      - /etc/opendkim/keys/w33d.xyz/default.private:/run/dkim/default.private:ro
      - /etc/letsencrypt/live/mail.w33d.xyz:/run/mailcert:ro
      - /etc/letsencrypt/archive/mail.w33d.xyz:/etc/letsencrypt/archive/mail.w33d.xyz:ro
    ports:
      - "25:2525"      # 仅在切换上线后启用，宿主机 Postfix 必须先停
      - "587:2587"
    depends_on:
      postgres:
        condition: service_healthy
    networks: [holdfast]
    restart: unless-stopped
```

> 先 `CREATE DATABASE corvid;`（与其它内容服务同 Postgres 用户/口令）。Webmail 不发布端口，由
> Sluice 在 `mail.w33d.xyz` 以 `auth=sso` 反代 `http://corvid:8800`。

## 切换上线（cutover）

宿主机现状：Postfix 占 `:25`（本地投递、无虚拟邮箱、队列空、**无可迁移邮件**），OpenDKIM 提供
milter；MX/SPF/DMARC/PTR/出站 `:25`/`mail.w33d.xyz` LE 证书均已就绪且**全部可复用**。

1. **建库**：在 Postgres 执行 `CREATE DATABASE corvid;`。
2. **构建镜像**：`docker build -t steadholme/corvid:dev ./corvid`。
3. **停宿主机邮件**：`systemctl stop postfix opendkim && systemctl disable postfix opendkim`，
   释放 `:25`。DKIM 私钥文件保留（Corvid 继续读它签名）。
4. **起 Corvid**：把上面的 compose 片段并入 `deploy/docker-compose.yml`（含 `25:2525`、
   `587:2587` 端口映射、DKIM 钥匙与 LE 证书只读挂载），`docker compose up -d corvid`。
5. **加路由**：在 Sluice 的 routes 表插入
   `{host: mail.w33d.xyz, path_prefix: /, upstream: http://corvid:8800, auth: sso}`
   （`routes.seed.json` 仅在空表时种子，需对运行库手动插入；autocert 随后会为 `mail.w33d.xyz`
   首次握手签发 LE 证书）。
6. **验证**：外部发信至 `w33d@w33d.xyz` → webmail 收件箱可见；从 webmail 发信 → 收件方校验
   DKIM=pass、SPF=pass；`dig MX/TXT`、PTR 不变。

**无需任何 DNS 改动**（MX `10 mail.w33d.xyz`、SPF、`default._domainkey`、DMARC、PTR 全部沿用）。

## 回滚（rollback）

1. 移除/停用 Corvid 的 `25:2525`、`587:2587` 端口映射（或 `docker compose stop corvid`），释放 `:25`。
2. `systemctl enable --now postfix opendkim`，宿主机 Postfix 用**同一把**钥匙/selector 重新占
   `:25`，DKIM 依旧有效。
3. 删除 Sluice 中 `mail.w33d.xyz` 的路由。
4. 同样**无需 DNS 改动**，正反向切换都对外透明。

## 已推迟（DEFER，v1 不做）

- 面向外部客户端的完整 IMAP4（`:143`/`:993`）；
- 应用专用密码（app-passwords）；
- 多文件夹 / 搜索；
- greylisting。

> v1 的唯一客户端是 Webmail。
