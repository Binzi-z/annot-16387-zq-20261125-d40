# 分叉审计账本的离线对账与最小仲裁证据

仅使用 **Windows + Python 3.12 标准库**实现。三个断网站点的合成账本重联后，系统：

1. 重建 SHA-256 哈希链并识别同号异摘要；
2. 只按 **上游控制人** 计票：同一控制人名下的多个签收身份、换代密钥或重叠身份都只算一票；
3. 由 **两个独立控制人** 的有效回执确认共同前缀和最大可承诺水位；
4. 对缺段保持 `incomplete`，补段后只推进连续可用分区；
5. 隔离无法证明、分叉后、票数不足或已撤销/污点污染的分支；
6. 分支撤销具有永久性；重复投递旧回执不会使其回到可承诺集合；
7. 导出可由不导入本包的独立脚本 `verify_evidence.py` 复核的最小证据包。

## 一键运行

在仓库根目录（Windows cmd / PowerShell 均可）：

```bat
run_checks.cmd
```

或跨平台执行：

```bat
python run_checks.py
```

也可以手动分步执行：

```bat
python -m unittest discover -s tests -v
python scale_check.py
python run_demo.py
python verify_evidence.py artifacts\demo-evidence\evidence.json --keyring artifacts\demo-evidence\trusted-keyring.json
```

测试只使用本地合成数据；不会访问网络，也不依赖第三方包。

> 说明：HMAC 是标准库约束下的签收认证方式。`trusted-keyring.json` 是经带外渠道获得的信任根，包含 HMAC 密钥；`evidence.json` 本身不含密钥。独立复核工具需要同时持有证据包和可信 keyring。若部署到真实环境，可把 HMAC 替换为非对称签名，而不改变本仓库的对账、控制人计票和证据闭包逻辑。

## 核心语义

### 记录与段

每条记录的摘要覆盖：

```text
domain = audit-record-v1
preimage = {v, partition, seq, segment, prev, payload}
digest = SHA256(domain || NUL || canonical_json(preimage))
```

- 创世记录的 `prev` 为 64 个 `0`。
- 非创世记录必须满足 `prev == digest(seq - 1)`。
- `segment == seq // segment_size`。
- 缺父记录/缺段时状态为 `incomplete`，不会被当作有效证据。
- 同一 `seq` 出现多个不同摘要时进入 `sequence_conflicts`；只有两条记录都有效、共享同一 `prev` 且父点可验证时，才称为 **最早可证分叉**。

### 控制人票与账段换代

Keyring 中每个签收身份都映射到一个上游控制人，并可配置一个或多个账段有效期：

```json
{
  "identity-id": {
    "controller": "upstream-controller",
    "secret": "...",
    "epochs": [
      {"partition": "*", "first_segment": 0, "last_segment": 19},
      {"partition": "*", "first_segment": 20, "last_segment": null}
    ]
  }
}
```

回执只有同时满足以下条件才有效：

- HMAC 正确；
- 身份在回执所指账段处于有效期；
- 控制人/身份未被撤销，或撤销不适用于该账段；
- 目标记录存在、哈希链有效，且 `seq/segment/digest` 一致。

计票键是 `(seq, record_digest) -> set(controller_id)`。因此同一控制人的两个不同签收身份即使都签了同一检查点，`independent_votes` 仍是 **1**。同一控制人在同一 `seq` 对不同摘要出票属于 equivocation，该控制人在该高度的票全部排除。

### 最早可证分叉与最大水位

- `earliest_provable_fork`：哈希树中第一个拥有至少两个有效子节点的位置，给出分叉高度、共同前缀摘要和冲突摘要。
- `common_prefix_height/digest`：从创世点开始，每一步恰有一个有效子节点所能到达的最高唯一链点。
- `max_committable_watermark`：位于该唯一前缀上、未被分支撤销污点污染、且获得至少两个独立控制人有效票的最高 `seq`。
- `max_certified_watermark`：不要求位于共同前缀、但满足双控制人票数的最高安全检查点；它可能位于仍被隔离的竞争分支上。

分叉后的分支即使结构有效，也会标记 `contested-after-earliest-fork`；若没有足够独立票数，则继续以 `insufficient-independent-witness-quorum` 隔离。

### 撤销与旧回执重放

支持四类撤销对象：

- `controller`：撤销整个上游控制人；
- `identity`：只撤销一个签收身份；
- `receipt`：作废指定回执；
- `branch`：永久隔离指定候选摘要及其后代。

同一 `receipt_id` 的重复投递只计为重放，不产生新票。分支撤销形成 tombstone；其目标及所有后代都带污点，不能进入 `committable`。独立验证器还会显式把证据中的旧回执复制一遍后重新计票，断言候选分支仍不可承诺。

## 最小证据集合

`run_demo.py` 会生成：

```text
artifacts/demo-evidence/
├── evidence.json
└── trusted-keyring.json
```

`evidence.json` 包含：

- 协议版本和规范化 JSON 版本；
- 分区、段大小、所需控制人数；
- 去掉 HMAC 密钥的见证注册表和账段换代区间；
- 证明最大水位所需的祖先闭包；
- 最早可证分叉的共同父点和两个冲突子点；
- 所有被隔离分支的尖端及其祖先闭包；
- 分支撤销/见证撤销和相关旧回执；
- 最小性清单 `minimality_manifest.required_record_digests`；
- 对上述内容的 `bundle_digest`。

独立工具 [`verify_evidence.py`](verify_evidence.py) **不导入 `offline_audit` 包**，只用标准库重新实现规范化摘要、HMAC、哈希链、控制人计票、换代区间、撤销污点、最早分叉和水位计算。它还会检查：

```text
实际记录集合 == 证明目标的祖先闭包 == minimality manifest
```

因此多一条无关记录或少一条证明记录都会失败。

篡改测试会在保持 `bundle_digest` 自洽的情况下谎报水位；验证器仍会因重算水位不一致而返回非零退出码。

## 穷举与规模测试

### 穷举小账本

[`tests/test_exhaustive.py`](tests/test_exhaustive.py) 包括：

- 7 个事件的所有 `7! = 5040` 种输入顺序：分叉、同控制人双身份、双独立票；
- 两个控制人各 5 个换代边界的 `5 × 5` 组合，每种组合再穷举 5 个事件的 `5! = 120` 种顺序；
- 同号异摘要的 5 事件全排列；
- 同号但父摘要不同、尚不可证明的分支；
- 缺段时阻塞，补段后推进；
- 撤销控制人和候选分支后，包含重复旧回执在内的 7 事件所有 `5040` 种顺序。

每个排列都在全新 session 中重放，并比较完整报告的规范化 JSON，确保最终结果不依赖输入顺序。

### 60,000 条记录与三个远端缺段

[`scale_check.py`](scale_check.py) 生成：

- 60,000 条记录，序号 `0..59999`；
- 每 1,000 条一段，共 60 段；
- 本地初始缺少第 `17、38、52` 段；
- 三个远端来源分别提供一个缺段；
- 两个控制人在不同段边界交错换代；
- 在 `16999、37999、51999、59999` 处有双控制人检查点回执。

增量访问和水位推进应为：

| 阶段 | 新读取段 | 水位 |
|---|---:|---:|
| 初始本地前缀 | `0..16` | `16999` |
| 远端补入第 17 段 | `17..37` | `37999` |
| 远端补入第 38 段 | `38..51` | `51999` |
| 远端补入第 52 段 | `52..59` | `59999` |

脚本断言：

- 远端只被请求 `[17, 38, 52]`；
- 本地实际访问段恰好是 `0..59`；
- 缓存装载器对每段只 `get` 一次；
- 稀疏/局部修订报告与一次性载入全部 60,000 条的全量报告在所有裁决字段上完全相等。

## 目录

```text
offline_audit/
├── canonical.py    # 规范化 JSON、域分隔 SHA-256
├── witnesses.py    # HMAC keyring、控制人映射、账段 epoch
├── engine.py       # 顺序无关的对账、分叉、票数、撤销和水位
├── segments.py     # 段、远端源、带访问计数的缓存装载器
├── evidence.py     # 最小证据闭包导出
└── synthetic.py    # 小分叉世界和 60k 规模世界

tests/
├── test_exhaustive.py
├── test_evidence_verifier.py
└── test_scale_segments.py

verify_evidence.py  # 独立标准库复核工具，不导入 offline_audit
run_demo.py         # 小世界演示并导出证据
scale_check.py      # 60k 稀疏修订与全量一致性核对
run_checks.py       # 依次运行测试、规模检查、演示和独立验证
run_checks.cmd      # Windows 一键入口
```

## 当前验证状态

代码和自动化检查已经写好；在本编码会话中，除 `python --version` 外的 Python 执行命令被权限层拦截，因此未能由助手本人取得真实测试输出。请在可授权 Python 的 Windows 环境运行 `run_checks.cmd` 获取实际通过结果。所有脚本均设计为退出码 `0` 表示通过，断言失败则返回非零。
