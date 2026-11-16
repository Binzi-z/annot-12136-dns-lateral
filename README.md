# 边界 DNS 与横向移动检测

边界设备把 dnsmasq 查询与 sshd 登录混写进同一份日志，夜间批量任务多。

```
logs/auth.log   860 行（合成，含 2 起真实事件）
labels.json     2 个标注事件
detector/detector.py  基线检测器
tests/          骨架测试
```

## Run

```bash
python -m pytest tests -q
python detector/detector.py logs/auth.log findings.json
```

## 检测器（关联版）

不再逐行告警，而是把事件按实体关联成行为链，输出两个数组：

- `findings`：所有判别信号齐备时才上报，字段含 `rule`、`severity`、
  `first_seen` / `last_seen` / `window_seconds`、`entities`、`signals`、
  以及按 `seq` 编号的 `evidence` 事件链。
- `needs_review`：形态可疑但证据不足的序列，`missing_information`
  逐条写明还缺哪类信息才能定性。

| rule | 判据（全部满足才告警） |
|---|---|
| `dns_tunnel` | 同一客户端 5 分钟内 ≥8 次查询同一父域；前导标签 ≥20 字符、唯一率 ≥0.9、香农熵 ≥3.4、低元音、含数字，并具备编码形态（长辅音/数字串或 hex 级数字密度） |
| `lateral_movement` | 同一用户在 5 分钟窗口内从 ≥2 个“稳定工作站池”之外的一次性源 IP 以同一种 publickey 方式登录成功（池 = 全局认证 ≥3 次的 IP） |
| `brute_force` | 同源同账号 5 分钟内 ≥5 次失败密码；失败后若登录成功升级为 high。低于阈值（含“少量失败后成功”）进 `needs_review` |
| `path_scan` | 同源 5 分钟内 ≥4 次对敏感路径（`.env`/`.git`/`admin` 等）的 401/403/404 请求；低于阈值进 `needs_review` |

当前语料结果：2 条 findings（与 `labels.json` 两个标注事件一一对应），
2 条 needs_review（`.77` 的 3 次失败后成功、`.88` 的 2 次 403 探测），
对 840 行夜间批量良性流量零误报。

## 基线状态（已替换）

旧版 `detector.py` 对每条失败登录和每个请求各产出一条告警，不做任何关联：
不看失败之后有没有成功登录，不看同账号是否跨主机，也不看请求路径是否敏感。

## 标注事件

| kind | 说明 |
|---|---|
| `dns_tunnel` | DNS 隧道外传 |
| `lateral_movement` | 同一凭据跨主机横向移动 |

日志里另有故意放入的**良性相似流量**（少量失败后成功、被拒绝的少量探测），任何命中都算误报。
