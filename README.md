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

## 基线状态

`detector/detector.py` 对每条失败登录和每个请求各产出一条告警，不做任何关联：
不看失败之后有没有成功登录，不看同账号是否跨主机，也不看请求路径是否敏感。

## 标注事件

| kind | 说明 |
|---|---|
| `dns_tunnel` | DNS 隧道外传 |
| `lateral_movement` | 同一凭据跨主机横向移动 |

日志里另有故意放入的**良性相似流量**（少量失败后成功、被拒绝的少量探测），任何命中都算误报。
