# 节点来源说明

## 两个节点文件的来源

### 1. collected_nodes.txt (裸节点文件)
**来源**: `main.py` 在抓取网页(Telegram频道、网页等)时，直接提取的**裸节点链接**

**生成位置**: 
- `main.py` 的 `fetch_urls_from_page()` 方法（第352-358行）
- 使用正则表达式从网页内容中提取 `vmess://`, `vless://`, `trojan://` 等节点协议

**内容**: 只包含节点URL，例如：
```
vless://55d9ec38-1b8a-454b-981a-6acfe8f56d8c@172.64.145.144
trojan://5a2c16f9@104.26.1.110
vmess://ew0KICAidiI6I...
```

**数量**: 每轮不同，取决于本轮网页抓取量

**写入方式**: **每轮覆盖**，只保留本轮抓到的节点，不做跨轮累积

---

### 2. sub/all_nodes.txt (全量节点文件) ⭐推荐
**来源**: `main.py` **完整运行**后生成，**每轮覆盖**（只保留本轮抓到的节点，上一轮的历史节点不会保留）

**内容**: 每行一个节点链接，**不限制协议**——除了 `vmess/vless/trojan/ss/hysteria2/hysteria/tuic/anytls`，还包括 `ssr/snell/socks5/wireguard/ssh` 等本项目筛选器暂不支持的协议，方便自行下载后用自己的工具测试。

**数量**: 10 万级别（20MB+）

**用途**: 可直接通过 raw 链接下载，在任意客户端/脚本里自行测试和筛选

**写入逻辑**: 本轮订阅节点 ∪ 本轮网页抓取节点 → set 去重 → 排序 → 整体覆盖写入。去重是「字符串完全相等」，同一节点不同备注会各留一条。

> 注意：`node_quality_filter.py` 只处理它认识的 8 种协议，其余协议在筛选阶段会被跳过，但仍会完整保留在 `all_nodes.txt` 里。
> 旧文件名 `sub/sub_all_url_check.txt` 已废弃，`node_quality_filter.py` 仍兼容读取。

---

## 节点质量筛选工具 (node_quality_filter.py)

### 读取优先级
```
1. 优先读取: sub/all_nodes.txt          (全量节点)
2. 兼容读取: sub/sub_all_url_check.txt  (旧文件名)
3. 备用读取: collected_nodes.txt        (裸节点列表)
```

### 输出位置
```
sub/high_quality_nodes.txt     # 高质量节点列表
runtime/quality_report.json    # 质量分析报告
```

---

## 使用建议

### 最佳实践
1. **先运行** `python main.py` - 抓取节点和订阅
2. **再运行** `python node_quality_filter.py` - 筛选高质量节点
3. **查看结果** `sub/high_quality_nodes.txt` - 使用筛选后的节点

### 工作流程
```
Telegram频道 + 网页  →  main.py  →  collected_nodes.txt (裸节点)
                                   →  sub/all_nodes.txt   (全量节点)

sub/all_nodes.txt  →  node_quality_filter.py  →  sub/high_quality_nodes.txt
```

---

## 总结

| 文件 | 生成方式 | 内容 | 推荐用途 |
|------|---------|------|----------|
| `collected_nodes.txt` | main.py网页抓取 | 裸节点 | 直接抓取的节点 |
| `sub/all_nodes.txt` | main.py完整运行 | 全量节点 | 自行测试/筛选 ⭐ |
| `sub/high_quality_nodes.txt` | node_quality_filter.py | 高质量节点 | 最终使用 ⭐⭐ |
