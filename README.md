# WebSecLab — 基于 DVWA 的 Web 漏洞分析与复现平台

> 网络安全漏洞知识管理 + 实验复现 + 安全扫描 + AI 智能分析 + 风险评估 + 知识图谱一体化的教学/研究平台。

WebSecLab 面向安全教学与攻防研究，将"漏洞知识库 → 实验复现 → 端口/服务扫描 → AI 漏洞分析 → 风险评估 → 实验报告"串成一条可追踪的闭环，并用知识图谱把零散的漏洞、CVE、CWE、分类、修复方案关联起来，辅助理解攻击面与关联关系。

---

## 功能特性

| 模块 | 能力 |
|------|------|
| **用户 & 权限** | 注册 / 登录 / 退出；RBAC 五角色（admin / teacher / student / auditor / researcher），细粒度权限码控制 |
| **漏洞知识库** | 漏洞 CRUD、分类（自定义分类 + OWASP Top 10）、CVSS 评分、等级筛选/排序、参考链接、轻量文本渲染 |
| **实验管理** | 实验创建（关联漏洞）、实验步骤日志（时间线）、Token 一键复制、实验耗时统计、关联 AI 报告 |
| **安全扫描** | 融合 Socket 端口扫描与 Nmap 扫描；后台异步执行、进度轮询；结果持久化与历史列表 |
| **AI 智能分析** | 支持本地 Ollama 或云端 API（DeepSeek / DashScope / OpenAI）；可配置 Prompt 模板；RAG 检索增强；分析历史管理 |
| **RAG 知识增强** | 基于 ChromaDB 向量库对漏洞知识做语义检索，自动拼接到分析 Prompt |
| **知识图谱** | NetworkX 构建漏洞关联图谱（漏洞 / 分类 / OWASP / CVE / CWE / 修复方案 / 攻击方式），ECharts 力导向可视化，详情页内嵌 ego 子图 |
| **风险评估** | 自有多因素风险评分引擎 `RiskEngine`（CVSS / 资产重要性 / 利用成功度 / 暴露面 / AI 置信度加权） |
| **实验报告** | 基于 ReportLab 生成 PDF 实验报告 |
| **Dashboard** | 安全态势可视化统计（管理员/用户双视图、告警、用户排行、下钻） |
| **MCP 工具链** | `mcp_manager` 编排「扫描 → 知识 → 风险 → 仪表盘」工具链并聚合分析报告 |
| **NVD 同步** | 通过 NVD 2.0 REST API 增量同步公开 CVE 到本地知识库（CWE→分类映射、CVSS→等级、去重） |

---

## 技术栈

- **后端**：Python 3.11+ / Flask 3.1（应用工厂模式 + Blueprint 模块化）
- **ORM / 数据库**：Flask-SQLAlchemy + SQLite（开发/生产）
- **认证 / 防护**：Flask-Login、Flask-WTF（CSRF 防护默认开启）、Werkzeug
- **前端**：Jinja2 模板 + Bootstrap + **HTMX**（列表筛选/排序/分页局部刷新，无整页跳转）+ ECharts
- **AI / 向量**：Ollama（本地 LLM）、OpenAI 兼容 API、ChromaDB（RAG 向量库）
- **图谱 / 算法**：NetworkX（知识图谱）
- **扫描**：原生 Socket 端口扫描 + Nmap（`python-nmap` 需系统安装 nmap）
- **报告**：ReportLab（PDF）
- **测试**：pytest（213 个用例）

---

## 快速开始

### 1. 安装依赖

```bash
pip install -r requirements.txt
```

> 如需 Nmap 扫描能力，请额外在系统中安装 [nmap](https://nmap.org/) 并确保可执行文件在 `PATH` 中。

### 2. 配置环境变量（可选）

复制并编辑 `.env`（项目已内置 `.env`，可直接修改）：

```ini
# LLM 接入方式: ollama (本地) 或 api (云端)
LLM_MODE=ollama
# 云端 API 提供商: deepseek / dashscope / openai
LLM_API_PROVIDER=deepseek
LLM_API_KEY=your-api-key
# LLM_API_BASE_URL=   # 留空使用提供商默认
# LLM_API_MODEL=      # 留空使用提供商默认

# 生产环境务必设置固定 SECRET_KEY，否则每次重启会话失效
# SECRET_KEY=change-me-to-a-strong-random-string

# 生产 HTTPS 部署时设为 true 开启 Cookie Secure 标志
# SESSION_COOKIE_SECURE=true
```

详见下方「配置说明」。

### 3. 初始化管理员账号

```bash
python scripts/create_admin.py
```

默认管理员：`admin` / `admin123`（首次运行自动创建；也可注册普通用户）。

### 4. 启动应用

```bash
python run.py
```

访问 http://127.0.0.1:5000

> 应用启动时会自动 `db.create_all()` 建表，并增量补齐历史库缺失列、种子化 RBAC 角色/权限与默认 Prompt 模板，无需手动执行迁移命令。

---

## 配置说明

所有配置集中在 `app/config.py`，通过环境变量驱动：

| 环境变量 | 默认值 | 说明 |
|----------|--------|------|
| `FLASK_ENV` | `default`（=development） | 运行环境：`development` / `testing` / `production` |
| `SECRET_KEY` | 运行期随机生成（告警） | 会话签名密钥，生产环境必须固定设置 |
| `LLM_MODE` | `ollama` | `ollama` 本地模型 或 `api` 云端模型 |
| `LLM_API_PROVIDER` | `deepseek` | `deepseek` / `dashscope` / `openai` |
| `LLM_API_KEY` | 空 | 云端 API 密钥 |
| `LLM_API_BASE_URL` | 空（用提供商默认） | 自定义 API 基址（私有化部署用） |
| `LLM_API_MODEL` | 空（用提供商默认） | 指定模型名 |
| `SESSION_COOKIE_SECURE` | `false` | 生产 HTTPS 部署设为 `true` |

---

## 项目结构

```
WebSecLab/
├── app/
│   ├── __init__.py            # 应用工厂 create_app() + 蓝图注册 + 自定义过滤器
│   ├── config.py              # 开发/测试/生产配置
│   ├── extensions.py          # 扩展 (db, migrate, login_manager, csrf)
│   ├── logging_config.py      # 结构化日志
│   ├── models/                # ORM 模型
│   │   ├── user.py            # 用户
│   │   ├── vulnerability.py   # 漏洞 + 分类 + OWASP
│   │   ├── experiment.py      # 实验 + 实验日志
│   │   ├── scan.py            # 扫描任务 + 结果
│   │   ├── ai_analysis.py     # AI 分析记录
│   │   ├── report.py          # 报告
│   │   ├── prompt_template.py # Prompt 模板
│   │   ├── risk.py            # 风险评估
│   │   └── rbac.py            # 角色 / 权限
│   ├── routes/                # 视图蓝图
│   │   ├── auth.py            # 注册/登录/退出
│   │   ├── main.py            # 首页/导航
│   │   ├── vulnerability.py   # 漏洞知识库 (列表/详情/增改/同步)
│   │   ├── experiment.py      # 实验管理
│   │   ├── scan.py            # 安全扫描
│   │   ├── ai.py              # AI 分析与历史
│   │   ├── report.py          # 报告
│   │   ├── dashboard.py       # 仪表盘
│   │   ├── risk.py            # 风险评估
│   │   ├── mcp.py             # MCP 工具链面板
│   │   └── knowledge_graph.py # 知识图谱
│   ├── services/              # 业务逻辑层
│   │   ├── auth_service.py / vulnerability_service.py / experiment_service.py
│   │   ├── ai_service.py / prompt_service.py / rag_service.py / chroma_service.py
│   │   ├── ollama_service.py / openai_service.py
│   │   ├── knowledge_graph_service.py / risk_service.py / dashboard_service.py
│   │   ├── scanner_service.py / nmap_service.py / socket_scanner.py / scanner/
│   │   ├── dvwa_service.py / nvd_sync_service.py / report_service.py
│   │   └── mcp/               # MCP 工具链 (manager/executor/registry/base_tool)
│   ├── utils/                 # permission.py (RBAC 装饰器) / token.py / pdf_generator.py
│   ├── templates/             # Jinja2 模板 (按模块分目录)
│   └── static/                # 静态资源 (vendor: echarts 等)
├── database/
│   └── webseclab.db           # SQLite 数据库
├── scripts/
│   ├── create_admin.py        # 管理员初始化
│   ├── init_vulnerability.py  # 漏洞种子数据
│   ├── init_experiment.py     # 实验种子数据
│   ├── migrate_add_*.py       # 历史库增量迁移脚本
│   └── test_*.py              # 功能自测脚本 (nmap/ollama/ai/phase6)
├── tests/                     # pytest 测试套件 (213 用例)
├── reports/                   # 生成的 PDF 报告输出
├── logs/                      # 运行日志
├── requirements.txt
├── pytest.ini
├── run.py                     # 应用入口
└── .env                       # 环境变量 (LLM 等)
```

---

## 账号与权限体系

| 角色 | 典型用途 | 关键权限 |
|------|----------|----------|
| `admin` 管理员 | 平台管理 | 全部权限（用户管理、漏洞库管理、实验管理、知识图谱管理、审计） |
| `teacher` 教师 | 课程教学 | 实验/漏洞库/AI/Prompt/知识图谱管理 + 查看仪表盘 |
| `student` 学生 | 学习复现 | 创建实验、启动扫描、AI 分析、生成报告、查看知识库 |
| `auditor` 审计员 | 合规审查 | 查看实验/扫描/AI/报告/风险/知识库 + 审计日志 |
| `researcher` 研究员 | 高级研究 | 扫描/AI/Prompt/知识图谱管理 + 漏洞库管理 |

权限以 `code` 形式定义（如 `experiment:create`、`vulnerability:manage`、`ai:analyze`），角色到权限为多对多关联，启动时由 `_seed_rbac()` 自动初始化。

---

## AI 分析配置

AI 分析是平台核心能力之一，支持两种接入方式：

1. **本地 Ollama**（默认，无需外网）
   - 安装并启动 Ollama，拉取模型（如 `qwen2.5`、`llama3`）
   - `.env` 设置 `LLM_MODE=ollama`
2. **云端 API**
   - `.env` 设置 `LLM_MODE=api`、`LLM_API_PROVIDER=deepseek|dashscope|openai`、`LLM_API_KEY=...`
   - 可选 `LLM_API_BASE_URL` / `LLM_API_MODEL` 指定私有化地址与模型

分析时可选择 Prompt 模板（管理员可在后台增改模板），并自动通过 ChromaDB 检索相关漏洞知识做 RAG 增强。

---

## 测试

```bash
# 运行全部测试 (213 用例)
python -m pytest

# 运行指定模块
python -m pytest tests/test_ai.py
python -m pytest tests/test_experiment.py tests/test_vulnerability.py
```

测试配置见 `pytest.ini`（默认 `-v --tb=short`，忽略 DeprecationWarning）。

---

## 知识图谱

- 图谱由 `KnowledgeGraphService` 基于 NetworkX 构建并缓存，节点类型涵盖漏洞、分类、OWASP、CVE、CWE、修复方案、攻击方式。
- 可视化页 `/knowledge-graph` 使用 ECharts 力导向图展示全图。
- 漏洞/实验详情页内嵌 **ego 子图**（以当前节点为中心的 1 跳邻域），通过 `/knowledge-graph/api/ego/<node_id>` 公开端点获取，无需加载整图。

---

## 开发说明

- **应用工厂**：`create_app(config_name)` 统一初始化扩展、注册蓝图与自定义 Jinja 过滤器。
- **自定义过滤器**：`light_format` 提供轻量文本渲染（先 HTML 转义防 XSS，再解析围栏/行内代码块，换行转 `<br>`），用于漏洞正文与实验结果的富文本展示，不引入额外 Markdown 库。
- **启动自愈迁移**：`create_app` 在 `app_context` 内执行 `db.create_all()` 并增量补齐历史库缺失列（`_ensure_scan_display_id` / `_ensure_vulnerability_schema`），降低库结构变更成本。
- **安全基线**：CSRF 默认开启；Cookie 设 `HttpOnly` / `SameSite=Lax`；生产环境通过 `SESSION_COOKIE_SECURE` 开启 `Secure`；`SECRET_KEY` 不再硬编码弱默认值。
- **HTMX 交互**：列表页（漏洞/实验/AI 历史）筛选、排序、分页均走 HTMX 局部刷新，体验一致且无整页跳转。

---

## 后续可扩展方向

- 实验详情页反向回链关联漏洞、管理员漏洞编辑页一键创建关联实验
- 新建漏洞自动增量更新知识图谱子图
- `/ai/result` 分析详情页富化、扫描列表搜索筛选补齐
- 多用户协作、报告模板自定义、图谱社区发现与分析

---

## 许可证

内部教学/研究用途。
