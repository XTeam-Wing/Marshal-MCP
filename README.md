# 漏洞扫描 MCP 服务器

基于 [github.com/ThinkInAIXYZ/go-mcp](https://github.com/ThinkInAIXYZ/go-mcp) 实现的 MCP 服务器，用于自动化应急响应下的漏洞扫描任务。

## 功能特点

- 接收漏洞特征和扫描URL列表
- 自动生成 nuclei 漏洞扫描 POC
- 上传 POC 到 Marshal 平台
- 创建扫描工作流
- 自动创建并提交扫描任务
- 支持自定义扫描参数（集群、优先级、端口等）
- 同时支持 HTTP API 和 MCP 协议

## 快速开始

### 安装和运行

```bash
# 克隆仓库
git clone https://github.com/your-username/marshal-mcp.git
cd marshal-mcp

# 编译
go build -o marshal-mcp .

# 运行
./marshal-mcp --config=config/config.yaml
```

### 配置文件

修改 `config/config.yaml` 文件：

```yaml
# MCP服务器配置
server:
  port: 8000
  timeout: 60

# Marshal API配置
api:
  url: "http://your-marshal-api-url"  # Marshal API服务地址
  token: "your-api-token"             # API认证令牌（必填）
```

**注意**: `api.token` 字段是必填的，用于 Marshal API 的认证。请确保设置了有效的 token 值。

## 使用方法

### MCP 协议
在支持 MCP 的客户端中使用

## 参数说明

| 参数名 | 类型 | 必填 | 默认值 | 说明 |
|--------|------|------|--------|------|
| vuln_name | string | 是 | - | 漏洞名称 |
| vuln_desc | string | 是 | - | 漏洞描述/特征 |
| urls | string[] | 是 | - | 需要扫描的URL列表 |
| cluster | string | 是 | - | 扫描集群 |
| priority | string | 否 | low | 优先级(high/medium/low) |
| task_name | string | 否 | 年月日-漏洞名称 | 任务名称 |
| task_num | int | 否 | 100 | 任务数量 |
| cycle_scan | bool | 否 | false | 是否周期扫描 |
| domain | string | 否 | - | 域名 |
| ip | string | 否 | - | IP地址 |
| port | string | 否 | 1-65535 | 扫描端口范围 |
| engine | string | 否 | naabu | 扫描引擎(naabu/osint) |
| interval_days | int | 否 | 7 | 扫描间隔天数 |
## API认证说明

本服务器调用的Marshal API需要认证。认证方式为在HTTP请求头中添加`Authorization`字段：

```
Authorization: <your-token>
```

确保在`config/config.yaml`中正确设置了`api.token`字段，服务器会自动将其添加到所有API请求中。