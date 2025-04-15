package main

import (
	"flag"
	"fmt"

	"github.com/ThinkInAIXYZ/go-mcp/protocol"
	"github.com/ThinkInAIXYZ/go-mcp/server"
	"github.com/ThinkInAIXYZ/go-mcp/transport"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/gologger/levels"

	"marshal-mcp/internal/config"
	"marshal-mcp/internal/handler"
	"marshal-mcp/internal/service"
)

var (
	configPath = flag.String("config", "config/config.yaml", "配置文件路径")
	debug      = flag.Bool("debug", false, "调试模式")
)

func main() {
	flag.Parse()
	if *debug {
		gologger.DefaultLogger.SetMaxLevel(levels.LevelDebug)
	} else {
		gologger.DefaultLogger.SetMaxLevel(levels.LevelInfo)
	}
	// 加载配置
	cfg, err := config.LoadConfig(*configPath)
	if err != nil {
		gologger.Fatal().Msgf("加载配置失败: %v", err)
	}

	// 创建MCP服务器
	addr := fmt.Sprintf(":%d", cfg.Server.Port)
	transportServer, err := transport.NewSSEServerTransport(addr)
	if err != nil {
		gologger.Fatal().Msgf("创建MCP传输服务器失败: %v", err)
	}

	mcpServer, err := server.NewServer(transportServer)
	if err != nil {
		gologger.Fatal().Msgf("创建MCP服务器失败: %v", err)
	}

	// 注册MCP工具: 漏洞扫描工具
	vulnScanTool, err := protocol.NewTool(
		"vuln_scan",
		"生成漏洞扫描任务",
		service.VulnScanRequest{},
	)
	if err != nil {
		gologger.Fatal().Msgf("注册漏洞扫描工具失败: %v", err)
	}

	mcpHandler := &handler.MCPHandler{
		Cfg: cfg,
	}
	mcpServer.RegisterTool(vulnScanTool, mcpHandler.HandleVulnScanRequest)

	// 启动MCP服务器
	gologger.Info().Msgf("MCP 服务器启动在 http://localhost%s/sse", addr)
	gologger.Info().Msgf("API地址: %s", cfg.API.URL)
	if err = mcpServer.Run(); err != nil {
		gologger.Fatal().Msgf("MCP服务器运行失败: %v", err)
	}
}
