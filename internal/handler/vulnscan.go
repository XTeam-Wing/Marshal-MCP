package handler

import (
	"fmt"
	"marshal-mcp/internal/config"
	"marshal-mcp/internal/service"

	"github.com/ThinkInAIXYZ/go-mcp/protocol"
)

// MCPHandler MCP协议处理器
type MCPHandler struct {
	Cfg *config.Config
}

// HandleVulnScanRequest 处理MCP协议的漏洞扫描请求
func (h *MCPHandler) HandleVulnScanRequest(req *protocol.CallToolRequest) (*protocol.CallToolResult, error) {
	var vulnReq service.VulnScanRequest
	if err := protocol.VerifyAndUnmarshal(req.RawArguments, &vulnReq); err != nil {
		return nil, fmt.Errorf("解析请求参数失败: %v", err)
	}
	// 创建服务实例
	scanService := service.NewScanService(h.Cfg)

	// 处理扫描请求
	result, err := scanService.ProcessVulnScan(&vulnReq)
	if err != nil {
		return nil, fmt.Errorf("处理漏洞扫描任务失败: %v", err)
	}

	return &protocol.CallToolResult{
		Content: []protocol.Content{
			protocol.TextContent{
				Type: "text",
				Text: fmt.Sprintf("已为漏洞 '%s' 生成扫描任务，任务ID: %s", vulnReq.VulnName, result.TaskID),
			},
		},
	}, nil
}
