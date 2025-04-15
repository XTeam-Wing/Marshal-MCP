package service

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"time"

	"marshal-mcp/internal/config"

	"github.com/projectdiscovery/gologger"
	"gopkg.in/yaml.v2"
)

// VulnScanRequest 漏洞扫描请求
type VulnScanRequest struct {
	VulnName     string   `json:"vuln_name" description:"漏洞名称" required:"true"`         // 漏洞名称
	Poc          string   `json:"poc" description:"poc内容" required:"true"`              // poc内容
	Urls         []string `json:"urls" description:"需要扫描的文件内容" required:"true"`         // 需要扫描的文件url列表
	Cluster      string   `json:"cluster" description:"扫描集群（必选）" required:"true"`       // 扫描集群（必选）
	Priority     string   `json:"priority" description:"优先级（必选，默认low）" required:"true"` // 优先级（必选，默认low）
	TaskName     string   `json:"task_name" description:"任务名称"`                         // 任务名称（可选）
	TaskNum      int      `json:"task_num" description:"任务数量"`                          // 任务数量（可选，默认100）
	CycleScan    bool     `json:"cycle_scan" description:"是否周期扫描"`                      // 是否周期扫描（可选，默认false）
	Domain       string   `json:"domain" description:"域名"`                              // 域名（可选）
	IP           string   `json:"ip" description:"IP"`                                  // IP（可选）
	Port         string   `json:"port" description:"扫描端口"`                              // 扫描端口（可选，默认1-65535）
	Engine       string   `json:"engine" description:"扫描引擎"`                            // 扫描引擎（naabu/osint，默认naabu）
	IntervalDays int      `json:"interval_days" description:"扫描间隔天数"`                   // 扫描间隔天数（可选，默认7）
}

// VulnScanResult 漏洞扫描结果
type VulnScanResult struct {
	TaskID     string `json:"task_id"`     // 任务ID
	TaskName   string `json:"task_name"`   // 任务名称
	WorkflowID string `json:"workflow_id"` // 工作流ID
	PluginID   string `json:"plugin_id"`   // 插件ID
}

// ScanService 扫描服务
type ScanService struct {
	cfg *config.Config
}

// NewScanService 创建扫描服务
func NewScanService(cfg *config.Config) *ScanService {
	return &ScanService{
		cfg: cfg,
	}
}

// PluginUploadReq 用于 /plugin/upload
type PluginUploadReq struct {
	Data        string `json:"data"`        // poc内容
	Level       string `json:"level"`       // poc级别
	Name        string `json:"name"`        // poc名称
	Description string `json:"description"` // 描述
	Type        string `json:"type"`        // nuclei/yak
}

// PluginUploadResp 用于 /plugin/upload 响应
type PluginUploadResp struct {
	Code int    `json:"code"`
	Msg  string `json:"msg"`
	Data struct {
		PluginID string `json:"plugin_id"`
	} `json:"data"`
}

// WorkFlowReq 用于 /workflow/add
type WorkFlowReq struct {
	Name          string   `json:"name"`           // 工作流名称
	Content       []string `json:"content"`        // 内容，plugin_id 列表
	DefaultPolicy bool     `json:"default_policy"` // 是否默认策略
}

// WorkFlowResp 用于 /workflow/add 响应
type WorkFlowResp struct {
	Code int    `json:"code"`
	Msg  string `json:"msg"`
	Data struct {
		ID int `json:"id"`
	} `json:"data"`
}

// TaskConfig 扫描任务配置
type TaskConfig struct {
	Port              string `json:"port"`               // 端口范围，如 1-65535
	PortscanEngine    string `json:"portscan_engine"`    // 端口扫描引擎 (naabu/osint)
	PortScan          bool   `json:"port_scan"`          // 是否端口扫描
	VulnerabilityScan bool   `json:"vulnerability_scan"` // 是否漏洞扫描
	Workflow          string `json:"workflow"`           // 工作流ID
}

// TaskCreateReq 用于 /task/create
type TaskCreateReq struct {
	TaskName  string     `json:"task_name"`        // 任务名称
	Cluster   string     `json:"cluster"`          // 集群
	Priority  string     `json:"priority"`         // 优先级（high/medium/low）
	CycleScan bool       `json:"cycle_scan"`       // 是否周期扫描
	TaskNum   int        `json:"task_num"`         // 任务数量
	Cycles    int        `json:"cycles,omitempty"` // 周期数量
	Domain    string     `json:"domain,omitempty"` // 域名
	IP        string     `json:"ip,omitempty"`     // IP
	Config    TaskConfig `json:"config"`           // 任务配置
	Urls      string     `json:"urls"`             // 需要扫描的文件url列表
}

// TaskCreateResp 用于 /task/create 响应
type TaskCreateResp struct {
	Code int    `json:"code"`
	Msg  string `json:"msg"`
	Data struct {
		TaskID string `json:"task_id"`
	} `json:"data"`
}

// ProcessVulnScan 处理漏洞扫描请求
func (s *ScanService) ProcessVulnScan(req *VulnScanRequest) (*VulnScanResult, error) {
	// 设置默认值
	if req.Priority == "" {
		req.Priority = "low"
	}
	if req.TaskNum == 0 {
		req.TaskNum = 100
	}
	if req.Port == "" {
		req.Port = "1-65535"
	}
	if req.Engine == "" {
		req.Engine = "naabu"
	}
	if req.TaskName == "" {
		req.TaskName = time.Now().Format("20060102") + "-" + req.VulnName
	}
	if req.IntervalDays == 0 {
		req.IntervalDays = 7
	}

	// 1. 直接上传用户传入的poc
	pluginID, err := s.uploadNucleiPlugin(req.Poc)
	if err != nil {
		return nil, fmt.Errorf("上传POC失败: %v", err)
	}

	// 2. 创建workflow
	workflowName := "workflow-" + req.TaskName
	workflowID, err := s.createWorkflow(workflowName, []string{pluginID})
	if err != nil {
		return nil, fmt.Errorf("创建Workflow失败: %v", err)
	}

	// 3. 创建扫描任务
	taskReq := TaskCreateReq{
		TaskName:  req.TaskName,
		Cluster:   req.Cluster,
		Priority:  req.Priority,
		CycleScan: req.CycleScan,
		TaskNum:   req.TaskNum,
		Domain:    req.Domain,
		Cycles:    req.IntervalDays,
		IP:        req.IP,
		Config: TaskConfig{
			Port:              req.Port,
			PortscanEngine:    req.Engine,
			PortScan:          false,
			VulnerabilityScan: true,
			Workflow:          workflowName,
		},
		Urls: strings.Join(req.Urls, "\n"),
	}

	taskID, err := s.createTask(taskReq)
	if err != nil {
		return nil, fmt.Errorf("创建任务失败: %v", err)
	}

	// 4. 返回结果
	return &VulnScanResult{
		TaskID:     taskID,
		TaskName:   req.TaskName,
		WorkflowID: fmt.Sprintf("%d", workflowID),
		PluginID:   pluginID,
	}, nil
}

type NucleiTemplate struct {
	ID   string `json:"id" yaml:"id"` // 模板ID
	Info struct {
		Name        string `json:"name" yaml:"name"`               // 模板名称
		Author      string `json:"author" yaml:"author"`           // 作者
		Severity    string `json:"severity" yaml:"severity"`       // 严重性
		Description string `json:"description" yaml:"description"` // 描述
		Tags        string `json:"tags" yaml:"tags"`               // 标签
	} `json:"info" yaml:"info"` // 模板信息
}

func (n *NucleiTemplate) GetLevel() string {
	switch n.Info.Severity {
	case "info":
		return "提示"
	case "low":
		return "低危"
	case "medium":
		return "中危"
	case "high":
		return "高危"
	case "critical":
		return "严重"
	default:
		return "低危"
	}
}

// uploadNucleiPlugin 上传 nuclei poc，返回 plugin_id 或错误
// 只保留name和poc参数
func (s *ScanService) uploadNucleiPlugin(poc string) (string, error) {
	nucleiTpl := NucleiTemplate{}
	if err := yaml.Unmarshal([]byte(poc), &nucleiTpl); err != nil {
		return "", fmt.Errorf("解析poc失败: %v", err)
	}
	reqBody := PluginUploadReq{
		Data:        poc,
		Name:        nucleiTpl.Info.Name,
		Description: "",                   // 不再需要描述
		Level:       nucleiTpl.GetLevel(), // 设置为高危
		Type:        "nuclei",
	}

	b, err := json.Marshal(reqBody)
	if err != nil {
		return "", err
	}

	// 创建请求并添加认证头
	req, err := http.NewRequest("POST", s.cfg.API.URL+"/plugin/upload", bytes.NewReader(b))
	if err != nil {
		return "", err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", s.cfg.API.Token) // 添加认证头

	// 发送请求
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, _ := ioutil.ReadAll(resp.Body)
	var pluginResp PluginUploadResp
	if err := json.Unmarshal(body, &pluginResp); err != nil {
		return "", err
	}

	if pluginResp.Code != 200 {
		return "", fmt.Errorf("plugin upload failed: %s", pluginResp.Msg)
	}

	return nucleiTpl.ID, nil
}

// createWorkflow 创建工作流，返回工作流ID和错误
func (s *ScanService) createWorkflow(name string, pluginIDs []string) (int, error) {
	reqBody := WorkFlowReq{
		Name:          name,
		Content:       pluginIDs,
		DefaultPolicy: false,
	}

	b, err := json.Marshal(reqBody)
	if err != nil {
		return 0, err
	}

	// 创建请求并添加认证头
	req, err := http.NewRequest("POST", s.cfg.API.URL+"/workflow/add", bytes.NewReader(b))
	if err != nil {
		return 0, err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", s.cfg.API.Token) // 添加认证头

	// 发送请求
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	body, _ := ioutil.ReadAll(resp.Body)
	var workflowResp WorkFlowResp
	if err := json.Unmarshal(body, &workflowResp); err != nil {
		return 0, err
	}

	if workflowResp.Code != 200 {
		return 0, fmt.Errorf("workflow creation failed: %s", workflowResp.Msg)
	}

	return workflowResp.Data.ID, nil
}

// createTask 创建扫描任务，返回任务ID和错误
func (s *ScanService) createTask(req TaskCreateReq) (string, error) {
	b, err := json.Marshal(req)
	if err != nil {
		return "", err
	}

	// 创建请求并添加认证头
	httpReq, err := http.NewRequest("POST", s.cfg.API.URL+"/task/create", bytes.NewReader(b))
	if err != nil {
		return "", err
	}

	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", s.cfg.API.Token) // 添加认证头

	// 发送请求
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
	resp, err := client.Do(httpReq)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, _ := ioutil.ReadAll(resp.Body)
	gologger.Debug().Msgf("create task response: %s", string(body))
	var taskResp TaskCreateResp
	if err := json.Unmarshal(body, &taskResp); err != nil {
		return "", err
	}

	if taskResp.Code != 200 {
		return "", fmt.Errorf("task creation failed: %s", taskResp.Msg)
	}

	return "success", nil
}
