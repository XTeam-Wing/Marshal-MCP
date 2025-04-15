package handler

// VulnScanTaskRequest 定义前端请求结构体
type VulnScanTaskRequest struct {
	VulnName     string   `json:"vuln_name"`     // 漏洞名称
	VulnDesc     string   `json:"vuln_desc"`     // 漏洞描述/特征
	Urls         []string `json:"urls"`          // 需要扫描的文件url列表
	Cluster      string   `json:"cluster"`       // 扫描集群（可选）
	Priority     string   `json:"priority"`      // 优先级（可选，默认low）
	TaskName     string   `json:"task_name"`     // 任务名称（可选）
	TaskNum      int      `json:"task_num"`      // 任务数量（可选，默认100）
	CycleScan    bool     `json:"cycle_scan"`    // 是否周期扫描（可选，默认false）
	Domain       string   `json:"domain"`        // 域名（可选）
	IP           string   `json:"ip"`            // IP（可选）
	Port         string   `json:"port"`          // 扫描端口（可选，默认1-65535）
	Engine       string   `json:"engine"`        // 扫描引擎（naabu/osint，默认naabu）
	IntervalDays int      `json:"interval_days"` // 扫描间隔天数（可选，默认7）
}

// VulnScanTaskResponse 定义返回结构体
type VulnScanTaskResponse struct {
	Code       int    `json:"code"`
	Msg        string `json:"msg"`
	TaskID     string `json:"task_id,omitempty"`
	WorkflowID string `json:"workflow_id,omitempty"`
	PluginID   string `json:"plugin_id,omitempty"`
}
