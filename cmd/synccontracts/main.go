package main

import (
    "encoding/json"
    "flag"
    "fmt"
    "io/ioutil"
    "log"
    "os"
    "strings"
)

// 适配 Foundry broadcast run-latest.json 的最小结构
type broadcastFile struct {
    Transactions []struct {
        TransactionType string `json:"transactionType"`
        ContractName    string `json:"contractName"`
        ContractAddress string `json:"contractAddress"`
    } `json:"transactions"`
}

func main() {
    // 命令行参数
    var (
        broadcastPath = flag.String("broadcast", "broadcast/LocalDeploy.s.sol/31337/run-latest.json", "Foundry broadcast run-latest.json 路径")
        configIn      = flag.String("in", "pkg/invariants/configs/lodestar.json", "原始配置文件路径")
        configOut     = flag.String("out", "pkg/invariants/configs/lodestar.local.json", "输出配置文件路径")
        namesCSV      = flag.String("names", "", "按合约名过滤(逗号分隔)，留空表示使用全部 CREATE 部署")
    )
    flag.Parse()

    log.SetFlags(log.Ldate | log.Ltime | log.Lshortfile)

    // 读取 broadcast 文件
    bdata, err := ioutil.ReadFile(*broadcastPath)
    if err != nil {
        log.Fatalf("读取 broadcast 失败: %v", err)
    }

    var b broadcastFile
    if err := json.Unmarshal(bdata, &b); err != nil {
        log.Fatalf("解析 broadcast JSON 失败: %v", err)
    }

    // 过滤合约名（可选）
    nameFilter := map[string]struct{}{}
    if *namesCSV != "" {
        for _, n := range strings.Split(*namesCSV, ",") {
            n = strings.TrimSpace(n)
            if n != "" {
                nameFilter[n] = struct{}{}
            }
        }
    }

    // 收集地址
    var addrs []string
    for _, tx := range b.Transactions {
        if tx.TransactionType != "CREATE" {
            continue
        }
        if len(nameFilter) > 0 {
            if _, ok := nameFilter[tx.ContractName]; !ok {
                continue
            }
        }
        if tx.ContractAddress != "" {
            addrs = append(addrs, strings.ToLower(tx.ContractAddress))
        }
    }

    if len(addrs) == 0 {
        log.Fatalf("未在 broadcast 中找到任何部署地址，请检查路径与过滤条件")
    }

    // 读取原始配置到通用 map，避免丢失未知字段
    cfgData, err := ioutil.ReadFile(*configIn)
    if err != nil {
        log.Fatalf("读取配置失败: %v", err)
    }
    var cfg map[string]interface{}
    if err := json.Unmarshal(cfgData, &cfg); err != nil {
        log.Fatalf("解析配置 JSON 失败: %v", err)
    }

    // 覆盖 contracts 字段
    cfg["contracts"] = addrs

    // 输出到新文件
    out, err := json.MarshalIndent(cfg, "", "  ")
    if err != nil {
        log.Fatalf("序列化新配置失败: %v", err)
    }
    if err := os.MkdirAll("pkg/invariants/configs", 0755); err != nil {
        log.Fatalf("创建目录失败: %v", err)
    }
    if err := ioutil.WriteFile(*configOut, out, 0644); err != nil {
        log.Fatalf("写入配置失败: %v", err)
    }

    fmt.Printf("已生成本地配置: %s\n", *configOut)
    fmt.Printf("受保护合约(%d):\n", len(addrs))
    for _, a := range addrs {
        fmt.Printf(" - %s\n", a)
    }
}

