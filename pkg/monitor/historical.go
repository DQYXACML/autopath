package monitor

import (
    "context"
    "fmt"
    "log"
)

// ProcessHistoricalBlocks 处理历史区块
// 在启动监控前调用此函数来扫描已存在的区块
func (m *BlockchainMonitor) ProcessHistoricalBlocks(ctx context.Context, fromBlock, toBlock uint64) error {
    log.Printf(" 开始扫描历史区块 %d 到 %d", fromBlock, toBlock)

    for blockNum := fromBlock; blockNum <= toBlock; blockNum++ {
        select {
        case <-ctx.Done():
            return ctx.Err()
        default:
            if err := m.processBlock(ctx, blockNum); err != nil {
                log.Printf("Error processing historical block %d: %v", blockNum, err)
                // 继续处理其他区块
                continue
            }
        }
    }

    log.Printf(" 历史区块扫描完成")
    return nil
}

// StartWithHistoricalScan 带历史扫描的启动方法
func (m *BlockchainMonitor) StartWithHistoricalScan(ctx context.Context, scanDepth uint64) error {
    m.mu.Lock()
    if m.running {
        m.mu.Unlock()
        return fmt.Errorf("monitor already running")
    }
    m.running = true
    m.mu.Unlock()

    // 获取当前区块高度
    latestBlock, err := m.client.BlockNumber(ctx)
    if err != nil {
        return fmt.Errorf("failed to get latest block: %w", err)
    }

    // 计算扫描起始区块
    var startBlock uint64
    if latestBlock > scanDepth {
        startBlock = latestBlock - scanDepth
    } else {
        startBlock = 0
    }

    // 先扫描历史区块
    if scanDepth > 0 {
        log.Printf(" 扫描最近 %d 个历史区块...", scanDepth)
        if err := m.ProcessHistoricalBlocks(ctx, startBlock, latestBlock); err != nil {
            log.Printf("Warning: Historical scan error: %v", err)
        }
    }

    // 设置最后处理的区块
    m.lastBlock = latestBlock

    // 然后开始正常的监控流程
    return m.Start(ctx)
}