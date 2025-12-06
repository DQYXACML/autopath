package lodestar

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"math/big"
	"strings"
	"sync"

	"autopath/pkg/invariants"
	"autopath/pkg/monitor"
	"autopath/pkg/projects"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/ethereum/go-ethereum/rpc"
)

type contractAddresses struct {
	Depositor common.Address
	SGLP      common.Address
	PlvGLP    common.Address
}

type abiReaders struct {
	callUint        func(ctx context.Context, to common.Address, data []byte) (*big.Int, error)
	readBalance     func(ctx context.Context, token, holder common.Address) *big.Int
	readTotalSupply func(ctx context.Context, token common.Address) *big.Int
	readGetCash     func(ctx context.Context, ctoken common.Address) *big.Int
	readTotalBor    func(ctx context.Context, ctoken common.Address) *big.Int
	readPrice       func(ctx context.Context, oracle, ctoken common.Address) *big.Int
}

type paramLookup struct {
	cfg *projects.ProjectConfig
}

func init() {
	projects.RegisterProjectRegistrar("lodestar", Register)
}

// Register 将 Lodestar 专属不变量注册到给定 Registry
func Register(ctx context.Context, deps projects.Dependencies) error {
	if deps.Registry == nil || deps.Config == nil || deps.RPCClient == nil || deps.Tracer == nil {
		return nil
	}

	addrs := resolveAddresses()
	lookup := paramLookup{cfg: deps.Config}
	readers := buildReaders(deps.RPCClient)

	registerPLVGLPRatio(ctx, deps.Registry, addrs, lookup, readers)
	registerOraclePriceDelta(ctx, deps.Registry, lookup, readers)
	registerUtilizationRate(ctx, deps.Registry, lookup, readers)
	registerBorrowConcentration(deps.Registry, lookup, deps.EthClient)
	registerRecursiveBorrow(ctx, deps.Registry, lookup, deps.Tracer)

	return nil
}

func resolveAddresses() contractAddresses {
	addrs := contractAddresses{
		Depositor: common.HexToAddress("0x5897f5BAbac89B4EF4b21FD3a7C96d3cC439Edf1"),
		SGLP:      common.HexToAddress("0x5402B5F40310bDED796c7D0F3FF6683f5C0cFfdf"),
		PlvGLP:    common.HexToAddress("0x5326E71Ff593Ecc2CF7AcaE5Fe57582D6e74CFF1"),
	}

	if data, err := ioutil.ReadFile("test/Lodestar/scripts/data/deployed-local.json"); err == nil {
		var deployed struct {
			GlpDepositor string `json:"glpDepositor"`
			SGLP         string `json:"sGLP"`
			PlvGLP       string `json:"plvGLP"`
		}
		if err := json.Unmarshal(data, &deployed); err == nil {
			if deployed.GlpDepositor != "" {
				addrs.Depositor = common.HexToAddress(deployed.GlpDepositor)
				log.Printf("   使用本地 GlpDepositor: %s", deployed.GlpDepositor)
			}
			if deployed.SGLP != "" {
				addrs.SGLP = common.HexToAddress(deployed.SGLP)
				log.Printf("   使用本地 sGLP: %s", deployed.SGLP)
			}
			if deployed.PlvGLP != "" {
				addrs.PlvGLP = common.HexToAddress(deployed.PlvGLP)
				log.Printf("   使用本地 plvGLP: %s", deployed.PlvGLP)
			}
		}
	}

	return addrs
}

func buildReaders(rpcClient *rpc.Client) abiReaders {
	erc20ABI, _ := abi.JSON(strings.NewReader(`[
	    {"name":"balanceOf","type":"function","stateMutability":"view","inputs":[{"type":"address"}],"outputs":[{"type":"uint256"}]},
	    {"name":"totalSupply","type":"function","stateMutability":"view","inputs":[],"outputs":[{"type":"uint256"}]}
	]`))
	cTokenABI, _ := abi.JSON(strings.NewReader(`[
	    {"name":"getCash","type":"function","stateMutability":"view","inputs":[],"outputs":[{"type":"uint256"}]},
	    {"name":"totalBorrows","type":"function","stateMutability":"view","inputs":[],"outputs":[{"type":"uint256"}]}
	]`))
	oracleABI, _ := abi.JSON(strings.NewReader(`[
	    {"name":"getUnderlyingPrice","type":"function","stateMutability":"view","inputs":[{"type":"address"}],"outputs":[{"type":"uint256"}]}
	]`))

	call := func(ctx context.Context, to common.Address, data []byte) (*big.Int, error) {
		var res string
		payload := map[string]string{
			"to":   to.Hex(),
			"data": "0x" + strings.TrimPrefix(common.Bytes2Hex(data), "0x"),
		}
		if err := rpcClient.CallContext(ctx, &res, "eth_call", payload, "latest"); err != nil {
			return nil, err
		}
		out, err := hexutil.Decode(res)
		if err != nil {
			return nil, err
		}
		if len(out) < 32 {
			return big.NewInt(0), nil
		}
		return new(big.Int).SetBytes(out[len(out)-32:]), nil
	}

	readBalance := func(ctx context.Context, token, holder common.Address) *big.Int {
		data, _ := erc20ABI.Pack("balanceOf", holder)
		v, err := call(ctx, token, data)
		if err != nil {
			log.Printf("balanceOf 调用失败: %v", err)
			return big.NewInt(0)
		}
		return v
	}

	readSupply := func(ctx context.Context, token common.Address) *big.Int {
		data, _ := erc20ABI.Pack("totalSupply")
		v, err := call(ctx, token, data)
		if err != nil {
			log.Printf("totalSupply 调用失败: %v", err)
			return big.NewInt(0)
		}
		return v
	}

	readCash := func(ctx context.Context, ctoken common.Address) *big.Int {
		data, _ := cTokenABI.Pack("getCash")
		v, err := call(ctx, ctoken, data)
		if err != nil {
			log.Printf("getCash 调用失败: %v", err)
			return big.NewInt(0)
		}
		return v
	}

	readBorrows := func(ctx context.Context, ctoken common.Address) *big.Int {
		data, _ := cTokenABI.Pack("totalBorrows")
		v, err := call(ctx, ctoken, data)
		if err != nil {
			log.Printf("totalBorrows 调用失败: %v", err)
			return big.NewInt(0)
		}
		return v
	}

	readPrice := func(ctx context.Context, oracle, ctoken common.Address) *big.Int {
		data, _ := oracleABI.Pack("getUnderlyingPrice", ctoken)
		v, err := call(ctx, oracle, data)
		if err != nil {
			log.Printf("getUnderlyingPrice 调用失败: %v", err)
			return big.NewInt(0)
		}
		return v
	}

	return abiReaders{
		callUint:        call,
		readBalance:     readBalance,
		readTotalSupply: readSupply,
		readGetCash:     readCash,
		readTotalBor:    readBorrows,
		readPrice:       readPrice,
	}
}

func (p paramLookup) float(invID, key string, def float64) float64 {
	if p.cfg == nil {
		return def
	}
	for _, raw := range p.cfg.Invariants {
		obj, ok := raw.(map[string]interface{})
		if !ok {
			continue
		}
		if id, ok := obj["id"].(string); !ok || id != invID {
			continue
		}
		params, _ := obj["parameters"].(map[string]interface{})
		if v, ok := params[key]; ok {
			if f, ok2 := v.(float64); ok2 {
				return f
			}
		}
	}
	return def
}

func (p paramLookup) str(invID, key, def string) string {
	if p.cfg == nil {
		return def
	}
	for _, raw := range p.cfg.Invariants {
		obj, ok := raw.(map[string]interface{})
		if !ok {
			continue
		}
		if id, ok := obj["id"].(string); !ok || id != invID {
			continue
		}
		params, _ := obj["parameters"].(map[string]interface{})
		if v, ok := params[key]; ok {
			if s, ok2 := v.(string); ok2 {
				return s
			}
		}
	}
	return def
}

func (p paramLookup) strSlice(invID, key string) []string {
	if p.cfg == nil {
		return nil
	}
	for _, raw := range p.cfg.Invariants {
		obj, ok := raw.(map[string]interface{})
		if !ok {
			continue
		}
		if id, ok := obj["id"].(string); !ok || id != invID {
			continue
		}
		params, _ := obj["parameters"].(map[string]interface{})
		if v, ok := params[key]; ok {
			if arr, ok2 := v.([]interface{}); ok2 {
				out := make([]string, 0, len(arr))
				for _, it := range arr {
					if s, ok3 := it.(string); ok3 {
						out = append(out, s)
					}
				}
				return out
			}
		}
	}
	return nil
}

func registerPLVGLPRatio(ctx context.Context, registry *invariants.Registry, addrs contractAddresses, lookup paramLookup, readers abiReaders) {
	maxRatio := lookup.float("plv-glp-ratio-check", "max_ratio", 1.5)
	if dep := lookup.str("plv-glp-ratio-check", "depositor_address", addrs.Depositor.Hex()); dep != "" {
		addrs.Depositor = common.HexToAddress(dep)
	}

	registry.RegisterEvaluator("plv-glp-ratio-check", func(state *invariants.ChainState) (bool, *invariants.ViolationDetail) {
		sglpBalance := readers.readBalance(ctx, addrs.SGLP, addrs.Depositor)
		plvglpSupply := readers.readTotalSupply(ctx, addrs.PlvGLP)

		log.Printf("[Invariant] plv-glp-ratio-check | sGLP_balance=%s, plvGLP_totalSupply=%s", sglpBalance.String(), plvglpSupply.String())

		if plvglpSupply.Sign() == 0 {
			log.Printf("       plvGLP供应量为0，跳过检查")
			return true, nil
		}

		ratio := new(big.Float).Quo(new(big.Float).SetInt(sglpBalance), new(big.Float).SetInt(plvglpSupply))
		ratioFloat, _ := ratio.Float64()
		log.Printf("[Invariant] plv-glp-ratio-check | ratio=%.6f, max=%.2f", ratioFloat, maxRatio)

		if ratioFloat > maxRatio {
			return false, &invariants.ViolationDetail{
				Message:       fmt.Sprintf("sGLP/plvGLP ratio %.2f exceeds threshold %.2f", ratioFloat, maxRatio),
				ActualValue:   ratioFloat,
				ExpectedValue: fmt.Sprintf("≤ %.2f", maxRatio),
				Metadata: map[string]interface{}{
					"sglp_balance":  sglpBalance.String(),
					"plvglp_supply": plvglpSupply.String(),
					"depositor":     addrs.Depositor.Hex(),
				},
			}
		}
		return true, nil
	})
}

func registerOraclePriceDelta(ctx context.Context, registry *invariants.Registry, lookup paramLookup, readers abiReaders) {
	priceLast := map[common.Address]*big.Int{}
	var priceMu sync.Mutex
	maxChange := lookup.float("oracle-price-delta", "max_change_percentage", 0.20)
	oracleAddrStr := lookup.str("oracle-price-delta", "oracle_address", "")
	if oracleAddrStr == "" {
		log.Printf("       未配置 oracle_address，跳过价格波动检测")
		return
	}
	oracleAddr := common.HexToAddress(oracleAddrStr)
	markets := lookup.strSlice("oracle-price-delta", "monitoring_markets")

	registry.RegisterEvaluator("oracle-price-delta", func(state *invariants.ChainState) (bool, *invariants.ViolationDetail) {
		if len(markets) == 0 {
			return true, nil
		}
		c := common.HexToAddress(markets[0])
		cur := readers.readPrice(ctx, oracleAddr, c)

		priceMu.Lock()
		defer priceMu.Unlock()

		last := priceLast[c]
		priceLast[c] = new(big.Int).Set(cur)

		if last == nil || last.Sign() == 0 {
			log.Printf("[Invariant] oracle-price-delta | market=%s, current_price(raw)=%s (first sample)", c.Hex(), cur.String())
			return true, nil
		}

		log.Printf("[Invariant] oracle-price-delta | market=%s, current_price(raw)=%s, prev_price(raw)=%s", c.Hex(), cur.String(), last.String())
		diff := new(big.Float).Abs(new(big.Float).Quo(new(big.Float).SetInt(new(big.Int).Sub(cur, last)), new(big.Float).SetInt(last)))
		f, _ := diff.Float64()
		log.Printf("[Invariant] oracle-price-delta | delta=%.4f%%, max=%.0f%%", f*100, maxChange*100)
		if f > maxChange {
			return false, &invariants.ViolationDetail{
				Message:       fmt.Sprintf("Price change %.2f%% exceeds threshold %.0f%%", f*100, maxChange*100),
				ActualValue:   f,
				ExpectedValue: fmt.Sprintf("≤ %.0f%%", maxChange*100),
			}
		}
		return true, nil
	})
}

func registerUtilizationRate(ctx context.Context, registry *invariants.Registry, lookup paramLookup, readers abiReaders) {
	maxUtil := lookup.float("utilization-rate-check", "max_utilization", 0.95)
	warnUtil := lookup.float("utilization-rate-check", "warning_utilization", 0.85)
	utilMkts := lookup.strSlice("utilization-rate-check", "critical_markets")

	registry.RegisterEvaluator("utilization-rate-check", func(state *invariants.ChainState) (bool, *invariants.ViolationDetail) {
		worst := 0.0
		worstAddr := common.Address{}
		var worstBor, worstCash *big.Int
		for _, s := range utilMkts {
			if s == "" {
				continue
			}
			m := common.HexToAddress(s)
			borrows := readers.readTotalBor(ctx, m)
			cash := readers.readGetCash(ctx, m)
			denom := new(big.Int).Add(borrows, cash)
			if denom.Sign() == 0 {
				continue
			}
			util := new(big.Float).Quo(new(big.Float).SetInt(borrows), new(big.Float).SetInt(denom))
			f, _ := util.Float64()
			if f > worst {
				worst = f
				worstAddr = m
				worstBor = borrows
				worstCash = cash
			}
		}
		if worstAddr == (common.Address{}) {
			return true, nil
		}
		log.Printf("[Invariant] utilization-rate-check | market=%s, totalBorrows=%s, cash=%s, utilization=%.4f%%, warn=%.2f%%, max=%.2f%%", worstAddr.Hex(), worstBor.String(), worstCash.String(), worst*100, warnUtil*100, maxUtil*100)
		if worst > maxUtil {
			return false, &invariants.ViolationDetail{
				Message:       fmt.Sprintf("Utilization %.1f%% exceeds max %.1f%%", worst*100, maxUtil*100),
				ActualValue:   worst,
				ExpectedValue: fmt.Sprintf("≤ %.1f%%", maxUtil*100),
				Metadata: map[string]interface{}{
					"market": worstAddr.Hex(),
				},
			}
		}
		if worst > warnUtil {
			log.Printf("       利用率接近警告阈值 (%.2f%%)", warnUtil*100)
		}
		return true, nil
	})
}

func registerBorrowConcentration(registry *invariants.Registry, lookup paramLookup, client *ethclient.Client) {
	if client == nil {
		return
	}
	maxSingleThreshold := lookup.float("borrow-concentration", "max_single_borrower_percentage", 0.30)
	bcMkts := lookup.strSlice("borrow-concentration", "markets")
	borrowTopic := crypto.Keccak256Hash([]byte("Borrow(address,uint256,uint256,uint256)"))

	registry.RegisterEvaluator("borrow-concentration", func(state *invariants.ChainState) (bool, *invariants.ViolationDetail) {
		if len(bcMkts) == 0 {
			return true, nil
		}
		receipt, err := client.TransactionReceipt(context.Background(), state.TxHash)
		if err != nil {
			log.Printf("       获取交易回执失败: %v", err)
			return true, nil
		}
		mset := map[common.Address]bool{}
		for _, s := range bcMkts {
			if s != "" {
				mset[common.HexToAddress(s)] = true
			}
		}
		worstShare := 0.0
		var worstMeta map[string]interface{}
		seen := 0
		for _, lg := range receipt.Logs {
			if !mset[lg.Address] {
				continue
			}
			if len(lg.Topics) == 0 || lg.Topics[0] != borrowTopic {
				continue
			}
			if len(lg.Data) < 32*4 {
				continue
			}
			borrower := common.BytesToAddress(lg.Data[12:32])
			accountBor := new(big.Int).SetBytes(lg.Data[64:96])
			totalBor := new(big.Int).SetBytes(lg.Data[96:128])
			if totalBor.Sign() == 0 {
				continue
			}
			shareF, _ := new(big.Float).Quo(new(big.Float).SetInt(accountBor), new(big.Float).SetInt(totalBor)).Float64()
			log.Printf("[Invariant] borrow-concentration | market=%s, borrower=%s, accountBorrows=%s, totalBorrows=%s, share=%.4f%%, max=%.2f%%", lg.Address.Hex(), borrower.Hex(), accountBor.String(), totalBor.String(), shareF*100, maxSingleThreshold*100)
			seen++
			if shareF > worstShare {
				worstShare = shareF
				worstMeta = map[string]interface{}{
					"market":          lg.Address.Hex(),
					"borrower":        borrower.Hex(),
					"account_borrows": accountBor.String(),
					"total_borrows":   totalBor.String(),
				}
			}
		}
		if seen == 0 {
			log.Printf("[Invariant] borrow-concentration | no Borrow events found in tx for configured markets")
		}
		if worstShare > maxSingleThreshold {
			return false, &invariants.ViolationDetail{
				Message:       fmt.Sprintf("Single borrower concentration %.1f%% exceeds threshold %.1f%%", worstShare*100, maxSingleThreshold*100),
				ActualValue:   worstShare,
				ExpectedValue: fmt.Sprintf("≤ %.1f%%", maxSingleThreshold*100),
				Metadata:      worstMeta,
			}
		}
		return true, nil
	})
}

func registerRecursiveBorrow(ctx context.Context, registry *invariants.Registry, lookup paramLookup, tracer *monitor.TransactionTracer) {
	maxDepth := int(lookup.float("recursive-borrow-detection", "max_recursive_depth", 5))
	winSec := int64(lookup.float("recursive-borrow-detection", "time_window_seconds", 60))
	plvglpMktStr := lookup.str("recursive-borrow-detection", "plvglp_market", "")
	if plvglpMktStr == "" {
		return
	}
	recent := map[string][]int64{}

	registry.RegisterEvaluator("recursive-borrow-detection", func(state *invariants.ChainState) (bool, *invariants.ViolationDetail) {
		mkt := strings.ToLower(plvglpMktStr)
		frame, err := tracer.TraceTransaction(state.TxHash)
		if err != nil {
			log.Printf("       交易追踪失败: %v", err)
			return true, nil
		}
		var borrowers []string
		var walk func(f *monitor.CallFrame)
		walk = func(f *monitor.CallFrame) {
			if strings.ToLower(f.To) == mkt && len(f.Input) >= 10 && f.Input[:10] == "0xc5ebeaec" {
				borrowers = append(borrowers, strings.ToLower(f.From))
			}
			for i := range f.Calls {
				walk(&f.Calls[i])
			}
		}
		walk(frame)
		if len(borrowers) == 0 {
			log.Printf("[Invariant] recursive-borrow-detection | tx has 0 borrow() calls for market=%s", plvglpMktStr)
			return true, nil
		}
		log.Printf("[Invariant] recursive-borrow-detection | tx has %d borrow() calls for market=%s", len(borrowers), plvglpMktStr)
		ts := int64(state.Timestamp)
		limit := ts - winSec
		maxDepthSeen := 0
		maxDepthBorrower := ""
		for _, b := range borrowers {
			key := b + "|" + mkt
			lst := recent[key]
			lst = append(lst, ts)
			j := 0
			for _, t := range lst {
				if t >= limit {
					lst[j] = t
					j++
				}
			}
			recent[key] = lst[:j]
			depth := len(recent[key])
			if depth > maxDepthSeen {
				maxDepthSeen = depth
				maxDepthBorrower = b
			}
			if depth > maxDepth {
				return false, &invariants.ViolationDetail{
					Message:       fmt.Sprintf("Recursive borrow depth %d exceeds max %d within %ds", depth, maxDepth, winSec),
					ActualValue:   depth,
					ExpectedValue: fmt.Sprintf("≤ %d", maxDepth),
					Metadata:      map[string]interface{}{"borrower": b, "market": plvglpMktStr},
				}
			}
		}
		log.Printf("[Invariant] recursive-borrow-detection | window=%ds, maxDepth=%d (borrower=%s), threshold=%d", winSec, maxDepthSeen, maxDepthBorrower, maxDepth)
		return true, nil
	})
}
