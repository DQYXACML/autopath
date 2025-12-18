// Code generated - DO NOT EDIT.
// This file is a generated binding and any manual changes will be lost.

package contracts

import (
	"errors"
	"math/big"
	"strings"

	ethereum "github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/event"
)

// Reference imports to suppress errors if they are not otherwise used.
var (
	_ = errors.New
	_ = big.NewInt
	_ = strings.NewReader
	_ = ethereum.NotFound
	_ = bind.Bind
	_ = common.Big1
	_ = types.BloomLookup
	_ = event.NewSubscription
	_ = abi.ConvertType
)

// ExpressionRuleLibExpressionRule is an auto generated low-level Go binding around an user-defined struct.
type ExpressionRuleLibExpressionRule struct {
	RuleType  string
	Terms     []ExpressionRuleLibExpressionTerm
	Threshold *big.Int
	Scale     *big.Int
}

// ExpressionRuleLibExpressionTerm is an auto generated low-level Go binding around an user-defined struct.
type ExpressionRuleLibExpressionTerm struct {
	Kind       uint8
	ParamIndex uint8
	ParamType  uint8
	Slot       [32]byte
	Coeff      *big.Int
}

// ParamCheckModuleFunctionConfig is an auto generated low-level Go binding around an user-defined struct.
type ParamCheckModuleFunctionConfig struct {
	Rules           []ParamCheckModuleParamRule
	ExpressionRules []ExpressionRuleLibExpressionRule
	RequireAllPass  bool
	LastUpdate      *big.Int
	Updater         common.Address
	Configured      bool
}

// ParamCheckModuleParamRule is an auto generated low-level Go binding around an user-defined struct.
type ParamCheckModuleParamRule struct {
	ParamIndex    uint8
	ParamType     uint8
	RuleType      uint8
	AllowedValues [][32]byte
	BlockedValues [][32]byte
	MinValue      [32]byte
	MaxValue      [32]byte
	Pattern       []byte
	Enabled       bool
}

// ParamCheckModuleParamSummary is an auto generated low-level Go binding around an user-defined struct.
type ParamCheckModuleParamSummary struct {
	ParamIndex      uint8
	ParamType       uint8
	SingleValues    [][32]byte
	IsRange         bool
	RangeMin        [32]byte
	RangeMax        [32]byte
	OccurrenceCount *big.Int
}

// ParamCheckModuleMetaData contains all meta data concerning the ParamCheckModule contract.
var ParamCheckModuleMetaData = &bind.MetaData{
	ABI: "[{\"type\":\"constructor\",\"inputs\":[{\"name\":\"_routerProxy\",\"type\":\"address\",\"internalType\":\"address\"},{\"name\":\"_registryProxy\",\"type\":\"address\",\"internalType\":\"address\"}],\"stateMutability\":\"nonpayable\"},{\"type\":\"function\",\"name\":\"MAX_RULES_PER_FUNCTION\",\"inputs\":[],\"outputs\":[{\"name\":\"\",\"type\":\"uint256\",\"internalType\":\"uint256\"}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"MIN_UPDATE_INTERVAL\",\"inputs\":[],\"outputs\":[{\"name\":\"\",\"type\":\"uint256\",\"internalType\":\"uint256\"}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"appendExpressionRules\",\"inputs\":[{\"name\":\"project\",\"type\":\"address\",\"internalType\":\"address\"},{\"name\":\"funcSig\",\"type\":\"bytes4\",\"internalType\":\"bytes4\"},{\"name\":\"newRules\",\"type\":\"tuple[]\",\"internalType\":\"structExpressionRuleLib.ExpressionRule[]\",\"components\":[{\"name\":\"ruleType\",\"type\":\"string\",\"internalType\":\"string\"},{\"name\":\"terms\",\"type\":\"tuple[]\",\"internalType\":\"structExpressionRuleLib.ExpressionTerm[]\",\"components\":[{\"name\":\"kind\",\"type\":\"uint8\",\"internalType\":\"uint8\"},{\"name\":\"paramIndex\",\"type\":\"uint8\",\"internalType\":\"uint8\"},{\"name\":\"paramType\",\"type\":\"uint8\",\"internalType\":\"uint8\"},{\"name\":\"slot\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"},{\"name\":\"coeff\",\"type\":\"int256\",\"internalType\":\"int256\"}]},{\"name\":\"threshold\",\"type\":\"int256\",\"internalType\":\"int256\"},{\"name\":\"scale\",\"type\":\"uint256\",\"internalType\":\"uint256\"}]}],\"outputs\":[],\"stateMutability\":\"nonpayable\"},{\"type\":\"function\",\"name\":\"autopatchOracles\",\"inputs\":[{\"name\":\"\",\"type\":\"address\",\"internalType\":\"address\"}],\"outputs\":[{\"name\":\"\",\"type\":\"bool\",\"internalType\":\"bool\"}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"batchUpdateRules\",\"inputs\":[{\"name\":\"project\",\"type\":\"address\",\"internalType\":\"address\"},{\"name\":\"funcSigs\",\"type\":\"bytes4[]\",\"internalType\":\"bytes4[]\"},{\"name\":\"configs\",\"type\":\"tuple[]\",\"internalType\":\"structParamCheckModule.FunctionConfig[]\",\"components\":[{\"name\":\"rules\",\"type\":\"tuple[]\",\"internalType\":\"structParamCheckModule.ParamRule[]\",\"components\":[{\"name\":\"paramIndex\",\"type\":\"uint8\",\"internalType\":\"uint8\"},{\"name\":\"paramType\",\"type\":\"uint8\",\"internalType\":\"enumParamCheckModule.ParamType\"},{\"name\":\"ruleType\",\"type\":\"uint8\",\"internalType\":\"enumParamCheckModule.RuleType\"},{\"name\":\"allowedValues\",\"type\":\"bytes32[]\",\"internalType\":\"bytes32[]\"},{\"name\":\"blockedValues\",\"type\":\"bytes32[]\",\"internalType\":\"bytes32[]\"},{\"name\":\"minValue\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"},{\"name\":\"maxValue\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"},{\"name\":\"pattern\",\"type\":\"bytes\",\"internalType\":\"bytes\"},{\"name\":\"enabled\",\"type\":\"bool\",\"internalType\":\"bool\"}]},{\"name\":\"expressionRules\",\"type\":\"tuple[]\",\"internalType\":\"structExpressionRuleLib.ExpressionRule[]\",\"components\":[{\"name\":\"ruleType\",\"type\":\"string\",\"internalType\":\"string\"},{\"name\":\"terms\",\"type\":\"tuple[]\",\"internalType\":\"structExpressionRuleLib.ExpressionTerm[]\",\"components\":[{\"name\":\"kind\",\"type\":\"uint8\",\"internalType\":\"uint8\"},{\"name\":\"paramIndex\",\"type\":\"uint8\",\"internalType\":\"uint8\"},{\"name\":\"paramType\",\"type\":\"uint8\",\"internalType\":\"uint8\"},{\"name\":\"slot\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"},{\"name\":\"coeff\",\"type\":\"int256\",\"internalType\":\"int256\"}]},{\"name\":\"threshold\",\"type\":\"int256\",\"internalType\":\"int256\"},{\"name\":\"scale\",\"type\":\"uint256\",\"internalType\":\"uint256\"}]},{\"name\":\"requireAllPass\",\"type\":\"bool\",\"internalType\":\"bool\"},{\"name\":\"lastUpdate\",\"type\":\"uint256\",\"internalType\":\"uint256\"},{\"name\":\"updater\",\"type\":\"address\",\"internalType\":\"address\"},{\"name\":\"configured\",\"type\":\"bool\",\"internalType\":\"bool\"}]}],\"outputs\":[],\"stateMutability\":\"nonpayable\"},{\"type\":\"function\",\"name\":\"detect\",\"inputs\":[{\"name\":\"project\",\"type\":\"address\",\"internalType\":\"address\"},{\"name\":\"params\",\"type\":\"string[]\",\"internalType\":\"string[]\"},{\"name\":\"data\",\"type\":\"bytes\",\"internalType\":\"bytes\"}],\"outputs\":[{\"name\":\"\",\"type\":\"bool\",\"internalType\":\"bool\"}],\"stateMutability\":\"nonpayable\"},{\"type\":\"function\",\"name\":\"emergencyPause\",\"inputs\":[{\"name\":\"project\",\"type\":\"address\",\"internalType\":\"address\"},{\"name\":\"funcSig\",\"type\":\"bytes4\",\"internalType\":\"bytes4\"},{\"name\":\"reason\",\"type\":\"string\",\"internalType\":\"string\"}],\"outputs\":[],\"stateMutability\":\"nonpayable\"},{\"type\":\"function\",\"name\":\"functionConfigs\",\"inputs\":[{\"name\":\"\",\"type\":\"address\",\"internalType\":\"address\"},{\"name\":\"\",\"type\":\"bytes4\",\"internalType\":\"bytes4\"}],\"outputs\":[{\"name\":\"requireAllPass\",\"type\":\"bool\",\"internalType\":\"bool\"},{\"name\":\"lastUpdate\",\"type\":\"uint256\",\"internalType\":\"uint256\"},{\"name\":\"updater\",\"type\":\"address\",\"internalType\":\"address\"},{\"name\":\"configured\",\"type\":\"bool\",\"internalType\":\"bool\"}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"getFunctionConfig\",\"inputs\":[{\"name\":\"project\",\"type\":\"address\",\"internalType\":\"address\"},{\"name\":\"funcSig\",\"type\":\"bytes4\",\"internalType\":\"bytes4\"}],\"outputs\":[{\"name\":\"\",\"type\":\"tuple\",\"internalType\":\"structParamCheckModule.FunctionConfig\",\"components\":[{\"name\":\"rules\",\"type\":\"tuple[]\",\"internalType\":\"structParamCheckModule.ParamRule[]\",\"components\":[{\"name\":\"paramIndex\",\"type\":\"uint8\",\"internalType\":\"uint8\"},{\"name\":\"paramType\",\"type\":\"uint8\",\"internalType\":\"enumParamCheckModule.ParamType\"},{\"name\":\"ruleType\",\"type\":\"uint8\",\"internalType\":\"enumParamCheckModule.RuleType\"},{\"name\":\"allowedValues\",\"type\":\"bytes32[]\",\"internalType\":\"bytes32[]\"},{\"name\":\"blockedValues\",\"type\":\"bytes32[]\",\"internalType\":\"bytes32[]\"},{\"name\":\"minValue\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"},{\"name\":\"maxValue\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"},{\"name\":\"pattern\",\"type\":\"bytes\",\"internalType\":\"bytes\"},{\"name\":\"enabled\",\"type\":\"bool\",\"internalType\":\"bool\"}]},{\"name\":\"expressionRules\",\"type\":\"tuple[]\",\"internalType\":\"structExpressionRuleLib.ExpressionRule[]\",\"components\":[{\"name\":\"ruleType\",\"type\":\"string\",\"internalType\":\"string\"},{\"name\":\"terms\",\"type\":\"tuple[]\",\"internalType\":\"structExpressionRuleLib.ExpressionTerm[]\",\"components\":[{\"name\":\"kind\",\"type\":\"uint8\",\"internalType\":\"uint8\"},{\"name\":\"paramIndex\",\"type\":\"uint8\",\"internalType\":\"uint8\"},{\"name\":\"paramType\",\"type\":\"uint8\",\"internalType\":\"uint8\"},{\"name\":\"slot\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"},{\"name\":\"coeff\",\"type\":\"int256\",\"internalType\":\"int256\"}]},{\"name\":\"threshold\",\"type\":\"int256\",\"internalType\":\"int256\"},{\"name\":\"scale\",\"type\":\"uint256\",\"internalType\":\"uint256\"}]},{\"name\":\"requireAllPass\",\"type\":\"bool\",\"internalType\":\"bool\"},{\"name\":\"lastUpdate\",\"type\":\"uint256\",\"internalType\":\"uint256\"},{\"name\":\"updater\",\"type\":\"address\",\"internalType\":\"address\"},{\"name\":\"configured\",\"type\":\"bool\",\"internalType\":\"bool\"}]}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"getRule\",\"inputs\":[{\"name\":\"project\",\"type\":\"address\",\"internalType\":\"address\"},{\"name\":\"funcSig\",\"type\":\"bytes4\",\"internalType\":\"bytes4\"},{\"name\":\"ruleIndex\",\"type\":\"uint8\",\"internalType\":\"uint8\"}],\"outputs\":[{\"name\":\"\",\"type\":\"tuple\",\"internalType\":\"structParamCheckModule.ParamRule\",\"components\":[{\"name\":\"paramIndex\",\"type\":\"uint8\",\"internalType\":\"uint8\"},{\"name\":\"paramType\",\"type\":\"uint8\",\"internalType\":\"enumParamCheckModule.ParamType\"},{\"name\":\"ruleType\",\"type\":\"uint8\",\"internalType\":\"enumParamCheckModule.RuleType\"},{\"name\":\"allowedValues\",\"type\":\"bytes32[]\",\"internalType\":\"bytes32[]\"},{\"name\":\"blockedValues\",\"type\":\"bytes32[]\",\"internalType\":\"bytes32[]\"},{\"name\":\"minValue\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"},{\"name\":\"maxValue\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"},{\"name\":\"pattern\",\"type\":\"bytes\",\"internalType\":\"bytes\"},{\"name\":\"enabled\",\"type\":\"bool\",\"internalType\":\"bool\"}]}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"isAuthorizedOracle\",\"inputs\":[{\"name\":\"oracle\",\"type\":\"address\",\"internalType\":\"address\"}],\"outputs\":[{\"name\":\"\",\"type\":\"bool\",\"internalType\":\"bool\"}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"manager\",\"inputs\":[],\"outputs\":[{\"name\":\"\",\"type\":\"address\",\"internalType\":\"address\"}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"registry\",\"inputs\":[],\"outputs\":[{\"name\":\"\",\"type\":\"address\",\"internalType\":\"address\"}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"removeExpressionRule\",\"inputs\":[{\"name\":\"project\",\"type\":\"address\",\"internalType\":\"address\"},{\"name\":\"funcSig\",\"type\":\"bytes4\",\"internalType\":\"bytes4\"},{\"name\":\"ruleIndex\",\"type\":\"uint256\",\"internalType\":\"uint256\"}],\"outputs\":[],\"stateMutability\":\"nonpayable\"},{\"type\":\"function\",\"name\":\"removeInfo\",\"inputs\":[{\"name\":\"data\",\"type\":\"bytes\",\"internalType\":\"bytes\"}],\"outputs\":[],\"stateMutability\":\"nonpayable\"},{\"type\":\"function\",\"name\":\"router\",\"inputs\":[],\"outputs\":[{\"name\":\"\",\"type\":\"address\",\"internalType\":\"address\"}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"setAutopatchOracle\",\"inputs\":[{\"name\":\"oracle\",\"type\":\"address\",\"internalType\":\"address\"},{\"name\":\"authorized\",\"type\":\"bool\",\"internalType\":\"bool\"}],\"outputs\":[],\"stateMutability\":\"nonpayable\"},{\"type\":\"function\",\"name\":\"setInfo\",\"inputs\":[{\"name\":\"data\",\"type\":\"bytes\",\"internalType\":\"bytes\"}],\"outputs\":[],\"stateMutability\":\"nonpayable\"},{\"type\":\"function\",\"name\":\"setMode\",\"inputs\":[{\"name\":\"data\",\"type\":\"bytes\",\"internalType\":\"bytes\"}],\"outputs\":[],\"stateMutability\":\"nonpayable\"},{\"type\":\"function\",\"name\":\"updateExpressionRules\",\"inputs\":[{\"name\":\"project\",\"type\":\"address\",\"internalType\":\"address\"},{\"name\":\"funcSig\",\"type\":\"bytes4\",\"internalType\":\"bytes4\"},{\"name\":\"rules\",\"type\":\"tuple[]\",\"internalType\":\"structExpressionRuleLib.ExpressionRule[]\",\"components\":[{\"name\":\"ruleType\",\"type\":\"string\",\"internalType\":\"string\"},{\"name\":\"terms\",\"type\":\"tuple[]\",\"internalType\":\"structExpressionRuleLib.ExpressionTerm[]\",\"components\":[{\"name\":\"kind\",\"type\":\"uint8\",\"internalType\":\"uint8\"},{\"name\":\"paramIndex\",\"type\":\"uint8\",\"internalType\":\"uint8\"},{\"name\":\"paramType\",\"type\":\"uint8\",\"internalType\":\"uint8\"},{\"name\":\"slot\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"},{\"name\":\"coeff\",\"type\":\"int256\",\"internalType\":\"int256\"}]},{\"name\":\"threshold\",\"type\":\"int256\",\"internalType\":\"int256\"},{\"name\":\"scale\",\"type\":\"uint256\",\"internalType\":\"uint256\"}]}],\"outputs\":[],\"stateMutability\":\"nonpayable\"},{\"type\":\"function\",\"name\":\"updateFromAutopatch\",\"inputs\":[{\"name\":\"project\",\"type\":\"address\",\"internalType\":\"address\"},{\"name\":\"funcSig\",\"type\":\"bytes4\",\"internalType\":\"bytes4\"},{\"name\":\"summaries\",\"type\":\"tuple[]\",\"internalType\":\"structParamCheckModule.ParamSummary[]\",\"components\":[{\"name\":\"paramIndex\",\"type\":\"uint8\",\"internalType\":\"uint8\"},{\"name\":\"paramType\",\"type\":\"uint8\",\"internalType\":\"enumParamCheckModule.ParamType\"},{\"name\":\"singleValues\",\"type\":\"bytes32[]\",\"internalType\":\"bytes32[]\"},{\"name\":\"isRange\",\"type\":\"bool\",\"internalType\":\"bool\"},{\"name\":\"rangeMin\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"},{\"name\":\"rangeMax\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"},{\"name\":\"occurrenceCount\",\"type\":\"uint256\",\"internalType\":\"uint256\"}]},{\"name\":\"threshold\",\"type\":\"uint256\",\"internalType\":\"uint256\"}],\"outputs\":[],\"stateMutability\":\"nonpayable\"},{\"type\":\"function\",\"name\":\"updateManager\",\"inputs\":[{\"name\":\"newManager\",\"type\":\"address\",\"internalType\":\"address\"}],\"outputs\":[],\"stateMutability\":\"nonpayable\"},{\"type\":\"event\",\"name\":\"AutopatchApplied\",\"inputs\":[{\"name\":\"project\",\"type\":\"address\",\"indexed\":true,\"internalType\":\"address\"},{\"name\":\"funcSig\",\"type\":\"bytes4\",\"indexed\":true,\"internalType\":\"bytes4\"},{\"name\":\"ruleCount\",\"type\":\"uint256\",\"indexed\":false,\"internalType\":\"uint256\"},{\"name\":\"summaryHash\",\"type\":\"bytes32\",\"indexed\":false,\"internalType\":\"bytes32\"}],\"anonymous\":false},{\"type\":\"event\",\"name\":\"AutopatchOracleSet\",\"inputs\":[{\"name\":\"oracle\",\"type\":\"address\",\"indexed\":true,\"internalType\":\"address\"},{\"name\":\"authorized\",\"type\":\"bool\",\"indexed\":false,\"internalType\":\"bool\"}],\"anonymous\":false},{\"type\":\"event\",\"name\":\"AutopatchRule\",\"inputs\":[{\"name\":\"project\",\"type\":\"address\",\"indexed\":true,\"internalType\":\"address\"},{\"name\":\"funcSig\",\"type\":\"bytes4\",\"indexed\":true,\"internalType\":\"bytes4\"},{\"name\":\"ruleIdx\",\"type\":\"uint8\",\"indexed\":false,\"internalType\":\"uint8\"},{\"name\":\"paramIndex\",\"type\":\"uint8\",\"indexed\":false,\"internalType\":\"uint8\"},{\"name\":\"paramType\",\"type\":\"uint8\",\"indexed\":false,\"internalType\":\"uint8\"},{\"name\":\"isRange\",\"type\":\"bool\",\"indexed\":false,\"internalType\":\"bool\"},{\"name\":\"rangeMin\",\"type\":\"bytes32\",\"indexed\":false,\"internalType\":\"bytes32\"},{\"name\":\"rangeMax\",\"type\":\"bytes32\",\"indexed\":false,\"internalType\":\"bytes32\"},{\"name\":\"allowedCount\",\"type\":\"uint256\",\"indexed\":false,\"internalType\":\"uint256\"}],\"anonymous\":false},{\"type\":\"event\",\"name\":\"EmergencyPause\",\"inputs\":[{\"name\":\"project\",\"type\":\"address\",\"indexed\":true,\"internalType\":\"address\"},{\"name\":\"funcSig\",\"type\":\"bytes4\",\"indexed\":true,\"internalType\":\"bytes4\"},{\"name\":\"reason\",\"type\":\"string\",\"indexed\":false,\"internalType\":\"string\"}],\"anonymous\":false},{\"type\":\"event\",\"name\":\"ExpressionRuleDuplicate\",\"inputs\":[{\"name\":\"project\",\"type\":\"address\",\"indexed\":true,\"internalType\":\"address\"},{\"name\":\"funcSig\",\"type\":\"bytes4\",\"indexed\":true,\"internalType\":\"bytes4\"},{\"name\":\"ruleHash\",\"type\":\"bytes32\",\"indexed\":false,\"internalType\":\"bytes32\"}],\"anonymous\":false},{\"type\":\"event\",\"name\":\"ExpressionRuleRemoved\",\"inputs\":[{\"name\":\"project\",\"type\":\"address\",\"indexed\":true,\"internalType\":\"address\"},{\"name\":\"funcSig\",\"type\":\"bytes4\",\"indexed\":true,\"internalType\":\"bytes4\"},{\"name\":\"ruleIndex\",\"type\":\"uint256\",\"indexed\":false,\"internalType\":\"uint256\"}],\"anonymous\":false},{\"type\":\"event\",\"name\":\"ExpressionRuleUpdated\",\"inputs\":[{\"name\":\"project\",\"type\":\"address\",\"indexed\":true,\"internalType\":\"address\"},{\"name\":\"funcSig\",\"type\":\"bytes4\",\"indexed\":true,\"internalType\":\"bytes4\"},{\"name\":\"ruleIndex\",\"type\":\"uint8\",\"indexed\":false,\"internalType\":\"uint8\"},{\"name\":\"ruleType\",\"type\":\"string\",\"indexed\":false,\"internalType\":\"string\"}],\"anonymous\":false},{\"type\":\"event\",\"name\":\"ExpressionRuleViolated\",\"inputs\":[{\"name\":\"project\",\"type\":\"address\",\"indexed\":true,\"internalType\":\"address\"},{\"name\":\"funcSig\",\"type\":\"bytes4\",\"indexed\":true,\"internalType\":\"bytes4\"},{\"name\":\"ruleIndex\",\"type\":\"uint8\",\"indexed\":false,\"internalType\":\"uint8\"},{\"name\":\"lhs\",\"type\":\"int256\",\"indexed\":false,\"internalType\":\"int256\"},{\"name\":\"threshold\",\"type\":\"int256\",\"indexed\":false,\"internalType\":\"int256\"}],\"anonymous\":false},{\"type\":\"event\",\"name\":\"ExpressionRuleViolated\",\"inputs\":[{\"name\":\"project\",\"type\":\"address\",\"indexed\":true,\"internalType\":\"address\"},{\"name\":\"funcSig\",\"type\":\"bytes4\",\"indexed\":true,\"internalType\":\"bytes4\"},{\"name\":\"ruleIndex\",\"type\":\"uint8\",\"indexed\":false,\"internalType\":\"uint8\"},{\"name\":\"lhs\",\"type\":\"int256\",\"indexed\":false,\"internalType\":\"int256\"},{\"name\":\"threshold\",\"type\":\"int256\",\"indexed\":false,\"internalType\":\"int256\"}],\"anonymous\":false},{\"type\":\"event\",\"name\":\"ExpressionRulesAppended\",\"inputs\":[{\"name\":\"project\",\"type\":\"address\",\"indexed\":true,\"internalType\":\"address\"},{\"name\":\"funcSig\",\"type\":\"bytes4\",\"indexed\":true,\"internalType\":\"bytes4\"},{\"name\":\"addedCount\",\"type\":\"uint256\",\"indexed\":false,\"internalType\":\"uint256\"},{\"name\":\"totalCount\",\"type\":\"uint256\",\"indexed\":false,\"internalType\":\"uint256\"}],\"anonymous\":false},{\"type\":\"event\",\"name\":\"ExpressionRulesReplaced\",\"inputs\":[{\"name\":\"project\",\"type\":\"address\",\"indexed\":true,\"internalType\":\"address\"},{\"name\":\"funcSig\",\"type\":\"bytes4\",\"indexed\":true,\"internalType\":\"bytes4\"},{\"name\":\"deletedCount\",\"type\":\"uint256\",\"indexed\":false,\"internalType\":\"uint256\"},{\"name\":\"newCount\",\"type\":\"uint256\",\"indexed\":false,\"internalType\":\"uint256\"}],\"anonymous\":false},{\"type\":\"event\",\"name\":\"ParameterBlocked\",\"inputs\":[{\"name\":\"project\",\"type\":\"address\",\"indexed\":true,\"internalType\":\"address\"},{\"name\":\"funcSig\",\"type\":\"bytes4\",\"indexed\":true,\"internalType\":\"bytes4\"},{\"name\":\"paramIndex\",\"type\":\"uint8\",\"indexed\":false,\"internalType\":\"uint8\"},{\"name\":\"paramValue\",\"type\":\"bytes32\",\"indexed\":false,\"internalType\":\"bytes32\"},{\"name\":\"reason\",\"type\":\"string\",\"indexed\":false,\"internalType\":\"string\"}],\"anonymous\":false},{\"type\":\"event\",\"name\":\"RuleConfigured\",\"inputs\":[{\"name\":\"project\",\"type\":\"address\",\"indexed\":true,\"internalType\":\"address\"},{\"name\":\"funcSig\",\"type\":\"bytes4\",\"indexed\":true,\"internalType\":\"bytes4\"},{\"name\":\"ruleIndex\",\"type\":\"uint8\",\"indexed\":false,\"internalType\":\"uint8\"},{\"name\":\"ruleType\",\"type\":\"uint8\",\"indexed\":false,\"internalType\":\"enumParamCheckModule.RuleType\"}],\"anonymous\":false},{\"type\":\"event\",\"name\":\"RuleUpdated\",\"inputs\":[{\"name\":\"project\",\"type\":\"address\",\"indexed\":true,\"internalType\":\"address\"},{\"name\":\"funcSig\",\"type\":\"bytes4\",\"indexed\":true,\"internalType\":\"bytes4\"},{\"name\":\"updater\",\"type\":\"address\",\"indexed\":false,\"internalType\":\"address\"},{\"name\":\"timestamp\",\"type\":\"uint256\",\"indexed\":false,\"internalType\":\"uint256\"}],\"anonymous\":false}]",
}

// ParamCheckModuleABI is the input ABI used to generate the binding from.
// Deprecated: Use ParamCheckModuleMetaData.ABI instead.
var ParamCheckModuleABI = ParamCheckModuleMetaData.ABI

// ParamCheckModule is an auto generated Go binding around an Ethereum contract.
type ParamCheckModule struct {
	ParamCheckModuleCaller     // Read-only binding to the contract
	ParamCheckModuleTransactor // Write-only binding to the contract
	ParamCheckModuleFilterer   // Log filterer for contract events
}

// ParamCheckModuleCaller is an auto generated read-only Go binding around an Ethereum contract.
type ParamCheckModuleCaller struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// ParamCheckModuleTransactor is an auto generated write-only Go binding around an Ethereum contract.
type ParamCheckModuleTransactor struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// ParamCheckModuleFilterer is an auto generated log filtering Go binding around an Ethereum contract events.
type ParamCheckModuleFilterer struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// ParamCheckModuleSession is an auto generated Go binding around an Ethereum contract,
// with pre-set call and transact options.
type ParamCheckModuleSession struct {
	Contract     *ParamCheckModule // Generic contract binding to set the session for
	CallOpts     bind.CallOpts     // Call options to use throughout this session
	TransactOpts bind.TransactOpts // Transaction auth options to use throughout this session
}

// ParamCheckModuleCallerSession is an auto generated read-only Go binding around an Ethereum contract,
// with pre-set call options.
type ParamCheckModuleCallerSession struct {
	Contract *ParamCheckModuleCaller // Generic contract caller binding to set the session for
	CallOpts bind.CallOpts           // Call options to use throughout this session
}

// ParamCheckModuleTransactorSession is an auto generated write-only Go binding around an Ethereum contract,
// with pre-set transact options.
type ParamCheckModuleTransactorSession struct {
	Contract     *ParamCheckModuleTransactor // Generic contract transactor binding to set the session for
	TransactOpts bind.TransactOpts           // Transaction auth options to use throughout this session
}

// ParamCheckModuleRaw is an auto generated low-level Go binding around an Ethereum contract.
type ParamCheckModuleRaw struct {
	Contract *ParamCheckModule // Generic contract binding to access the raw methods on
}

// ParamCheckModuleCallerRaw is an auto generated low-level read-only Go binding around an Ethereum contract.
type ParamCheckModuleCallerRaw struct {
	Contract *ParamCheckModuleCaller // Generic read-only contract binding to access the raw methods on
}

// ParamCheckModuleTransactorRaw is an auto generated low-level write-only Go binding around an Ethereum contract.
type ParamCheckModuleTransactorRaw struct {
	Contract *ParamCheckModuleTransactor // Generic write-only contract binding to access the raw methods on
}

// NewParamCheckModule creates a new instance of ParamCheckModule, bound to a specific deployed contract.
func NewParamCheckModule(address common.Address, backend bind.ContractBackend) (*ParamCheckModule, error) {
	contract, err := bindParamCheckModule(address, backend, backend, backend)
	if err != nil {
		return nil, err
	}
	return &ParamCheckModule{ParamCheckModuleCaller: ParamCheckModuleCaller{contract: contract}, ParamCheckModuleTransactor: ParamCheckModuleTransactor{contract: contract}, ParamCheckModuleFilterer: ParamCheckModuleFilterer{contract: contract}}, nil
}

// NewParamCheckModuleCaller creates a new read-only instance of ParamCheckModule, bound to a specific deployed contract.
func NewParamCheckModuleCaller(address common.Address, caller bind.ContractCaller) (*ParamCheckModuleCaller, error) {
	contract, err := bindParamCheckModule(address, caller, nil, nil)
	if err != nil {
		return nil, err
	}
	return &ParamCheckModuleCaller{contract: contract}, nil
}

// NewParamCheckModuleTransactor creates a new write-only instance of ParamCheckModule, bound to a specific deployed contract.
func NewParamCheckModuleTransactor(address common.Address, transactor bind.ContractTransactor) (*ParamCheckModuleTransactor, error) {
	contract, err := bindParamCheckModule(address, nil, transactor, nil)
	if err != nil {
		return nil, err
	}
	return &ParamCheckModuleTransactor{contract: contract}, nil
}

// NewParamCheckModuleFilterer creates a new log filterer instance of ParamCheckModule, bound to a specific deployed contract.
func NewParamCheckModuleFilterer(address common.Address, filterer bind.ContractFilterer) (*ParamCheckModuleFilterer, error) {
	contract, err := bindParamCheckModule(address, nil, nil, filterer)
	if err != nil {
		return nil, err
	}
	return &ParamCheckModuleFilterer{contract: contract}, nil
}

// bindParamCheckModule binds a generic wrapper to an already deployed contract.
func bindParamCheckModule(address common.Address, caller bind.ContractCaller, transactor bind.ContractTransactor, filterer bind.ContractFilterer) (*bind.BoundContract, error) {
	parsed, err := ParamCheckModuleMetaData.GetAbi()
	if err != nil {
		return nil, err
	}
	return bind.NewBoundContract(address, *parsed, caller, transactor, filterer), nil
}

// Call invokes the (constant) contract method with params as input values and
// sets the output to result. The result type might be a single field for simple
// returns, a slice of interfaces for anonymous returns and a struct for named
// returns.
func (_ParamCheckModule *ParamCheckModuleRaw) Call(opts *bind.CallOpts, result *[]interface{}, method string, params ...interface{}) error {
	return _ParamCheckModule.Contract.ParamCheckModuleCaller.contract.Call(opts, result, method, params...)
}

// Transfer initiates a plain transaction to move funds to the contract, calling
// its default method if one is available.
func (_ParamCheckModule *ParamCheckModuleRaw) Transfer(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _ParamCheckModule.Contract.ParamCheckModuleTransactor.contract.Transfer(opts)
}

// Transact invokes the (paid) contract method with params as input values.
func (_ParamCheckModule *ParamCheckModuleRaw) Transact(opts *bind.TransactOpts, method string, params ...interface{}) (*types.Transaction, error) {
	return _ParamCheckModule.Contract.ParamCheckModuleTransactor.contract.Transact(opts, method, params...)
}

// Call invokes the (constant) contract method with params as input values and
// sets the output to result. The result type might be a single field for simple
// returns, a slice of interfaces for anonymous returns and a struct for named
// returns.
func (_ParamCheckModule *ParamCheckModuleCallerRaw) Call(opts *bind.CallOpts, result *[]interface{}, method string, params ...interface{}) error {
	return _ParamCheckModule.Contract.contract.Call(opts, result, method, params...)
}

// Transfer initiates a plain transaction to move funds to the contract, calling
// its default method if one is available.
func (_ParamCheckModule *ParamCheckModuleTransactorRaw) Transfer(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _ParamCheckModule.Contract.contract.Transfer(opts)
}

// Transact invokes the (paid) contract method with params as input values.
func (_ParamCheckModule *ParamCheckModuleTransactorRaw) Transact(opts *bind.TransactOpts, method string, params ...interface{}) (*types.Transaction, error) {
	return _ParamCheckModule.Contract.contract.Transact(opts, method, params...)
}

// MAXRULESPERFUNCTION is a free data retrieval call binding the contract method 0x413c8c2a.
//
// Solidity: function MAX_RULES_PER_FUNCTION() view returns(uint256)
func (_ParamCheckModule *ParamCheckModuleCaller) MAXRULESPERFUNCTION(opts *bind.CallOpts) (*big.Int, error) {
	var out []interface{}
	err := _ParamCheckModule.contract.Call(opts, &out, "MAX_RULES_PER_FUNCTION")

	if err != nil {
		return *new(*big.Int), err
	}

	out0 := *abi.ConvertType(out[0], new(*big.Int)).(**big.Int)

	return out0, err

}

// MAXRULESPERFUNCTION is a free data retrieval call binding the contract method 0x413c8c2a.
//
// Solidity: function MAX_RULES_PER_FUNCTION() view returns(uint256)
func (_ParamCheckModule *ParamCheckModuleSession) MAXRULESPERFUNCTION() (*big.Int, error) {
	return _ParamCheckModule.Contract.MAXRULESPERFUNCTION(&_ParamCheckModule.CallOpts)
}

// MAXRULESPERFUNCTION is a free data retrieval call binding the contract method 0x413c8c2a.
//
// Solidity: function MAX_RULES_PER_FUNCTION() view returns(uint256)
func (_ParamCheckModule *ParamCheckModuleCallerSession) MAXRULESPERFUNCTION() (*big.Int, error) {
	return _ParamCheckModule.Contract.MAXRULESPERFUNCTION(&_ParamCheckModule.CallOpts)
}

// MINUPDATEINTERVAL is a free data retrieval call binding the contract method 0xbd3be27c.
//
// Solidity: function MIN_UPDATE_INTERVAL() view returns(uint256)
func (_ParamCheckModule *ParamCheckModuleCaller) MINUPDATEINTERVAL(opts *bind.CallOpts) (*big.Int, error) {
	var out []interface{}
	err := _ParamCheckModule.contract.Call(opts, &out, "MIN_UPDATE_INTERVAL")

	if err != nil {
		return *new(*big.Int), err
	}

	out0 := *abi.ConvertType(out[0], new(*big.Int)).(**big.Int)

	return out0, err

}

// MINUPDATEINTERVAL is a free data retrieval call binding the contract method 0xbd3be27c.
//
// Solidity: function MIN_UPDATE_INTERVAL() view returns(uint256)
func (_ParamCheckModule *ParamCheckModuleSession) MINUPDATEINTERVAL() (*big.Int, error) {
	return _ParamCheckModule.Contract.MINUPDATEINTERVAL(&_ParamCheckModule.CallOpts)
}

// MINUPDATEINTERVAL is a free data retrieval call binding the contract method 0xbd3be27c.
//
// Solidity: function MIN_UPDATE_INTERVAL() view returns(uint256)
func (_ParamCheckModule *ParamCheckModuleCallerSession) MINUPDATEINTERVAL() (*big.Int, error) {
	return _ParamCheckModule.Contract.MINUPDATEINTERVAL(&_ParamCheckModule.CallOpts)
}

// AutopatchOracles is a free data retrieval call binding the contract method 0x50117ede.
//
// Solidity: function autopatchOracles(address ) view returns(bool)
func (_ParamCheckModule *ParamCheckModuleCaller) AutopatchOracles(opts *bind.CallOpts, arg0 common.Address) (bool, error) {
	var out []interface{}
	err := _ParamCheckModule.contract.Call(opts, &out, "autopatchOracles", arg0)

	if err != nil {
		return *new(bool), err
	}

	out0 := *abi.ConvertType(out[0], new(bool)).(*bool)

	return out0, err

}

// AutopatchOracles is a free data retrieval call binding the contract method 0x50117ede.
//
// Solidity: function autopatchOracles(address ) view returns(bool)
func (_ParamCheckModule *ParamCheckModuleSession) AutopatchOracles(arg0 common.Address) (bool, error) {
	return _ParamCheckModule.Contract.AutopatchOracles(&_ParamCheckModule.CallOpts, arg0)
}

// AutopatchOracles is a free data retrieval call binding the contract method 0x50117ede.
//
// Solidity: function autopatchOracles(address ) view returns(bool)
func (_ParamCheckModule *ParamCheckModuleCallerSession) AutopatchOracles(arg0 common.Address) (bool, error) {
	return _ParamCheckModule.Contract.AutopatchOracles(&_ParamCheckModule.CallOpts, arg0)
}

// FunctionConfigs is a free data retrieval call binding the contract method 0xa0bf98c7.
//
// Solidity: function functionConfigs(address , bytes4 ) view returns(bool requireAllPass, uint256 lastUpdate, address updater, bool configured)
func (_ParamCheckModule *ParamCheckModuleCaller) FunctionConfigs(opts *bind.CallOpts, arg0 common.Address, arg1 [4]byte) (struct {
	RequireAllPass bool
	LastUpdate     *big.Int
	Updater        common.Address
	Configured     bool
}, error) {
	var out []interface{}
	err := _ParamCheckModule.contract.Call(opts, &out, "functionConfigs", arg0, arg1)

	outstruct := new(struct {
		RequireAllPass bool
		LastUpdate     *big.Int
		Updater        common.Address
		Configured     bool
	})
	if err != nil {
		return *outstruct, err
	}

	outstruct.RequireAllPass = *abi.ConvertType(out[0], new(bool)).(*bool)
	outstruct.LastUpdate = *abi.ConvertType(out[1], new(*big.Int)).(**big.Int)
	outstruct.Updater = *abi.ConvertType(out[2], new(common.Address)).(*common.Address)
	outstruct.Configured = *abi.ConvertType(out[3], new(bool)).(*bool)

	return *outstruct, err

}

// FunctionConfigs is a free data retrieval call binding the contract method 0xa0bf98c7.
//
// Solidity: function functionConfigs(address , bytes4 ) view returns(bool requireAllPass, uint256 lastUpdate, address updater, bool configured)
func (_ParamCheckModule *ParamCheckModuleSession) FunctionConfigs(arg0 common.Address, arg1 [4]byte) (struct {
	RequireAllPass bool
	LastUpdate     *big.Int
	Updater        common.Address
	Configured     bool
}, error) {
	return _ParamCheckModule.Contract.FunctionConfigs(&_ParamCheckModule.CallOpts, arg0, arg1)
}

// FunctionConfigs is a free data retrieval call binding the contract method 0xa0bf98c7.
//
// Solidity: function functionConfigs(address , bytes4 ) view returns(bool requireAllPass, uint256 lastUpdate, address updater, bool configured)
func (_ParamCheckModule *ParamCheckModuleCallerSession) FunctionConfigs(arg0 common.Address, arg1 [4]byte) (struct {
	RequireAllPass bool
	LastUpdate     *big.Int
	Updater        common.Address
	Configured     bool
}, error) {
	return _ParamCheckModule.Contract.FunctionConfigs(&_ParamCheckModule.CallOpts, arg0, arg1)
}

// GetFunctionConfig is a free data retrieval call binding the contract method 0x9d03848c.
//
// Solidity: function getFunctionConfig(address project, bytes4 funcSig) view returns(((uint8,uint8,uint8,bytes32[],bytes32[],bytes32,bytes32,bytes,bool)[],(string,(uint8,uint8,uint8,bytes32,int256)[],int256,uint256)[],bool,uint256,address,bool))
func (_ParamCheckModule *ParamCheckModuleCaller) GetFunctionConfig(opts *bind.CallOpts, project common.Address, funcSig [4]byte) (ParamCheckModuleFunctionConfig, error) {
	var out []interface{}
	err := _ParamCheckModule.contract.Call(opts, &out, "getFunctionConfig", project, funcSig)

	if err != nil {
		return *new(ParamCheckModuleFunctionConfig), err
	}

	out0 := *abi.ConvertType(out[0], new(ParamCheckModuleFunctionConfig)).(*ParamCheckModuleFunctionConfig)

	return out0, err

}

// GetFunctionConfig is a free data retrieval call binding the contract method 0x9d03848c.
//
// Solidity: function getFunctionConfig(address project, bytes4 funcSig) view returns(((uint8,uint8,uint8,bytes32[],bytes32[],bytes32,bytes32,bytes,bool)[],(string,(uint8,uint8,uint8,bytes32,int256)[],int256,uint256)[],bool,uint256,address,bool))
func (_ParamCheckModule *ParamCheckModuleSession) GetFunctionConfig(project common.Address, funcSig [4]byte) (ParamCheckModuleFunctionConfig, error) {
	return _ParamCheckModule.Contract.GetFunctionConfig(&_ParamCheckModule.CallOpts, project, funcSig)
}

// GetFunctionConfig is a free data retrieval call binding the contract method 0x9d03848c.
//
// Solidity: function getFunctionConfig(address project, bytes4 funcSig) view returns(((uint8,uint8,uint8,bytes32[],bytes32[],bytes32,bytes32,bytes,bool)[],(string,(uint8,uint8,uint8,bytes32,int256)[],int256,uint256)[],bool,uint256,address,bool))
func (_ParamCheckModule *ParamCheckModuleCallerSession) GetFunctionConfig(project common.Address, funcSig [4]byte) (ParamCheckModuleFunctionConfig, error) {
	return _ParamCheckModule.Contract.GetFunctionConfig(&_ParamCheckModule.CallOpts, project, funcSig)
}

// GetRule is a free data retrieval call binding the contract method 0xa1bcf0a4.
//
// Solidity: function getRule(address project, bytes4 funcSig, uint8 ruleIndex) view returns((uint8,uint8,uint8,bytes32[],bytes32[],bytes32,bytes32,bytes,bool))
func (_ParamCheckModule *ParamCheckModuleCaller) GetRule(opts *bind.CallOpts, project common.Address, funcSig [4]byte, ruleIndex uint8) (ParamCheckModuleParamRule, error) {
	var out []interface{}
	err := _ParamCheckModule.contract.Call(opts, &out, "getRule", project, funcSig, ruleIndex)

	if err != nil {
		return *new(ParamCheckModuleParamRule), err
	}

	out0 := *abi.ConvertType(out[0], new(ParamCheckModuleParamRule)).(*ParamCheckModuleParamRule)

	return out0, err

}

// GetRule is a free data retrieval call binding the contract method 0xa1bcf0a4.
//
// Solidity: function getRule(address project, bytes4 funcSig, uint8 ruleIndex) view returns((uint8,uint8,uint8,bytes32[],bytes32[],bytes32,bytes32,bytes,bool))
func (_ParamCheckModule *ParamCheckModuleSession) GetRule(project common.Address, funcSig [4]byte, ruleIndex uint8) (ParamCheckModuleParamRule, error) {
	return _ParamCheckModule.Contract.GetRule(&_ParamCheckModule.CallOpts, project, funcSig, ruleIndex)
}

// GetRule is a free data retrieval call binding the contract method 0xa1bcf0a4.
//
// Solidity: function getRule(address project, bytes4 funcSig, uint8 ruleIndex) view returns((uint8,uint8,uint8,bytes32[],bytes32[],bytes32,bytes32,bytes,bool))
func (_ParamCheckModule *ParamCheckModuleCallerSession) GetRule(project common.Address, funcSig [4]byte, ruleIndex uint8) (ParamCheckModuleParamRule, error) {
	return _ParamCheckModule.Contract.GetRule(&_ParamCheckModule.CallOpts, project, funcSig, ruleIndex)
}

// IsAuthorizedOracle is a free data retrieval call binding the contract method 0xbfe609da.
//
// Solidity: function isAuthorizedOracle(address oracle) view returns(bool)
func (_ParamCheckModule *ParamCheckModuleCaller) IsAuthorizedOracle(opts *bind.CallOpts, oracle common.Address) (bool, error) {
	var out []interface{}
	err := _ParamCheckModule.contract.Call(opts, &out, "isAuthorizedOracle", oracle)

	if err != nil {
		return *new(bool), err
	}

	out0 := *abi.ConvertType(out[0], new(bool)).(*bool)

	return out0, err

}

// IsAuthorizedOracle is a free data retrieval call binding the contract method 0xbfe609da.
//
// Solidity: function isAuthorizedOracle(address oracle) view returns(bool)
func (_ParamCheckModule *ParamCheckModuleSession) IsAuthorizedOracle(oracle common.Address) (bool, error) {
	return _ParamCheckModule.Contract.IsAuthorizedOracle(&_ParamCheckModule.CallOpts, oracle)
}

// IsAuthorizedOracle is a free data retrieval call binding the contract method 0xbfe609da.
//
// Solidity: function isAuthorizedOracle(address oracle) view returns(bool)
func (_ParamCheckModule *ParamCheckModuleCallerSession) IsAuthorizedOracle(oracle common.Address) (bool, error) {
	return _ParamCheckModule.Contract.IsAuthorizedOracle(&_ParamCheckModule.CallOpts, oracle)
}

// Manager is a free data retrieval call binding the contract method 0x481c6a75.
//
// Solidity: function manager() view returns(address)
func (_ParamCheckModule *ParamCheckModuleCaller) Manager(opts *bind.CallOpts) (common.Address, error) {
	var out []interface{}
	err := _ParamCheckModule.contract.Call(opts, &out, "manager")

	if err != nil {
		return *new(common.Address), err
	}

	out0 := *abi.ConvertType(out[0], new(common.Address)).(*common.Address)

	return out0, err

}

// Manager is a free data retrieval call binding the contract method 0x481c6a75.
//
// Solidity: function manager() view returns(address)
func (_ParamCheckModule *ParamCheckModuleSession) Manager() (common.Address, error) {
	return _ParamCheckModule.Contract.Manager(&_ParamCheckModule.CallOpts)
}

// Manager is a free data retrieval call binding the contract method 0x481c6a75.
//
// Solidity: function manager() view returns(address)
func (_ParamCheckModule *ParamCheckModuleCallerSession) Manager() (common.Address, error) {
	return _ParamCheckModule.Contract.Manager(&_ParamCheckModule.CallOpts)
}

// Registry is a free data retrieval call binding the contract method 0x7b103999.
//
// Solidity: function registry() view returns(address)
func (_ParamCheckModule *ParamCheckModuleCaller) Registry(opts *bind.CallOpts) (common.Address, error) {
	var out []interface{}
	err := _ParamCheckModule.contract.Call(opts, &out, "registry")

	if err != nil {
		return *new(common.Address), err
	}

	out0 := *abi.ConvertType(out[0], new(common.Address)).(*common.Address)

	return out0, err

}

// Registry is a free data retrieval call binding the contract method 0x7b103999.
//
// Solidity: function registry() view returns(address)
func (_ParamCheckModule *ParamCheckModuleSession) Registry() (common.Address, error) {
	return _ParamCheckModule.Contract.Registry(&_ParamCheckModule.CallOpts)
}

// Registry is a free data retrieval call binding the contract method 0x7b103999.
//
// Solidity: function registry() view returns(address)
func (_ParamCheckModule *ParamCheckModuleCallerSession) Registry() (common.Address, error) {
	return _ParamCheckModule.Contract.Registry(&_ParamCheckModule.CallOpts)
}

// Router is a free data retrieval call binding the contract method 0xf887ea40.
//
// Solidity: function router() view returns(address)
func (_ParamCheckModule *ParamCheckModuleCaller) Router(opts *bind.CallOpts) (common.Address, error) {
	var out []interface{}
	err := _ParamCheckModule.contract.Call(opts, &out, "router")

	if err != nil {
		return *new(common.Address), err
	}

	out0 := *abi.ConvertType(out[0], new(common.Address)).(*common.Address)

	return out0, err

}

// Router is a free data retrieval call binding the contract method 0xf887ea40.
//
// Solidity: function router() view returns(address)
func (_ParamCheckModule *ParamCheckModuleSession) Router() (common.Address, error) {
	return _ParamCheckModule.Contract.Router(&_ParamCheckModule.CallOpts)
}

// Router is a free data retrieval call binding the contract method 0xf887ea40.
//
// Solidity: function router() view returns(address)
func (_ParamCheckModule *ParamCheckModuleCallerSession) Router() (common.Address, error) {
	return _ParamCheckModule.Contract.Router(&_ParamCheckModule.CallOpts)
}

// AppendExpressionRules is a paid mutator transaction binding the contract method 0xd94b5e36.
//
// Solidity: function appendExpressionRules(address project, bytes4 funcSig, (string,(uint8,uint8,uint8,bytes32,int256)[],int256,uint256)[] newRules) returns()
func (_ParamCheckModule *ParamCheckModuleTransactor) AppendExpressionRules(opts *bind.TransactOpts, project common.Address, funcSig [4]byte, newRules []ExpressionRuleLibExpressionRule) (*types.Transaction, error) {
	return _ParamCheckModule.contract.Transact(opts, "appendExpressionRules", project, funcSig, newRules)
}

// AppendExpressionRules is a paid mutator transaction binding the contract method 0xd94b5e36.
//
// Solidity: function appendExpressionRules(address project, bytes4 funcSig, (string,(uint8,uint8,uint8,bytes32,int256)[],int256,uint256)[] newRules) returns()
func (_ParamCheckModule *ParamCheckModuleSession) AppendExpressionRules(project common.Address, funcSig [4]byte, newRules []ExpressionRuleLibExpressionRule) (*types.Transaction, error) {
	return _ParamCheckModule.Contract.AppendExpressionRules(&_ParamCheckModule.TransactOpts, project, funcSig, newRules)
}

// AppendExpressionRules is a paid mutator transaction binding the contract method 0xd94b5e36.
//
// Solidity: function appendExpressionRules(address project, bytes4 funcSig, (string,(uint8,uint8,uint8,bytes32,int256)[],int256,uint256)[] newRules) returns()
func (_ParamCheckModule *ParamCheckModuleTransactorSession) AppendExpressionRules(project common.Address, funcSig [4]byte, newRules []ExpressionRuleLibExpressionRule) (*types.Transaction, error) {
	return _ParamCheckModule.Contract.AppendExpressionRules(&_ParamCheckModule.TransactOpts, project, funcSig, newRules)
}

// BatchUpdateRules is a paid mutator transaction binding the contract method 0xa96470c1.
//
// Solidity: function batchUpdateRules(address project, bytes4[] funcSigs, ((uint8,uint8,uint8,bytes32[],bytes32[],bytes32,bytes32,bytes,bool)[],(string,(uint8,uint8,uint8,bytes32,int256)[],int256,uint256)[],bool,uint256,address,bool)[] configs) returns()
func (_ParamCheckModule *ParamCheckModuleTransactor) BatchUpdateRules(opts *bind.TransactOpts, project common.Address, funcSigs [][4]byte, configs []ParamCheckModuleFunctionConfig) (*types.Transaction, error) {
	return _ParamCheckModule.contract.Transact(opts, "batchUpdateRules", project, funcSigs, configs)
}

// BatchUpdateRules is a paid mutator transaction binding the contract method 0xa96470c1.
//
// Solidity: function batchUpdateRules(address project, bytes4[] funcSigs, ((uint8,uint8,uint8,bytes32[],bytes32[],bytes32,bytes32,bytes,bool)[],(string,(uint8,uint8,uint8,bytes32,int256)[],int256,uint256)[],bool,uint256,address,bool)[] configs) returns()
func (_ParamCheckModule *ParamCheckModuleSession) BatchUpdateRules(project common.Address, funcSigs [][4]byte, configs []ParamCheckModuleFunctionConfig) (*types.Transaction, error) {
	return _ParamCheckModule.Contract.BatchUpdateRules(&_ParamCheckModule.TransactOpts, project, funcSigs, configs)
}

// BatchUpdateRules is a paid mutator transaction binding the contract method 0xa96470c1.
//
// Solidity: function batchUpdateRules(address project, bytes4[] funcSigs, ((uint8,uint8,uint8,bytes32[],bytes32[],bytes32,bytes32,bytes,bool)[],(string,(uint8,uint8,uint8,bytes32,int256)[],int256,uint256)[],bool,uint256,address,bool)[] configs) returns()
func (_ParamCheckModule *ParamCheckModuleTransactorSession) BatchUpdateRules(project common.Address, funcSigs [][4]byte, configs []ParamCheckModuleFunctionConfig) (*types.Transaction, error) {
	return _ParamCheckModule.Contract.BatchUpdateRules(&_ParamCheckModule.TransactOpts, project, funcSigs, configs)
}

// Detect is a paid mutator transaction binding the contract method 0x12c3a2a5.
//
// Solidity: function detect(address project, string[] params, bytes data) returns(bool)
func (_ParamCheckModule *ParamCheckModuleTransactor) Detect(opts *bind.TransactOpts, project common.Address, params []string, data []byte) (*types.Transaction, error) {
	return _ParamCheckModule.contract.Transact(opts, "detect", project, params, data)
}

// Detect is a paid mutator transaction binding the contract method 0x12c3a2a5.
//
// Solidity: function detect(address project, string[] params, bytes data) returns(bool)
func (_ParamCheckModule *ParamCheckModuleSession) Detect(project common.Address, params []string, data []byte) (*types.Transaction, error) {
	return _ParamCheckModule.Contract.Detect(&_ParamCheckModule.TransactOpts, project, params, data)
}

// Detect is a paid mutator transaction binding the contract method 0x12c3a2a5.
//
// Solidity: function detect(address project, string[] params, bytes data) returns(bool)
func (_ParamCheckModule *ParamCheckModuleTransactorSession) Detect(project common.Address, params []string, data []byte) (*types.Transaction, error) {
	return _ParamCheckModule.Contract.Detect(&_ParamCheckModule.TransactOpts, project, params, data)
}

// EmergencyPause is a paid mutator transaction binding the contract method 0x1bd229fc.
//
// Solidity: function emergencyPause(address project, bytes4 funcSig, string reason) returns()
func (_ParamCheckModule *ParamCheckModuleTransactor) EmergencyPause(opts *bind.TransactOpts, project common.Address, funcSig [4]byte, reason string) (*types.Transaction, error) {
	return _ParamCheckModule.contract.Transact(opts, "emergencyPause", project, funcSig, reason)
}

// EmergencyPause is a paid mutator transaction binding the contract method 0x1bd229fc.
//
// Solidity: function emergencyPause(address project, bytes4 funcSig, string reason) returns()
func (_ParamCheckModule *ParamCheckModuleSession) EmergencyPause(project common.Address, funcSig [4]byte, reason string) (*types.Transaction, error) {
	return _ParamCheckModule.Contract.EmergencyPause(&_ParamCheckModule.TransactOpts, project, funcSig, reason)
}

// EmergencyPause is a paid mutator transaction binding the contract method 0x1bd229fc.
//
// Solidity: function emergencyPause(address project, bytes4 funcSig, string reason) returns()
func (_ParamCheckModule *ParamCheckModuleTransactorSession) EmergencyPause(project common.Address, funcSig [4]byte, reason string) (*types.Transaction, error) {
	return _ParamCheckModule.Contract.EmergencyPause(&_ParamCheckModule.TransactOpts, project, funcSig, reason)
}

// RemoveExpressionRule is a paid mutator transaction binding the contract method 0x2eb4e272.
//
// Solidity: function removeExpressionRule(address project, bytes4 funcSig, uint256 ruleIndex) returns()
func (_ParamCheckModule *ParamCheckModuleTransactor) RemoveExpressionRule(opts *bind.TransactOpts, project common.Address, funcSig [4]byte, ruleIndex *big.Int) (*types.Transaction, error) {
	return _ParamCheckModule.contract.Transact(opts, "removeExpressionRule", project, funcSig, ruleIndex)
}

// RemoveExpressionRule is a paid mutator transaction binding the contract method 0x2eb4e272.
//
// Solidity: function removeExpressionRule(address project, bytes4 funcSig, uint256 ruleIndex) returns()
func (_ParamCheckModule *ParamCheckModuleSession) RemoveExpressionRule(project common.Address, funcSig [4]byte, ruleIndex *big.Int) (*types.Transaction, error) {
	return _ParamCheckModule.Contract.RemoveExpressionRule(&_ParamCheckModule.TransactOpts, project, funcSig, ruleIndex)
}

// RemoveExpressionRule is a paid mutator transaction binding the contract method 0x2eb4e272.
//
// Solidity: function removeExpressionRule(address project, bytes4 funcSig, uint256 ruleIndex) returns()
func (_ParamCheckModule *ParamCheckModuleTransactorSession) RemoveExpressionRule(project common.Address, funcSig [4]byte, ruleIndex *big.Int) (*types.Transaction, error) {
	return _ParamCheckModule.Contract.RemoveExpressionRule(&_ParamCheckModule.TransactOpts, project, funcSig, ruleIndex)
}

// RemoveInfo is a paid mutator transaction binding the contract method 0x5a5a2374.
//
// Solidity: function removeInfo(bytes data) returns()
func (_ParamCheckModule *ParamCheckModuleTransactor) RemoveInfo(opts *bind.TransactOpts, data []byte) (*types.Transaction, error) {
	return _ParamCheckModule.contract.Transact(opts, "removeInfo", data)
}

// RemoveInfo is a paid mutator transaction binding the contract method 0x5a5a2374.
//
// Solidity: function removeInfo(bytes data) returns()
func (_ParamCheckModule *ParamCheckModuleSession) RemoveInfo(data []byte) (*types.Transaction, error) {
	return _ParamCheckModule.Contract.RemoveInfo(&_ParamCheckModule.TransactOpts, data)
}

// RemoveInfo is a paid mutator transaction binding the contract method 0x5a5a2374.
//
// Solidity: function removeInfo(bytes data) returns()
func (_ParamCheckModule *ParamCheckModuleTransactorSession) RemoveInfo(data []byte) (*types.Transaction, error) {
	return _ParamCheckModule.Contract.RemoveInfo(&_ParamCheckModule.TransactOpts, data)
}

// SetAutopatchOracle is a paid mutator transaction binding the contract method 0xf3a364ad.
//
// Solidity: function setAutopatchOracle(address oracle, bool authorized) returns()
func (_ParamCheckModule *ParamCheckModuleTransactor) SetAutopatchOracle(opts *bind.TransactOpts, oracle common.Address, authorized bool) (*types.Transaction, error) {
	return _ParamCheckModule.contract.Transact(opts, "setAutopatchOracle", oracle, authorized)
}

// SetAutopatchOracle is a paid mutator transaction binding the contract method 0xf3a364ad.
//
// Solidity: function setAutopatchOracle(address oracle, bool authorized) returns()
func (_ParamCheckModule *ParamCheckModuleSession) SetAutopatchOracle(oracle common.Address, authorized bool) (*types.Transaction, error) {
	return _ParamCheckModule.Contract.SetAutopatchOracle(&_ParamCheckModule.TransactOpts, oracle, authorized)
}

// SetAutopatchOracle is a paid mutator transaction binding the contract method 0xf3a364ad.
//
// Solidity: function setAutopatchOracle(address oracle, bool authorized) returns()
func (_ParamCheckModule *ParamCheckModuleTransactorSession) SetAutopatchOracle(oracle common.Address, authorized bool) (*types.Transaction, error) {
	return _ParamCheckModule.Contract.SetAutopatchOracle(&_ParamCheckModule.TransactOpts, oracle, authorized)
}

// SetInfo is a paid mutator transaction binding the contract method 0xc5bb1844.
//
// Solidity: function setInfo(bytes data) returns()
func (_ParamCheckModule *ParamCheckModuleTransactor) SetInfo(opts *bind.TransactOpts, data []byte) (*types.Transaction, error) {
	return _ParamCheckModule.contract.Transact(opts, "setInfo", data)
}

// SetInfo is a paid mutator transaction binding the contract method 0xc5bb1844.
//
// Solidity: function setInfo(bytes data) returns()
func (_ParamCheckModule *ParamCheckModuleSession) SetInfo(data []byte) (*types.Transaction, error) {
	return _ParamCheckModule.Contract.SetInfo(&_ParamCheckModule.TransactOpts, data)
}

// SetInfo is a paid mutator transaction binding the contract method 0xc5bb1844.
//
// Solidity: function setInfo(bytes data) returns()
func (_ParamCheckModule *ParamCheckModuleTransactorSession) SetInfo(data []byte) (*types.Transaction, error) {
	return _ParamCheckModule.Contract.SetInfo(&_ParamCheckModule.TransactOpts, data)
}

// SetMode is a paid mutator transaction binding the contract method 0xe56ac775.
//
// Solidity: function setMode(bytes data) returns()
func (_ParamCheckModule *ParamCheckModuleTransactor) SetMode(opts *bind.TransactOpts, data []byte) (*types.Transaction, error) {
	return _ParamCheckModule.contract.Transact(opts, "setMode", data)
}

// SetMode is a paid mutator transaction binding the contract method 0xe56ac775.
//
// Solidity: function setMode(bytes data) returns()
func (_ParamCheckModule *ParamCheckModuleSession) SetMode(data []byte) (*types.Transaction, error) {
	return _ParamCheckModule.Contract.SetMode(&_ParamCheckModule.TransactOpts, data)
}

// SetMode is a paid mutator transaction binding the contract method 0xe56ac775.
//
// Solidity: function setMode(bytes data) returns()
func (_ParamCheckModule *ParamCheckModuleTransactorSession) SetMode(data []byte) (*types.Transaction, error) {
	return _ParamCheckModule.Contract.SetMode(&_ParamCheckModule.TransactOpts, data)
}

// UpdateExpressionRules is a paid mutator transaction binding the contract method 0x8eefbf5c.
//
// Solidity: function updateExpressionRules(address project, bytes4 funcSig, (string,(uint8,uint8,uint8,bytes32,int256)[],int256,uint256)[] rules) returns()
func (_ParamCheckModule *ParamCheckModuleTransactor) UpdateExpressionRules(opts *bind.TransactOpts, project common.Address, funcSig [4]byte, rules []ExpressionRuleLibExpressionRule) (*types.Transaction, error) {
	return _ParamCheckModule.contract.Transact(opts, "updateExpressionRules", project, funcSig, rules)
}

// UpdateExpressionRules is a paid mutator transaction binding the contract method 0x8eefbf5c.
//
// Solidity: function updateExpressionRules(address project, bytes4 funcSig, (string,(uint8,uint8,uint8,bytes32,int256)[],int256,uint256)[] rules) returns()
func (_ParamCheckModule *ParamCheckModuleSession) UpdateExpressionRules(project common.Address, funcSig [4]byte, rules []ExpressionRuleLibExpressionRule) (*types.Transaction, error) {
	return _ParamCheckModule.Contract.UpdateExpressionRules(&_ParamCheckModule.TransactOpts, project, funcSig, rules)
}

// UpdateExpressionRules is a paid mutator transaction binding the contract method 0x8eefbf5c.
//
// Solidity: function updateExpressionRules(address project, bytes4 funcSig, (string,(uint8,uint8,uint8,bytes32,int256)[],int256,uint256)[] rules) returns()
func (_ParamCheckModule *ParamCheckModuleTransactorSession) UpdateExpressionRules(project common.Address, funcSig [4]byte, rules []ExpressionRuleLibExpressionRule) (*types.Transaction, error) {
	return _ParamCheckModule.Contract.UpdateExpressionRules(&_ParamCheckModule.TransactOpts, project, funcSig, rules)
}

// UpdateFromAutopatch is a paid mutator transaction binding the contract method 0x3dc5d77a.
//
// Solidity: function updateFromAutopatch(address project, bytes4 funcSig, (uint8,uint8,bytes32[],bool,bytes32,bytes32,uint256)[] summaries, uint256 threshold) returns()
func (_ParamCheckModule *ParamCheckModuleTransactor) UpdateFromAutopatch(opts *bind.TransactOpts, project common.Address, funcSig [4]byte, summaries []ParamCheckModuleParamSummary, threshold *big.Int) (*types.Transaction, error) {
	return _ParamCheckModule.contract.Transact(opts, "updateFromAutopatch", project, funcSig, summaries, threshold)
}

// UpdateFromAutopatch is a paid mutator transaction binding the contract method 0x3dc5d77a.
//
// Solidity: function updateFromAutopatch(address project, bytes4 funcSig, (uint8,uint8,bytes32[],bool,bytes32,bytes32,uint256)[] summaries, uint256 threshold) returns()
func (_ParamCheckModule *ParamCheckModuleSession) UpdateFromAutopatch(project common.Address, funcSig [4]byte, summaries []ParamCheckModuleParamSummary, threshold *big.Int) (*types.Transaction, error) {
	return _ParamCheckModule.Contract.UpdateFromAutopatch(&_ParamCheckModule.TransactOpts, project, funcSig, summaries, threshold)
}

// UpdateFromAutopatch is a paid mutator transaction binding the contract method 0x3dc5d77a.
//
// Solidity: function updateFromAutopatch(address project, bytes4 funcSig, (uint8,uint8,bytes32[],bool,bytes32,bytes32,uint256)[] summaries, uint256 threshold) returns()
func (_ParamCheckModule *ParamCheckModuleTransactorSession) UpdateFromAutopatch(project common.Address, funcSig [4]byte, summaries []ParamCheckModuleParamSummary, threshold *big.Int) (*types.Transaction, error) {
	return _ParamCheckModule.Contract.UpdateFromAutopatch(&_ParamCheckModule.TransactOpts, project, funcSig, summaries, threshold)
}

// UpdateManager is a paid mutator transaction binding the contract method 0x58aba00f.
//
// Solidity: function updateManager(address newManager) returns()
func (_ParamCheckModule *ParamCheckModuleTransactor) UpdateManager(opts *bind.TransactOpts, newManager common.Address) (*types.Transaction, error) {
	return _ParamCheckModule.contract.Transact(opts, "updateManager", newManager)
}

// UpdateManager is a paid mutator transaction binding the contract method 0x58aba00f.
//
// Solidity: function updateManager(address newManager) returns()
func (_ParamCheckModule *ParamCheckModuleSession) UpdateManager(newManager common.Address) (*types.Transaction, error) {
	return _ParamCheckModule.Contract.UpdateManager(&_ParamCheckModule.TransactOpts, newManager)
}

// UpdateManager is a paid mutator transaction binding the contract method 0x58aba00f.
//
// Solidity: function updateManager(address newManager) returns()
func (_ParamCheckModule *ParamCheckModuleTransactorSession) UpdateManager(newManager common.Address) (*types.Transaction, error) {
	return _ParamCheckModule.Contract.UpdateManager(&_ParamCheckModule.TransactOpts, newManager)
}

// ParamCheckModuleAutopatchAppliedIterator is returned from FilterAutopatchApplied and is used to iterate over the raw logs and unpacked data for AutopatchApplied events raised by the ParamCheckModule contract.
type ParamCheckModuleAutopatchAppliedIterator struct {
	Event *ParamCheckModuleAutopatchApplied // Event containing the contract specifics and raw log

	contract *bind.BoundContract // Generic contract to use for unpacking event data
	event    string              // Event name to use for unpacking event data

	logs chan types.Log        // Log channel receiving the found contract events
	sub  ethereum.Subscription // Subscription for errors, completion and termination
	done bool                  // Whether the subscription completed delivering logs
	fail error                 // Occurred error to stop iteration
}

// Next advances the iterator to the subsequent event, returning whether there
// are any more events found. In case of a retrieval or parsing error, false is
// returned and Error() can be queried for the exact failure.
func (it *ParamCheckModuleAutopatchAppliedIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(ParamCheckModuleAutopatchApplied)
			if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
				it.fail = err
				return false
			}
			it.Event.Raw = log
			return true

		default:
			return false
		}
	}
	// Iterator still in progress, wait for either a data or an error event
	select {
	case log := <-it.logs:
		it.Event = new(ParamCheckModuleAutopatchApplied)
		if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
			it.fail = err
			return false
		}
		it.Event.Raw = log
		return true

	case err := <-it.sub.Err():
		it.done = true
		it.fail = err
		return it.Next()
	}
}

// Error returns any retrieval or parsing error occurred during filtering.
func (it *ParamCheckModuleAutopatchAppliedIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *ParamCheckModuleAutopatchAppliedIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// ParamCheckModuleAutopatchApplied represents a AutopatchApplied event raised by the ParamCheckModule contract.
type ParamCheckModuleAutopatchApplied struct {
	Project     common.Address
	FuncSig     [4]byte
	RuleCount   *big.Int
	SummaryHash [32]byte
	Raw         types.Log // Blockchain specific contextual infos
}

// FilterAutopatchApplied is a free log retrieval operation binding the contract event 0x4dee774d9f9445eb632dae071c21c5a1325f5945a99f9013c21b584bcf222be7.
//
// Solidity: event AutopatchApplied(address indexed project, bytes4 indexed funcSig, uint256 ruleCount, bytes32 summaryHash)
func (_ParamCheckModule *ParamCheckModuleFilterer) FilterAutopatchApplied(opts *bind.FilterOpts, project []common.Address, funcSig [][4]byte) (*ParamCheckModuleAutopatchAppliedIterator, error) {

	var projectRule []interface{}
	for _, projectItem := range project {
		projectRule = append(projectRule, projectItem)
	}
	var funcSigRule []interface{}
	for _, funcSigItem := range funcSig {
		funcSigRule = append(funcSigRule, funcSigItem)
	}

	logs, sub, err := _ParamCheckModule.contract.FilterLogs(opts, "AutopatchApplied", projectRule, funcSigRule)
	if err != nil {
		return nil, err
	}
	return &ParamCheckModuleAutopatchAppliedIterator{contract: _ParamCheckModule.contract, event: "AutopatchApplied", logs: logs, sub: sub}, nil
}

// WatchAutopatchApplied is a free log subscription operation binding the contract event 0x4dee774d9f9445eb632dae071c21c5a1325f5945a99f9013c21b584bcf222be7.
//
// Solidity: event AutopatchApplied(address indexed project, bytes4 indexed funcSig, uint256 ruleCount, bytes32 summaryHash)
func (_ParamCheckModule *ParamCheckModuleFilterer) WatchAutopatchApplied(opts *bind.WatchOpts, sink chan<- *ParamCheckModuleAutopatchApplied, project []common.Address, funcSig [][4]byte) (event.Subscription, error) {

	var projectRule []interface{}
	for _, projectItem := range project {
		projectRule = append(projectRule, projectItem)
	}
	var funcSigRule []interface{}
	for _, funcSigItem := range funcSig {
		funcSigRule = append(funcSigRule, funcSigItem)
	}

	logs, sub, err := _ParamCheckModule.contract.WatchLogs(opts, "AutopatchApplied", projectRule, funcSigRule)
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(ParamCheckModuleAutopatchApplied)
				if err := _ParamCheckModule.contract.UnpackLog(event, "AutopatchApplied", log); err != nil {
					return err
				}
				event.Raw = log

				select {
				case sink <- event:
				case err := <-sub.Err():
					return err
				case <-quit:
					return nil
				}
			case err := <-sub.Err():
				return err
			case <-quit:
				return nil
			}
		}
	}), nil
}

// ParseAutopatchApplied is a log parse operation binding the contract event 0x4dee774d9f9445eb632dae071c21c5a1325f5945a99f9013c21b584bcf222be7.
//
// Solidity: event AutopatchApplied(address indexed project, bytes4 indexed funcSig, uint256 ruleCount, bytes32 summaryHash)
func (_ParamCheckModule *ParamCheckModuleFilterer) ParseAutopatchApplied(log types.Log) (*ParamCheckModuleAutopatchApplied, error) {
	event := new(ParamCheckModuleAutopatchApplied)
	if err := _ParamCheckModule.contract.UnpackLog(event, "AutopatchApplied", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}

// ParamCheckModuleAutopatchOracleSetIterator is returned from FilterAutopatchOracleSet and is used to iterate over the raw logs and unpacked data for AutopatchOracleSet events raised by the ParamCheckModule contract.
type ParamCheckModuleAutopatchOracleSetIterator struct {
	Event *ParamCheckModuleAutopatchOracleSet // Event containing the contract specifics and raw log

	contract *bind.BoundContract // Generic contract to use for unpacking event data
	event    string              // Event name to use for unpacking event data

	logs chan types.Log        // Log channel receiving the found contract events
	sub  ethereum.Subscription // Subscription for errors, completion and termination
	done bool                  // Whether the subscription completed delivering logs
	fail error                 // Occurred error to stop iteration
}

// Next advances the iterator to the subsequent event, returning whether there
// are any more events found. In case of a retrieval or parsing error, false is
// returned and Error() can be queried for the exact failure.
func (it *ParamCheckModuleAutopatchOracleSetIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(ParamCheckModuleAutopatchOracleSet)
			if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
				it.fail = err
				return false
			}
			it.Event.Raw = log
			return true

		default:
			return false
		}
	}
	// Iterator still in progress, wait for either a data or an error event
	select {
	case log := <-it.logs:
		it.Event = new(ParamCheckModuleAutopatchOracleSet)
		if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
			it.fail = err
			return false
		}
		it.Event.Raw = log
		return true

	case err := <-it.sub.Err():
		it.done = true
		it.fail = err
		return it.Next()
	}
}

// Error returns any retrieval or parsing error occurred during filtering.
func (it *ParamCheckModuleAutopatchOracleSetIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *ParamCheckModuleAutopatchOracleSetIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// ParamCheckModuleAutopatchOracleSet represents a AutopatchOracleSet event raised by the ParamCheckModule contract.
type ParamCheckModuleAutopatchOracleSet struct {
	Oracle     common.Address
	Authorized bool
	Raw        types.Log // Blockchain specific contextual infos
}

// FilterAutopatchOracleSet is a free log retrieval operation binding the contract event 0x167187772c483e4ccaa35e4244b4bed124745d04d5d179d6565818cd2ec6e708.
//
// Solidity: event AutopatchOracleSet(address indexed oracle, bool authorized)
func (_ParamCheckModule *ParamCheckModuleFilterer) FilterAutopatchOracleSet(opts *bind.FilterOpts, oracle []common.Address) (*ParamCheckModuleAutopatchOracleSetIterator, error) {

	var oracleRule []interface{}
	for _, oracleItem := range oracle {
		oracleRule = append(oracleRule, oracleItem)
	}

	logs, sub, err := _ParamCheckModule.contract.FilterLogs(opts, "AutopatchOracleSet", oracleRule)
	if err != nil {
		return nil, err
	}
	return &ParamCheckModuleAutopatchOracleSetIterator{contract: _ParamCheckModule.contract, event: "AutopatchOracleSet", logs: logs, sub: sub}, nil
}

// WatchAutopatchOracleSet is a free log subscription operation binding the contract event 0x167187772c483e4ccaa35e4244b4bed124745d04d5d179d6565818cd2ec6e708.
//
// Solidity: event AutopatchOracleSet(address indexed oracle, bool authorized)
func (_ParamCheckModule *ParamCheckModuleFilterer) WatchAutopatchOracleSet(opts *bind.WatchOpts, sink chan<- *ParamCheckModuleAutopatchOracleSet, oracle []common.Address) (event.Subscription, error) {

	var oracleRule []interface{}
	for _, oracleItem := range oracle {
		oracleRule = append(oracleRule, oracleItem)
	}

	logs, sub, err := _ParamCheckModule.contract.WatchLogs(opts, "AutopatchOracleSet", oracleRule)
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(ParamCheckModuleAutopatchOracleSet)
				if err := _ParamCheckModule.contract.UnpackLog(event, "AutopatchOracleSet", log); err != nil {
					return err
				}
				event.Raw = log

				select {
				case sink <- event:
				case err := <-sub.Err():
					return err
				case <-quit:
					return nil
				}
			case err := <-sub.Err():
				return err
			case <-quit:
				return nil
			}
		}
	}), nil
}

// ParseAutopatchOracleSet is a log parse operation binding the contract event 0x167187772c483e4ccaa35e4244b4bed124745d04d5d179d6565818cd2ec6e708.
//
// Solidity: event AutopatchOracleSet(address indexed oracle, bool authorized)
func (_ParamCheckModule *ParamCheckModuleFilterer) ParseAutopatchOracleSet(log types.Log) (*ParamCheckModuleAutopatchOracleSet, error) {
	event := new(ParamCheckModuleAutopatchOracleSet)
	if err := _ParamCheckModule.contract.UnpackLog(event, "AutopatchOracleSet", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}

// ParamCheckModuleAutopatchRuleIterator is returned from FilterAutopatchRule and is used to iterate over the raw logs and unpacked data for AutopatchRule events raised by the ParamCheckModule contract.
type ParamCheckModuleAutopatchRuleIterator struct {
	Event *ParamCheckModuleAutopatchRule // Event containing the contract specifics and raw log

	contract *bind.BoundContract // Generic contract to use for unpacking event data
	event    string              // Event name to use for unpacking event data

	logs chan types.Log        // Log channel receiving the found contract events
	sub  ethereum.Subscription // Subscription for errors, completion and termination
	done bool                  // Whether the subscription completed delivering logs
	fail error                 // Occurred error to stop iteration
}

// Next advances the iterator to the subsequent event, returning whether there
// are any more events found. In case of a retrieval or parsing error, false is
// returned and Error() can be queried for the exact failure.
func (it *ParamCheckModuleAutopatchRuleIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(ParamCheckModuleAutopatchRule)
			if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
				it.fail = err
				return false
			}
			it.Event.Raw = log
			return true

		default:
			return false
		}
	}
	// Iterator still in progress, wait for either a data or an error event
	select {
	case log := <-it.logs:
		it.Event = new(ParamCheckModuleAutopatchRule)
		if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
			it.fail = err
			return false
		}
		it.Event.Raw = log
		return true

	case err := <-it.sub.Err():
		it.done = true
		it.fail = err
		return it.Next()
	}
}

// Error returns any retrieval or parsing error occurred during filtering.
func (it *ParamCheckModuleAutopatchRuleIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *ParamCheckModuleAutopatchRuleIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// ParamCheckModuleAutopatchRule represents a AutopatchRule event raised by the ParamCheckModule contract.
type ParamCheckModuleAutopatchRule struct {
	Project      common.Address
	FuncSig      [4]byte
	RuleIdx      uint8
	ParamIndex   uint8
	ParamType    uint8
	IsRange      bool
	RangeMin     [32]byte
	RangeMax     [32]byte
	AllowedCount *big.Int
	Raw          types.Log // Blockchain specific contextual infos
}

// FilterAutopatchRule is a free log retrieval operation binding the contract event 0x1b8bc7480cb96f27908627c063c99492612784f8a0cf7415e044b7b42fc327f9.
//
// Solidity: event AutopatchRule(address indexed project, bytes4 indexed funcSig, uint8 ruleIdx, uint8 paramIndex, uint8 paramType, bool isRange, bytes32 rangeMin, bytes32 rangeMax, uint256 allowedCount)
func (_ParamCheckModule *ParamCheckModuleFilterer) FilterAutopatchRule(opts *bind.FilterOpts, project []common.Address, funcSig [][4]byte) (*ParamCheckModuleAutopatchRuleIterator, error) {

	var projectRule []interface{}
	for _, projectItem := range project {
		projectRule = append(projectRule, projectItem)
	}
	var funcSigRule []interface{}
	for _, funcSigItem := range funcSig {
		funcSigRule = append(funcSigRule, funcSigItem)
	}

	logs, sub, err := _ParamCheckModule.contract.FilterLogs(opts, "AutopatchRule", projectRule, funcSigRule)
	if err != nil {
		return nil, err
	}
	return &ParamCheckModuleAutopatchRuleIterator{contract: _ParamCheckModule.contract, event: "AutopatchRule", logs: logs, sub: sub}, nil
}

// WatchAutopatchRule is a free log subscription operation binding the contract event 0x1b8bc7480cb96f27908627c063c99492612784f8a0cf7415e044b7b42fc327f9.
//
// Solidity: event AutopatchRule(address indexed project, bytes4 indexed funcSig, uint8 ruleIdx, uint8 paramIndex, uint8 paramType, bool isRange, bytes32 rangeMin, bytes32 rangeMax, uint256 allowedCount)
func (_ParamCheckModule *ParamCheckModuleFilterer) WatchAutopatchRule(opts *bind.WatchOpts, sink chan<- *ParamCheckModuleAutopatchRule, project []common.Address, funcSig [][4]byte) (event.Subscription, error) {

	var projectRule []interface{}
	for _, projectItem := range project {
		projectRule = append(projectRule, projectItem)
	}
	var funcSigRule []interface{}
	for _, funcSigItem := range funcSig {
		funcSigRule = append(funcSigRule, funcSigItem)
	}

	logs, sub, err := _ParamCheckModule.contract.WatchLogs(opts, "AutopatchRule", projectRule, funcSigRule)
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(ParamCheckModuleAutopatchRule)
				if err := _ParamCheckModule.contract.UnpackLog(event, "AutopatchRule", log); err != nil {
					return err
				}
				event.Raw = log

				select {
				case sink <- event:
				case err := <-sub.Err():
					return err
				case <-quit:
					return nil
				}
			case err := <-sub.Err():
				return err
			case <-quit:
				return nil
			}
		}
	}), nil
}

// ParseAutopatchRule is a log parse operation binding the contract event 0x1b8bc7480cb96f27908627c063c99492612784f8a0cf7415e044b7b42fc327f9.
//
// Solidity: event AutopatchRule(address indexed project, bytes4 indexed funcSig, uint8 ruleIdx, uint8 paramIndex, uint8 paramType, bool isRange, bytes32 rangeMin, bytes32 rangeMax, uint256 allowedCount)
func (_ParamCheckModule *ParamCheckModuleFilterer) ParseAutopatchRule(log types.Log) (*ParamCheckModuleAutopatchRule, error) {
	event := new(ParamCheckModuleAutopatchRule)
	if err := _ParamCheckModule.contract.UnpackLog(event, "AutopatchRule", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}

// ParamCheckModuleEmergencyPauseIterator is returned from FilterEmergencyPause and is used to iterate over the raw logs and unpacked data for EmergencyPause events raised by the ParamCheckModule contract.
type ParamCheckModuleEmergencyPauseIterator struct {
	Event *ParamCheckModuleEmergencyPause // Event containing the contract specifics and raw log

	contract *bind.BoundContract // Generic contract to use for unpacking event data
	event    string              // Event name to use for unpacking event data

	logs chan types.Log        // Log channel receiving the found contract events
	sub  ethereum.Subscription // Subscription for errors, completion and termination
	done bool                  // Whether the subscription completed delivering logs
	fail error                 // Occurred error to stop iteration
}

// Next advances the iterator to the subsequent event, returning whether there
// are any more events found. In case of a retrieval or parsing error, false is
// returned and Error() can be queried for the exact failure.
func (it *ParamCheckModuleEmergencyPauseIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(ParamCheckModuleEmergencyPause)
			if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
				it.fail = err
				return false
			}
			it.Event.Raw = log
			return true

		default:
			return false
		}
	}
	// Iterator still in progress, wait for either a data or an error event
	select {
	case log := <-it.logs:
		it.Event = new(ParamCheckModuleEmergencyPause)
		if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
			it.fail = err
			return false
		}
		it.Event.Raw = log
		return true

	case err := <-it.sub.Err():
		it.done = true
		it.fail = err
		return it.Next()
	}
}

// Error returns any retrieval or parsing error occurred during filtering.
func (it *ParamCheckModuleEmergencyPauseIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *ParamCheckModuleEmergencyPauseIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// ParamCheckModuleEmergencyPause represents a EmergencyPause event raised by the ParamCheckModule contract.
type ParamCheckModuleEmergencyPause struct {
	Project common.Address
	FuncSig [4]byte
	Reason  string
	Raw     types.Log // Blockchain specific contextual infos
}

// FilterEmergencyPause is a free log retrieval operation binding the contract event 0x3ca04eb65c349bf0623268ec17dc1dd54ecae10e2583c629b8a5697d9a6b4136.
//
// Solidity: event EmergencyPause(address indexed project, bytes4 indexed funcSig, string reason)
func (_ParamCheckModule *ParamCheckModuleFilterer) FilterEmergencyPause(opts *bind.FilterOpts, project []common.Address, funcSig [][4]byte) (*ParamCheckModuleEmergencyPauseIterator, error) {

	var projectRule []interface{}
	for _, projectItem := range project {
		projectRule = append(projectRule, projectItem)
	}
	var funcSigRule []interface{}
	for _, funcSigItem := range funcSig {
		funcSigRule = append(funcSigRule, funcSigItem)
	}

	logs, sub, err := _ParamCheckModule.contract.FilterLogs(opts, "EmergencyPause", projectRule, funcSigRule)
	if err != nil {
		return nil, err
	}
	return &ParamCheckModuleEmergencyPauseIterator{contract: _ParamCheckModule.contract, event: "EmergencyPause", logs: logs, sub: sub}, nil
}

// WatchEmergencyPause is a free log subscription operation binding the contract event 0x3ca04eb65c349bf0623268ec17dc1dd54ecae10e2583c629b8a5697d9a6b4136.
//
// Solidity: event EmergencyPause(address indexed project, bytes4 indexed funcSig, string reason)
func (_ParamCheckModule *ParamCheckModuleFilterer) WatchEmergencyPause(opts *bind.WatchOpts, sink chan<- *ParamCheckModuleEmergencyPause, project []common.Address, funcSig [][4]byte) (event.Subscription, error) {

	var projectRule []interface{}
	for _, projectItem := range project {
		projectRule = append(projectRule, projectItem)
	}
	var funcSigRule []interface{}
	for _, funcSigItem := range funcSig {
		funcSigRule = append(funcSigRule, funcSigItem)
	}

	logs, sub, err := _ParamCheckModule.contract.WatchLogs(opts, "EmergencyPause", projectRule, funcSigRule)
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(ParamCheckModuleEmergencyPause)
				if err := _ParamCheckModule.contract.UnpackLog(event, "EmergencyPause", log); err != nil {
					return err
				}
				event.Raw = log

				select {
				case sink <- event:
				case err := <-sub.Err():
					return err
				case <-quit:
					return nil
				}
			case err := <-sub.Err():
				return err
			case <-quit:
				return nil
			}
		}
	}), nil
}

// ParseEmergencyPause is a log parse operation binding the contract event 0x3ca04eb65c349bf0623268ec17dc1dd54ecae10e2583c629b8a5697d9a6b4136.
//
// Solidity: event EmergencyPause(address indexed project, bytes4 indexed funcSig, string reason)
func (_ParamCheckModule *ParamCheckModuleFilterer) ParseEmergencyPause(log types.Log) (*ParamCheckModuleEmergencyPause, error) {
	event := new(ParamCheckModuleEmergencyPause)
	if err := _ParamCheckModule.contract.UnpackLog(event, "EmergencyPause", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}

// ParamCheckModuleExpressionRuleDuplicateIterator is returned from FilterExpressionRuleDuplicate and is used to iterate over the raw logs and unpacked data for ExpressionRuleDuplicate events raised by the ParamCheckModule contract.
type ParamCheckModuleExpressionRuleDuplicateIterator struct {
	Event *ParamCheckModuleExpressionRuleDuplicate // Event containing the contract specifics and raw log

	contract *bind.BoundContract // Generic contract to use for unpacking event data
	event    string              // Event name to use for unpacking event data

	logs chan types.Log        // Log channel receiving the found contract events
	sub  ethereum.Subscription // Subscription for errors, completion and termination
	done bool                  // Whether the subscription completed delivering logs
	fail error                 // Occurred error to stop iteration
}

// Next advances the iterator to the subsequent event, returning whether there
// are any more events found. In case of a retrieval or parsing error, false is
// returned and Error() can be queried for the exact failure.
func (it *ParamCheckModuleExpressionRuleDuplicateIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(ParamCheckModuleExpressionRuleDuplicate)
			if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
				it.fail = err
				return false
			}
			it.Event.Raw = log
			return true

		default:
			return false
		}
	}
	// Iterator still in progress, wait for either a data or an error event
	select {
	case log := <-it.logs:
		it.Event = new(ParamCheckModuleExpressionRuleDuplicate)
		if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
			it.fail = err
			return false
		}
		it.Event.Raw = log
		return true

	case err := <-it.sub.Err():
		it.done = true
		it.fail = err
		return it.Next()
	}
}

// Error returns any retrieval or parsing error occurred during filtering.
func (it *ParamCheckModuleExpressionRuleDuplicateIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *ParamCheckModuleExpressionRuleDuplicateIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// ParamCheckModuleExpressionRuleDuplicate represents a ExpressionRuleDuplicate event raised by the ParamCheckModule contract.
type ParamCheckModuleExpressionRuleDuplicate struct {
	Project  common.Address
	FuncSig  [4]byte
	RuleHash [32]byte
	Raw      types.Log // Blockchain specific contextual infos
}

// FilterExpressionRuleDuplicate is a free log retrieval operation binding the contract event 0x43dfb1e1f9745a068cfeadec274fc35ceebbada66b438b70f35950714391a653.
//
// Solidity: event ExpressionRuleDuplicate(address indexed project, bytes4 indexed funcSig, bytes32 ruleHash)
func (_ParamCheckModule *ParamCheckModuleFilterer) FilterExpressionRuleDuplicate(opts *bind.FilterOpts, project []common.Address, funcSig [][4]byte) (*ParamCheckModuleExpressionRuleDuplicateIterator, error) {

	var projectRule []interface{}
	for _, projectItem := range project {
		projectRule = append(projectRule, projectItem)
	}
	var funcSigRule []interface{}
	for _, funcSigItem := range funcSig {
		funcSigRule = append(funcSigRule, funcSigItem)
	}

	logs, sub, err := _ParamCheckModule.contract.FilterLogs(opts, "ExpressionRuleDuplicate", projectRule, funcSigRule)
	if err != nil {
		return nil, err
	}
	return &ParamCheckModuleExpressionRuleDuplicateIterator{contract: _ParamCheckModule.contract, event: "ExpressionRuleDuplicate", logs: logs, sub: sub}, nil
}

// WatchExpressionRuleDuplicate is a free log subscription operation binding the contract event 0x43dfb1e1f9745a068cfeadec274fc35ceebbada66b438b70f35950714391a653.
//
// Solidity: event ExpressionRuleDuplicate(address indexed project, bytes4 indexed funcSig, bytes32 ruleHash)
func (_ParamCheckModule *ParamCheckModuleFilterer) WatchExpressionRuleDuplicate(opts *bind.WatchOpts, sink chan<- *ParamCheckModuleExpressionRuleDuplicate, project []common.Address, funcSig [][4]byte) (event.Subscription, error) {

	var projectRule []interface{}
	for _, projectItem := range project {
		projectRule = append(projectRule, projectItem)
	}
	var funcSigRule []interface{}
	for _, funcSigItem := range funcSig {
		funcSigRule = append(funcSigRule, funcSigItem)
	}

	logs, sub, err := _ParamCheckModule.contract.WatchLogs(opts, "ExpressionRuleDuplicate", projectRule, funcSigRule)
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(ParamCheckModuleExpressionRuleDuplicate)
				if err := _ParamCheckModule.contract.UnpackLog(event, "ExpressionRuleDuplicate", log); err != nil {
					return err
				}
				event.Raw = log

				select {
				case sink <- event:
				case err := <-sub.Err():
					return err
				case <-quit:
					return nil
				}
			case err := <-sub.Err():
				return err
			case <-quit:
				return nil
			}
		}
	}), nil
}

// ParseExpressionRuleDuplicate is a log parse operation binding the contract event 0x43dfb1e1f9745a068cfeadec274fc35ceebbada66b438b70f35950714391a653.
//
// Solidity: event ExpressionRuleDuplicate(address indexed project, bytes4 indexed funcSig, bytes32 ruleHash)
func (_ParamCheckModule *ParamCheckModuleFilterer) ParseExpressionRuleDuplicate(log types.Log) (*ParamCheckModuleExpressionRuleDuplicate, error) {
	event := new(ParamCheckModuleExpressionRuleDuplicate)
	if err := _ParamCheckModule.contract.UnpackLog(event, "ExpressionRuleDuplicate", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}

// ParamCheckModuleExpressionRuleRemovedIterator is returned from FilterExpressionRuleRemoved and is used to iterate over the raw logs and unpacked data for ExpressionRuleRemoved events raised by the ParamCheckModule contract.
type ParamCheckModuleExpressionRuleRemovedIterator struct {
	Event *ParamCheckModuleExpressionRuleRemoved // Event containing the contract specifics and raw log

	contract *bind.BoundContract // Generic contract to use for unpacking event data
	event    string              // Event name to use for unpacking event data

	logs chan types.Log        // Log channel receiving the found contract events
	sub  ethereum.Subscription // Subscription for errors, completion and termination
	done bool                  // Whether the subscription completed delivering logs
	fail error                 // Occurred error to stop iteration
}

// Next advances the iterator to the subsequent event, returning whether there
// are any more events found. In case of a retrieval or parsing error, false is
// returned and Error() can be queried for the exact failure.
func (it *ParamCheckModuleExpressionRuleRemovedIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(ParamCheckModuleExpressionRuleRemoved)
			if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
				it.fail = err
				return false
			}
			it.Event.Raw = log
			return true

		default:
			return false
		}
	}
	// Iterator still in progress, wait for either a data or an error event
	select {
	case log := <-it.logs:
		it.Event = new(ParamCheckModuleExpressionRuleRemoved)
		if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
			it.fail = err
			return false
		}
		it.Event.Raw = log
		return true

	case err := <-it.sub.Err():
		it.done = true
		it.fail = err
		return it.Next()
	}
}

// Error returns any retrieval or parsing error occurred during filtering.
func (it *ParamCheckModuleExpressionRuleRemovedIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *ParamCheckModuleExpressionRuleRemovedIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// ParamCheckModuleExpressionRuleRemoved represents a ExpressionRuleRemoved event raised by the ParamCheckModule contract.
type ParamCheckModuleExpressionRuleRemoved struct {
	Project   common.Address
	FuncSig   [4]byte
	RuleIndex *big.Int
	Raw       types.Log // Blockchain specific contextual infos
}

// FilterExpressionRuleRemoved is a free log retrieval operation binding the contract event 0x826d8ac69f45aebd285f3f322937f6d1f865ff14ffbed38e2e3ad8116c6ff0ad.
//
// Solidity: event ExpressionRuleRemoved(address indexed project, bytes4 indexed funcSig, uint256 ruleIndex)
func (_ParamCheckModule *ParamCheckModuleFilterer) FilterExpressionRuleRemoved(opts *bind.FilterOpts, project []common.Address, funcSig [][4]byte) (*ParamCheckModuleExpressionRuleRemovedIterator, error) {

	var projectRule []interface{}
	for _, projectItem := range project {
		projectRule = append(projectRule, projectItem)
	}
	var funcSigRule []interface{}
	for _, funcSigItem := range funcSig {
		funcSigRule = append(funcSigRule, funcSigItem)
	}

	logs, sub, err := _ParamCheckModule.contract.FilterLogs(opts, "ExpressionRuleRemoved", projectRule, funcSigRule)
	if err != nil {
		return nil, err
	}
	return &ParamCheckModuleExpressionRuleRemovedIterator{contract: _ParamCheckModule.contract, event: "ExpressionRuleRemoved", logs: logs, sub: sub}, nil
}

// WatchExpressionRuleRemoved is a free log subscription operation binding the contract event 0x826d8ac69f45aebd285f3f322937f6d1f865ff14ffbed38e2e3ad8116c6ff0ad.
//
// Solidity: event ExpressionRuleRemoved(address indexed project, bytes4 indexed funcSig, uint256 ruleIndex)
func (_ParamCheckModule *ParamCheckModuleFilterer) WatchExpressionRuleRemoved(opts *bind.WatchOpts, sink chan<- *ParamCheckModuleExpressionRuleRemoved, project []common.Address, funcSig [][4]byte) (event.Subscription, error) {

	var projectRule []interface{}
	for _, projectItem := range project {
		projectRule = append(projectRule, projectItem)
	}
	var funcSigRule []interface{}
	for _, funcSigItem := range funcSig {
		funcSigRule = append(funcSigRule, funcSigItem)
	}

	logs, sub, err := _ParamCheckModule.contract.WatchLogs(opts, "ExpressionRuleRemoved", projectRule, funcSigRule)
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(ParamCheckModuleExpressionRuleRemoved)
				if err := _ParamCheckModule.contract.UnpackLog(event, "ExpressionRuleRemoved", log); err != nil {
					return err
				}
				event.Raw = log

				select {
				case sink <- event:
				case err := <-sub.Err():
					return err
				case <-quit:
					return nil
				}
			case err := <-sub.Err():
				return err
			case <-quit:
				return nil
			}
		}
	}), nil
}

// ParseExpressionRuleRemoved is a log parse operation binding the contract event 0x826d8ac69f45aebd285f3f322937f6d1f865ff14ffbed38e2e3ad8116c6ff0ad.
//
// Solidity: event ExpressionRuleRemoved(address indexed project, bytes4 indexed funcSig, uint256 ruleIndex)
func (_ParamCheckModule *ParamCheckModuleFilterer) ParseExpressionRuleRemoved(log types.Log) (*ParamCheckModuleExpressionRuleRemoved, error) {
	event := new(ParamCheckModuleExpressionRuleRemoved)
	if err := _ParamCheckModule.contract.UnpackLog(event, "ExpressionRuleRemoved", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}

// ParamCheckModuleExpressionRuleUpdatedIterator is returned from FilterExpressionRuleUpdated and is used to iterate over the raw logs and unpacked data for ExpressionRuleUpdated events raised by the ParamCheckModule contract.
type ParamCheckModuleExpressionRuleUpdatedIterator struct {
	Event *ParamCheckModuleExpressionRuleUpdated // Event containing the contract specifics and raw log

	contract *bind.BoundContract // Generic contract to use for unpacking event data
	event    string              // Event name to use for unpacking event data

	logs chan types.Log        // Log channel receiving the found contract events
	sub  ethereum.Subscription // Subscription for errors, completion and termination
	done bool                  // Whether the subscription completed delivering logs
	fail error                 // Occurred error to stop iteration
}

// Next advances the iterator to the subsequent event, returning whether there
// are any more events found. In case of a retrieval or parsing error, false is
// returned and Error() can be queried for the exact failure.
func (it *ParamCheckModuleExpressionRuleUpdatedIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(ParamCheckModuleExpressionRuleUpdated)
			if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
				it.fail = err
				return false
			}
			it.Event.Raw = log
			return true

		default:
			return false
		}
	}
	// Iterator still in progress, wait for either a data or an error event
	select {
	case log := <-it.logs:
		it.Event = new(ParamCheckModuleExpressionRuleUpdated)
		if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
			it.fail = err
			return false
		}
		it.Event.Raw = log
		return true

	case err := <-it.sub.Err():
		it.done = true
		it.fail = err
		return it.Next()
	}
}

// Error returns any retrieval or parsing error occurred during filtering.
func (it *ParamCheckModuleExpressionRuleUpdatedIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *ParamCheckModuleExpressionRuleUpdatedIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// ParamCheckModuleExpressionRuleUpdated represents a ExpressionRuleUpdated event raised by the ParamCheckModule contract.
type ParamCheckModuleExpressionRuleUpdated struct {
	Project   common.Address
	FuncSig   [4]byte
	RuleIndex uint8
	RuleType  string
	Raw       types.Log // Blockchain specific contextual infos
}

// FilterExpressionRuleUpdated is a free log retrieval operation binding the contract event 0x8e874f97286020cf870b74593633e86351a217b2413e3b2b4e827d2312db615d.
//
// Solidity: event ExpressionRuleUpdated(address indexed project, bytes4 indexed funcSig, uint8 ruleIndex, string ruleType)
func (_ParamCheckModule *ParamCheckModuleFilterer) FilterExpressionRuleUpdated(opts *bind.FilterOpts, project []common.Address, funcSig [][4]byte) (*ParamCheckModuleExpressionRuleUpdatedIterator, error) {

	var projectRule []interface{}
	for _, projectItem := range project {
		projectRule = append(projectRule, projectItem)
	}
	var funcSigRule []interface{}
	for _, funcSigItem := range funcSig {
		funcSigRule = append(funcSigRule, funcSigItem)
	}

	logs, sub, err := _ParamCheckModule.contract.FilterLogs(opts, "ExpressionRuleUpdated", projectRule, funcSigRule)
	if err != nil {
		return nil, err
	}
	return &ParamCheckModuleExpressionRuleUpdatedIterator{contract: _ParamCheckModule.contract, event: "ExpressionRuleUpdated", logs: logs, sub: sub}, nil
}

// WatchExpressionRuleUpdated is a free log subscription operation binding the contract event 0x8e874f97286020cf870b74593633e86351a217b2413e3b2b4e827d2312db615d.
//
// Solidity: event ExpressionRuleUpdated(address indexed project, bytes4 indexed funcSig, uint8 ruleIndex, string ruleType)
func (_ParamCheckModule *ParamCheckModuleFilterer) WatchExpressionRuleUpdated(opts *bind.WatchOpts, sink chan<- *ParamCheckModuleExpressionRuleUpdated, project []common.Address, funcSig [][4]byte) (event.Subscription, error) {

	var projectRule []interface{}
	for _, projectItem := range project {
		projectRule = append(projectRule, projectItem)
	}
	var funcSigRule []interface{}
	for _, funcSigItem := range funcSig {
		funcSigRule = append(funcSigRule, funcSigItem)
	}

	logs, sub, err := _ParamCheckModule.contract.WatchLogs(opts, "ExpressionRuleUpdated", projectRule, funcSigRule)
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(ParamCheckModuleExpressionRuleUpdated)
				if err := _ParamCheckModule.contract.UnpackLog(event, "ExpressionRuleUpdated", log); err != nil {
					return err
				}
				event.Raw = log

				select {
				case sink <- event:
				case err := <-sub.Err():
					return err
				case <-quit:
					return nil
				}
			case err := <-sub.Err():
				return err
			case <-quit:
				return nil
			}
		}
	}), nil
}

// ParseExpressionRuleUpdated is a log parse operation binding the contract event 0x8e874f97286020cf870b74593633e86351a217b2413e3b2b4e827d2312db615d.
//
// Solidity: event ExpressionRuleUpdated(address indexed project, bytes4 indexed funcSig, uint8 ruleIndex, string ruleType)
func (_ParamCheckModule *ParamCheckModuleFilterer) ParseExpressionRuleUpdated(log types.Log) (*ParamCheckModuleExpressionRuleUpdated, error) {
	event := new(ParamCheckModuleExpressionRuleUpdated)
	if err := _ParamCheckModule.contract.UnpackLog(event, "ExpressionRuleUpdated", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}

// ParamCheckModuleExpressionRuleViolatedIterator is returned from FilterExpressionRuleViolated and is used to iterate over the raw logs and unpacked data for ExpressionRuleViolated events raised by the ParamCheckModule contract.
type ParamCheckModuleExpressionRuleViolatedIterator struct {
	Event *ParamCheckModuleExpressionRuleViolated // Event containing the contract specifics and raw log

	contract *bind.BoundContract // Generic contract to use for unpacking event data
	event    string              // Event name to use for unpacking event data

	logs chan types.Log        // Log channel receiving the found contract events
	sub  ethereum.Subscription // Subscription for errors, completion and termination
	done bool                  // Whether the subscription completed delivering logs
	fail error                 // Occurred error to stop iteration
}

// Next advances the iterator to the subsequent event, returning whether there
// are any more events found. In case of a retrieval or parsing error, false is
// returned and Error() can be queried for the exact failure.
func (it *ParamCheckModuleExpressionRuleViolatedIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(ParamCheckModuleExpressionRuleViolated)
			if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
				it.fail = err
				return false
			}
			it.Event.Raw = log
			return true

		default:
			return false
		}
	}
	// Iterator still in progress, wait for either a data or an error event
	select {
	case log := <-it.logs:
		it.Event = new(ParamCheckModuleExpressionRuleViolated)
		if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
			it.fail = err
			return false
		}
		it.Event.Raw = log
		return true

	case err := <-it.sub.Err():
		it.done = true
		it.fail = err
		return it.Next()
	}
}

// Error returns any retrieval or parsing error occurred during filtering.
func (it *ParamCheckModuleExpressionRuleViolatedIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *ParamCheckModuleExpressionRuleViolatedIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// ParamCheckModuleExpressionRuleViolated represents a ExpressionRuleViolated event raised by the ParamCheckModule contract.
type ParamCheckModuleExpressionRuleViolated struct {
	Project   common.Address
	FuncSig   [4]byte
	RuleIndex uint8
	Lhs       *big.Int
	Threshold *big.Int
	Raw       types.Log // Blockchain specific contextual infos
}

// FilterExpressionRuleViolated is a free log retrieval operation binding the contract event 0xa8ac7f999d45aadfcaabf4c5a117e8e38c61d55ba02b3957c5462cd4928285e1.
//
// Solidity: event ExpressionRuleViolated(address indexed project, bytes4 indexed funcSig, uint8 ruleIndex, int256 lhs, int256 threshold)
func (_ParamCheckModule *ParamCheckModuleFilterer) FilterExpressionRuleViolated(opts *bind.FilterOpts, project []common.Address, funcSig [][4]byte) (*ParamCheckModuleExpressionRuleViolatedIterator, error) {

	var projectRule []interface{}
	for _, projectItem := range project {
		projectRule = append(projectRule, projectItem)
	}
	var funcSigRule []interface{}
	for _, funcSigItem := range funcSig {
		funcSigRule = append(funcSigRule, funcSigItem)
	}

	logs, sub, err := _ParamCheckModule.contract.FilterLogs(opts, "ExpressionRuleViolated", projectRule, funcSigRule)
	if err != nil {
		return nil, err
	}
	return &ParamCheckModuleExpressionRuleViolatedIterator{contract: _ParamCheckModule.contract, event: "ExpressionRuleViolated", logs: logs, sub: sub}, nil
}

// WatchExpressionRuleViolated is a free log subscription operation binding the contract event 0xa8ac7f999d45aadfcaabf4c5a117e8e38c61d55ba02b3957c5462cd4928285e1.
//
// Solidity: event ExpressionRuleViolated(address indexed project, bytes4 indexed funcSig, uint8 ruleIndex, int256 lhs, int256 threshold)
func (_ParamCheckModule *ParamCheckModuleFilterer) WatchExpressionRuleViolated(opts *bind.WatchOpts, sink chan<- *ParamCheckModuleExpressionRuleViolated, project []common.Address, funcSig [][4]byte) (event.Subscription, error) {

	var projectRule []interface{}
	for _, projectItem := range project {
		projectRule = append(projectRule, projectItem)
	}
	var funcSigRule []interface{}
	for _, funcSigItem := range funcSig {
		funcSigRule = append(funcSigRule, funcSigItem)
	}

	logs, sub, err := _ParamCheckModule.contract.WatchLogs(opts, "ExpressionRuleViolated", projectRule, funcSigRule)
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(ParamCheckModuleExpressionRuleViolated)
				if err := _ParamCheckModule.contract.UnpackLog(event, "ExpressionRuleViolated", log); err != nil {
					return err
				}
				event.Raw = log

				select {
				case sink <- event:
				case err := <-sub.Err():
					return err
				case <-quit:
					return nil
				}
			case err := <-sub.Err():
				return err
			case <-quit:
				return nil
			}
		}
	}), nil
}

// ParseExpressionRuleViolated is a log parse operation binding the contract event 0xa8ac7f999d45aadfcaabf4c5a117e8e38c61d55ba02b3957c5462cd4928285e1.
//
// Solidity: event ExpressionRuleViolated(address indexed project, bytes4 indexed funcSig, uint8 ruleIndex, int256 lhs, int256 threshold)
func (_ParamCheckModule *ParamCheckModuleFilterer) ParseExpressionRuleViolated(log types.Log) (*ParamCheckModuleExpressionRuleViolated, error) {
	event := new(ParamCheckModuleExpressionRuleViolated)
	if err := _ParamCheckModule.contract.UnpackLog(event, "ExpressionRuleViolated", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}

// ParamCheckModuleExpressionRuleViolated0Iterator is returned from FilterExpressionRuleViolated0 and is used to iterate over the raw logs and unpacked data for ExpressionRuleViolated0 events raised by the ParamCheckModule contract.
type ParamCheckModuleExpressionRuleViolated0Iterator struct {
	Event *ParamCheckModuleExpressionRuleViolated0 // Event containing the contract specifics and raw log

	contract *bind.BoundContract // Generic contract to use for unpacking event data
	event    string              // Event name to use for unpacking event data

	logs chan types.Log        // Log channel receiving the found contract events
	sub  ethereum.Subscription // Subscription for errors, completion and termination
	done bool                  // Whether the subscription completed delivering logs
	fail error                 // Occurred error to stop iteration
}

// Next advances the iterator to the subsequent event, returning whether there
// are any more events found. In case of a retrieval or parsing error, false is
// returned and Error() can be queried for the exact failure.
func (it *ParamCheckModuleExpressionRuleViolated0Iterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(ParamCheckModuleExpressionRuleViolated0)
			if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
				it.fail = err
				return false
			}
			it.Event.Raw = log
			return true

		default:
			return false
		}
	}
	// Iterator still in progress, wait for either a data or an error event
	select {
	case log := <-it.logs:
		it.Event = new(ParamCheckModuleExpressionRuleViolated0)
		if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
			it.fail = err
			return false
		}
		it.Event.Raw = log
		return true

	case err := <-it.sub.Err():
		it.done = true
		it.fail = err
		return it.Next()
	}
}

// Error returns any retrieval or parsing error occurred during filtering.
func (it *ParamCheckModuleExpressionRuleViolated0Iterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *ParamCheckModuleExpressionRuleViolated0Iterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// ParamCheckModuleExpressionRuleViolated0 represents a ExpressionRuleViolated0 event raised by the ParamCheckModule contract.
type ParamCheckModuleExpressionRuleViolated0 struct {
	Project   common.Address
	FuncSig   [4]byte
	RuleIndex uint8
	Lhs       *big.Int
	Threshold *big.Int
	Raw       types.Log // Blockchain specific contextual infos
}

// FilterExpressionRuleViolated0 is a free log retrieval operation binding the contract event 0xa8ac7f999d45aadfcaabf4c5a117e8e38c61d55ba02b3957c5462cd4928285e1.
//
// Solidity: event ExpressionRuleViolated(address indexed project, bytes4 indexed funcSig, uint8 ruleIndex, int256 lhs, int256 threshold)
func (_ParamCheckModule *ParamCheckModuleFilterer) FilterExpressionRuleViolated0(opts *bind.FilterOpts, project []common.Address, funcSig [][4]byte) (*ParamCheckModuleExpressionRuleViolated0Iterator, error) {

	var projectRule []interface{}
	for _, projectItem := range project {
		projectRule = append(projectRule, projectItem)
	}
	var funcSigRule []interface{}
	for _, funcSigItem := range funcSig {
		funcSigRule = append(funcSigRule, funcSigItem)
	}

	logs, sub, err := _ParamCheckModule.contract.FilterLogs(opts, "ExpressionRuleViolated0", projectRule, funcSigRule)
	if err != nil {
		return nil, err
	}
	return &ParamCheckModuleExpressionRuleViolated0Iterator{contract: _ParamCheckModule.contract, event: "ExpressionRuleViolated0", logs: logs, sub: sub}, nil
}

// WatchExpressionRuleViolated0 is a free log subscription operation binding the contract event 0xa8ac7f999d45aadfcaabf4c5a117e8e38c61d55ba02b3957c5462cd4928285e1.
//
// Solidity: event ExpressionRuleViolated(address indexed project, bytes4 indexed funcSig, uint8 ruleIndex, int256 lhs, int256 threshold)
func (_ParamCheckModule *ParamCheckModuleFilterer) WatchExpressionRuleViolated0(opts *bind.WatchOpts, sink chan<- *ParamCheckModuleExpressionRuleViolated0, project []common.Address, funcSig [][4]byte) (event.Subscription, error) {

	var projectRule []interface{}
	for _, projectItem := range project {
		projectRule = append(projectRule, projectItem)
	}
	var funcSigRule []interface{}
	for _, funcSigItem := range funcSig {
		funcSigRule = append(funcSigRule, funcSigItem)
	}

	logs, sub, err := _ParamCheckModule.contract.WatchLogs(opts, "ExpressionRuleViolated0", projectRule, funcSigRule)
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(ParamCheckModuleExpressionRuleViolated0)
				if err := _ParamCheckModule.contract.UnpackLog(event, "ExpressionRuleViolated0", log); err != nil {
					return err
				}
				event.Raw = log

				select {
				case sink <- event:
				case err := <-sub.Err():
					return err
				case <-quit:
					return nil
				}
			case err := <-sub.Err():
				return err
			case <-quit:
				return nil
			}
		}
	}), nil
}

// ParseExpressionRuleViolated0 is a log parse operation binding the contract event 0xa8ac7f999d45aadfcaabf4c5a117e8e38c61d55ba02b3957c5462cd4928285e1.
//
// Solidity: event ExpressionRuleViolated(address indexed project, bytes4 indexed funcSig, uint8 ruleIndex, int256 lhs, int256 threshold)
func (_ParamCheckModule *ParamCheckModuleFilterer) ParseExpressionRuleViolated0(log types.Log) (*ParamCheckModuleExpressionRuleViolated0, error) {
	event := new(ParamCheckModuleExpressionRuleViolated0)
	if err := _ParamCheckModule.contract.UnpackLog(event, "ExpressionRuleViolated0", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}

// ParamCheckModuleExpressionRulesAppendedIterator is returned from FilterExpressionRulesAppended and is used to iterate over the raw logs and unpacked data for ExpressionRulesAppended events raised by the ParamCheckModule contract.
type ParamCheckModuleExpressionRulesAppendedIterator struct {
	Event *ParamCheckModuleExpressionRulesAppended // Event containing the contract specifics and raw log

	contract *bind.BoundContract // Generic contract to use for unpacking event data
	event    string              // Event name to use for unpacking event data

	logs chan types.Log        // Log channel receiving the found contract events
	sub  ethereum.Subscription // Subscription for errors, completion and termination
	done bool                  // Whether the subscription completed delivering logs
	fail error                 // Occurred error to stop iteration
}

// Next advances the iterator to the subsequent event, returning whether there
// are any more events found. In case of a retrieval or parsing error, false is
// returned and Error() can be queried for the exact failure.
func (it *ParamCheckModuleExpressionRulesAppendedIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(ParamCheckModuleExpressionRulesAppended)
			if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
				it.fail = err
				return false
			}
			it.Event.Raw = log
			return true

		default:
			return false
		}
	}
	// Iterator still in progress, wait for either a data or an error event
	select {
	case log := <-it.logs:
		it.Event = new(ParamCheckModuleExpressionRulesAppended)
		if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
			it.fail = err
			return false
		}
		it.Event.Raw = log
		return true

	case err := <-it.sub.Err():
		it.done = true
		it.fail = err
		return it.Next()
	}
}

// Error returns any retrieval or parsing error occurred during filtering.
func (it *ParamCheckModuleExpressionRulesAppendedIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *ParamCheckModuleExpressionRulesAppendedIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// ParamCheckModuleExpressionRulesAppended represents a ExpressionRulesAppended event raised by the ParamCheckModule contract.
type ParamCheckModuleExpressionRulesAppended struct {
	Project    common.Address
	FuncSig    [4]byte
	AddedCount *big.Int
	TotalCount *big.Int
	Raw        types.Log // Blockchain specific contextual infos
}

// FilterExpressionRulesAppended is a free log retrieval operation binding the contract event 0x7d568109f676ac8e0d1c2b22dd6783648acc78f9a9641fa15e8807eca9f4fb7f.
//
// Solidity: event ExpressionRulesAppended(address indexed project, bytes4 indexed funcSig, uint256 addedCount, uint256 totalCount)
func (_ParamCheckModule *ParamCheckModuleFilterer) FilterExpressionRulesAppended(opts *bind.FilterOpts, project []common.Address, funcSig [][4]byte) (*ParamCheckModuleExpressionRulesAppendedIterator, error) {

	var projectRule []interface{}
	for _, projectItem := range project {
		projectRule = append(projectRule, projectItem)
	}
	var funcSigRule []interface{}
	for _, funcSigItem := range funcSig {
		funcSigRule = append(funcSigRule, funcSigItem)
	}

	logs, sub, err := _ParamCheckModule.contract.FilterLogs(opts, "ExpressionRulesAppended", projectRule, funcSigRule)
	if err != nil {
		return nil, err
	}
	return &ParamCheckModuleExpressionRulesAppendedIterator{contract: _ParamCheckModule.contract, event: "ExpressionRulesAppended", logs: logs, sub: sub}, nil
}

// WatchExpressionRulesAppended is a free log subscription operation binding the contract event 0x7d568109f676ac8e0d1c2b22dd6783648acc78f9a9641fa15e8807eca9f4fb7f.
//
// Solidity: event ExpressionRulesAppended(address indexed project, bytes4 indexed funcSig, uint256 addedCount, uint256 totalCount)
func (_ParamCheckModule *ParamCheckModuleFilterer) WatchExpressionRulesAppended(opts *bind.WatchOpts, sink chan<- *ParamCheckModuleExpressionRulesAppended, project []common.Address, funcSig [][4]byte) (event.Subscription, error) {

	var projectRule []interface{}
	for _, projectItem := range project {
		projectRule = append(projectRule, projectItem)
	}
	var funcSigRule []interface{}
	for _, funcSigItem := range funcSig {
		funcSigRule = append(funcSigRule, funcSigItem)
	}

	logs, sub, err := _ParamCheckModule.contract.WatchLogs(opts, "ExpressionRulesAppended", projectRule, funcSigRule)
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(ParamCheckModuleExpressionRulesAppended)
				if err := _ParamCheckModule.contract.UnpackLog(event, "ExpressionRulesAppended", log); err != nil {
					return err
				}
				event.Raw = log

				select {
				case sink <- event:
				case err := <-sub.Err():
					return err
				case <-quit:
					return nil
				}
			case err := <-sub.Err():
				return err
			case <-quit:
				return nil
			}
		}
	}), nil
}

// ParseExpressionRulesAppended is a log parse operation binding the contract event 0x7d568109f676ac8e0d1c2b22dd6783648acc78f9a9641fa15e8807eca9f4fb7f.
//
// Solidity: event ExpressionRulesAppended(address indexed project, bytes4 indexed funcSig, uint256 addedCount, uint256 totalCount)
func (_ParamCheckModule *ParamCheckModuleFilterer) ParseExpressionRulesAppended(log types.Log) (*ParamCheckModuleExpressionRulesAppended, error) {
	event := new(ParamCheckModuleExpressionRulesAppended)
	if err := _ParamCheckModule.contract.UnpackLog(event, "ExpressionRulesAppended", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}

// ParamCheckModuleExpressionRulesReplacedIterator is returned from FilterExpressionRulesReplaced and is used to iterate over the raw logs and unpacked data for ExpressionRulesReplaced events raised by the ParamCheckModule contract.
type ParamCheckModuleExpressionRulesReplacedIterator struct {
	Event *ParamCheckModuleExpressionRulesReplaced // Event containing the contract specifics and raw log

	contract *bind.BoundContract // Generic contract to use for unpacking event data
	event    string              // Event name to use for unpacking event data

	logs chan types.Log        // Log channel receiving the found contract events
	sub  ethereum.Subscription // Subscription for errors, completion and termination
	done bool                  // Whether the subscription completed delivering logs
	fail error                 // Occurred error to stop iteration
}

// Next advances the iterator to the subsequent event, returning whether there
// are any more events found. In case of a retrieval or parsing error, false is
// returned and Error() can be queried for the exact failure.
func (it *ParamCheckModuleExpressionRulesReplacedIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(ParamCheckModuleExpressionRulesReplaced)
			if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
				it.fail = err
				return false
			}
			it.Event.Raw = log
			return true

		default:
			return false
		}
	}
	// Iterator still in progress, wait for either a data or an error event
	select {
	case log := <-it.logs:
		it.Event = new(ParamCheckModuleExpressionRulesReplaced)
		if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
			it.fail = err
			return false
		}
		it.Event.Raw = log
		return true

	case err := <-it.sub.Err():
		it.done = true
		it.fail = err
		return it.Next()
	}
}

// Error returns any retrieval or parsing error occurred during filtering.
func (it *ParamCheckModuleExpressionRulesReplacedIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *ParamCheckModuleExpressionRulesReplacedIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// ParamCheckModuleExpressionRulesReplaced represents a ExpressionRulesReplaced event raised by the ParamCheckModule contract.
type ParamCheckModuleExpressionRulesReplaced struct {
	Project      common.Address
	FuncSig      [4]byte
	DeletedCount *big.Int
	NewCount     *big.Int
	Raw          types.Log // Blockchain specific contextual infos
}

// FilterExpressionRulesReplaced is a free log retrieval operation binding the contract event 0x19508d029151c80472e99fd6caff0e3641a6b5239bbbee4a2a413e15b3e86aff.
//
// Solidity: event ExpressionRulesReplaced(address indexed project, bytes4 indexed funcSig, uint256 deletedCount, uint256 newCount)
func (_ParamCheckModule *ParamCheckModuleFilterer) FilterExpressionRulesReplaced(opts *bind.FilterOpts, project []common.Address, funcSig [][4]byte) (*ParamCheckModuleExpressionRulesReplacedIterator, error) {

	var projectRule []interface{}
	for _, projectItem := range project {
		projectRule = append(projectRule, projectItem)
	}
	var funcSigRule []interface{}
	for _, funcSigItem := range funcSig {
		funcSigRule = append(funcSigRule, funcSigItem)
	}

	logs, sub, err := _ParamCheckModule.contract.FilterLogs(opts, "ExpressionRulesReplaced", projectRule, funcSigRule)
	if err != nil {
		return nil, err
	}
	return &ParamCheckModuleExpressionRulesReplacedIterator{contract: _ParamCheckModule.contract, event: "ExpressionRulesReplaced", logs: logs, sub: sub}, nil
}

// WatchExpressionRulesReplaced is a free log subscription operation binding the contract event 0x19508d029151c80472e99fd6caff0e3641a6b5239bbbee4a2a413e15b3e86aff.
//
// Solidity: event ExpressionRulesReplaced(address indexed project, bytes4 indexed funcSig, uint256 deletedCount, uint256 newCount)
func (_ParamCheckModule *ParamCheckModuleFilterer) WatchExpressionRulesReplaced(opts *bind.WatchOpts, sink chan<- *ParamCheckModuleExpressionRulesReplaced, project []common.Address, funcSig [][4]byte) (event.Subscription, error) {

	var projectRule []interface{}
	for _, projectItem := range project {
		projectRule = append(projectRule, projectItem)
	}
	var funcSigRule []interface{}
	for _, funcSigItem := range funcSig {
		funcSigRule = append(funcSigRule, funcSigItem)
	}

	logs, sub, err := _ParamCheckModule.contract.WatchLogs(opts, "ExpressionRulesReplaced", projectRule, funcSigRule)
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(ParamCheckModuleExpressionRulesReplaced)
				if err := _ParamCheckModule.contract.UnpackLog(event, "ExpressionRulesReplaced", log); err != nil {
					return err
				}
				event.Raw = log

				select {
				case sink <- event:
				case err := <-sub.Err():
					return err
				case <-quit:
					return nil
				}
			case err := <-sub.Err():
				return err
			case <-quit:
				return nil
			}
		}
	}), nil
}

// ParseExpressionRulesReplaced is a log parse operation binding the contract event 0x19508d029151c80472e99fd6caff0e3641a6b5239bbbee4a2a413e15b3e86aff.
//
// Solidity: event ExpressionRulesReplaced(address indexed project, bytes4 indexed funcSig, uint256 deletedCount, uint256 newCount)
func (_ParamCheckModule *ParamCheckModuleFilterer) ParseExpressionRulesReplaced(log types.Log) (*ParamCheckModuleExpressionRulesReplaced, error) {
	event := new(ParamCheckModuleExpressionRulesReplaced)
	if err := _ParamCheckModule.contract.UnpackLog(event, "ExpressionRulesReplaced", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}

// ParamCheckModuleParameterBlockedIterator is returned from FilterParameterBlocked and is used to iterate over the raw logs and unpacked data for ParameterBlocked events raised by the ParamCheckModule contract.
type ParamCheckModuleParameterBlockedIterator struct {
	Event *ParamCheckModuleParameterBlocked // Event containing the contract specifics and raw log

	contract *bind.BoundContract // Generic contract to use for unpacking event data
	event    string              // Event name to use for unpacking event data

	logs chan types.Log        // Log channel receiving the found contract events
	sub  ethereum.Subscription // Subscription for errors, completion and termination
	done bool                  // Whether the subscription completed delivering logs
	fail error                 // Occurred error to stop iteration
}

// Next advances the iterator to the subsequent event, returning whether there
// are any more events found. In case of a retrieval or parsing error, false is
// returned and Error() can be queried for the exact failure.
func (it *ParamCheckModuleParameterBlockedIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(ParamCheckModuleParameterBlocked)
			if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
				it.fail = err
				return false
			}
			it.Event.Raw = log
			return true

		default:
			return false
		}
	}
	// Iterator still in progress, wait for either a data or an error event
	select {
	case log := <-it.logs:
		it.Event = new(ParamCheckModuleParameterBlocked)
		if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
			it.fail = err
			return false
		}
		it.Event.Raw = log
		return true

	case err := <-it.sub.Err():
		it.done = true
		it.fail = err
		return it.Next()
	}
}

// Error returns any retrieval or parsing error occurred during filtering.
func (it *ParamCheckModuleParameterBlockedIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *ParamCheckModuleParameterBlockedIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// ParamCheckModuleParameterBlocked represents a ParameterBlocked event raised by the ParamCheckModule contract.
type ParamCheckModuleParameterBlocked struct {
	Project    common.Address
	FuncSig    [4]byte
	ParamIndex uint8
	ParamValue [32]byte
	Reason     string
	Raw        types.Log // Blockchain specific contextual infos
}

// FilterParameterBlocked is a free log retrieval operation binding the contract event 0x5354e2e276fd28edd80ddbf474db78efc52a94fb124c3ba2e60201a38a7d561f.
//
// Solidity: event ParameterBlocked(address indexed project, bytes4 indexed funcSig, uint8 paramIndex, bytes32 paramValue, string reason)
func (_ParamCheckModule *ParamCheckModuleFilterer) FilterParameterBlocked(opts *bind.FilterOpts, project []common.Address, funcSig [][4]byte) (*ParamCheckModuleParameterBlockedIterator, error) {

	var projectRule []interface{}
	for _, projectItem := range project {
		projectRule = append(projectRule, projectItem)
	}
	var funcSigRule []interface{}
	for _, funcSigItem := range funcSig {
		funcSigRule = append(funcSigRule, funcSigItem)
	}

	logs, sub, err := _ParamCheckModule.contract.FilterLogs(opts, "ParameterBlocked", projectRule, funcSigRule)
	if err != nil {
		return nil, err
	}
	return &ParamCheckModuleParameterBlockedIterator{contract: _ParamCheckModule.contract, event: "ParameterBlocked", logs: logs, sub: sub}, nil
}

// WatchParameterBlocked is a free log subscription operation binding the contract event 0x5354e2e276fd28edd80ddbf474db78efc52a94fb124c3ba2e60201a38a7d561f.
//
// Solidity: event ParameterBlocked(address indexed project, bytes4 indexed funcSig, uint8 paramIndex, bytes32 paramValue, string reason)
func (_ParamCheckModule *ParamCheckModuleFilterer) WatchParameterBlocked(opts *bind.WatchOpts, sink chan<- *ParamCheckModuleParameterBlocked, project []common.Address, funcSig [][4]byte) (event.Subscription, error) {

	var projectRule []interface{}
	for _, projectItem := range project {
		projectRule = append(projectRule, projectItem)
	}
	var funcSigRule []interface{}
	for _, funcSigItem := range funcSig {
		funcSigRule = append(funcSigRule, funcSigItem)
	}

	logs, sub, err := _ParamCheckModule.contract.WatchLogs(opts, "ParameterBlocked", projectRule, funcSigRule)
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(ParamCheckModuleParameterBlocked)
				if err := _ParamCheckModule.contract.UnpackLog(event, "ParameterBlocked", log); err != nil {
					return err
				}
				event.Raw = log

				select {
				case sink <- event:
				case err := <-sub.Err():
					return err
				case <-quit:
					return nil
				}
			case err := <-sub.Err():
				return err
			case <-quit:
				return nil
			}
		}
	}), nil
}

// ParseParameterBlocked is a log parse operation binding the contract event 0x5354e2e276fd28edd80ddbf474db78efc52a94fb124c3ba2e60201a38a7d561f.
//
// Solidity: event ParameterBlocked(address indexed project, bytes4 indexed funcSig, uint8 paramIndex, bytes32 paramValue, string reason)
func (_ParamCheckModule *ParamCheckModuleFilterer) ParseParameterBlocked(log types.Log) (*ParamCheckModuleParameterBlocked, error) {
	event := new(ParamCheckModuleParameterBlocked)
	if err := _ParamCheckModule.contract.UnpackLog(event, "ParameterBlocked", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}

// ParamCheckModuleRuleConfiguredIterator is returned from FilterRuleConfigured and is used to iterate over the raw logs and unpacked data for RuleConfigured events raised by the ParamCheckModule contract.
type ParamCheckModuleRuleConfiguredIterator struct {
	Event *ParamCheckModuleRuleConfigured // Event containing the contract specifics and raw log

	contract *bind.BoundContract // Generic contract to use for unpacking event data
	event    string              // Event name to use for unpacking event data

	logs chan types.Log        // Log channel receiving the found contract events
	sub  ethereum.Subscription // Subscription for errors, completion and termination
	done bool                  // Whether the subscription completed delivering logs
	fail error                 // Occurred error to stop iteration
}

// Next advances the iterator to the subsequent event, returning whether there
// are any more events found. In case of a retrieval or parsing error, false is
// returned and Error() can be queried for the exact failure.
func (it *ParamCheckModuleRuleConfiguredIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(ParamCheckModuleRuleConfigured)
			if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
				it.fail = err
				return false
			}
			it.Event.Raw = log
			return true

		default:
			return false
		}
	}
	// Iterator still in progress, wait for either a data or an error event
	select {
	case log := <-it.logs:
		it.Event = new(ParamCheckModuleRuleConfigured)
		if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
			it.fail = err
			return false
		}
		it.Event.Raw = log
		return true

	case err := <-it.sub.Err():
		it.done = true
		it.fail = err
		return it.Next()
	}
}

// Error returns any retrieval or parsing error occurred during filtering.
func (it *ParamCheckModuleRuleConfiguredIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *ParamCheckModuleRuleConfiguredIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// ParamCheckModuleRuleConfigured represents a RuleConfigured event raised by the ParamCheckModule contract.
type ParamCheckModuleRuleConfigured struct {
	Project   common.Address
	FuncSig   [4]byte
	RuleIndex uint8
	RuleType  uint8
	Raw       types.Log // Blockchain specific contextual infos
}

// FilterRuleConfigured is a free log retrieval operation binding the contract event 0x513af0e6fbec5404cd04d331bc839aa58c97dba680899feb9efa781cbc8e96b6.
//
// Solidity: event RuleConfigured(address indexed project, bytes4 indexed funcSig, uint8 ruleIndex, uint8 ruleType)
func (_ParamCheckModule *ParamCheckModuleFilterer) FilterRuleConfigured(opts *bind.FilterOpts, project []common.Address, funcSig [][4]byte) (*ParamCheckModuleRuleConfiguredIterator, error) {

	var projectRule []interface{}
	for _, projectItem := range project {
		projectRule = append(projectRule, projectItem)
	}
	var funcSigRule []interface{}
	for _, funcSigItem := range funcSig {
		funcSigRule = append(funcSigRule, funcSigItem)
	}

	logs, sub, err := _ParamCheckModule.contract.FilterLogs(opts, "RuleConfigured", projectRule, funcSigRule)
	if err != nil {
		return nil, err
	}
	return &ParamCheckModuleRuleConfiguredIterator{contract: _ParamCheckModule.contract, event: "RuleConfigured", logs: logs, sub: sub}, nil
}

// WatchRuleConfigured is a free log subscription operation binding the contract event 0x513af0e6fbec5404cd04d331bc839aa58c97dba680899feb9efa781cbc8e96b6.
//
// Solidity: event RuleConfigured(address indexed project, bytes4 indexed funcSig, uint8 ruleIndex, uint8 ruleType)
func (_ParamCheckModule *ParamCheckModuleFilterer) WatchRuleConfigured(opts *bind.WatchOpts, sink chan<- *ParamCheckModuleRuleConfigured, project []common.Address, funcSig [][4]byte) (event.Subscription, error) {

	var projectRule []interface{}
	for _, projectItem := range project {
		projectRule = append(projectRule, projectItem)
	}
	var funcSigRule []interface{}
	for _, funcSigItem := range funcSig {
		funcSigRule = append(funcSigRule, funcSigItem)
	}

	logs, sub, err := _ParamCheckModule.contract.WatchLogs(opts, "RuleConfigured", projectRule, funcSigRule)
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(ParamCheckModuleRuleConfigured)
				if err := _ParamCheckModule.contract.UnpackLog(event, "RuleConfigured", log); err != nil {
					return err
				}
				event.Raw = log

				select {
				case sink <- event:
				case err := <-sub.Err():
					return err
				case <-quit:
					return nil
				}
			case err := <-sub.Err():
				return err
			case <-quit:
				return nil
			}
		}
	}), nil
}

// ParseRuleConfigured is a log parse operation binding the contract event 0x513af0e6fbec5404cd04d331bc839aa58c97dba680899feb9efa781cbc8e96b6.
//
// Solidity: event RuleConfigured(address indexed project, bytes4 indexed funcSig, uint8 ruleIndex, uint8 ruleType)
func (_ParamCheckModule *ParamCheckModuleFilterer) ParseRuleConfigured(log types.Log) (*ParamCheckModuleRuleConfigured, error) {
	event := new(ParamCheckModuleRuleConfigured)
	if err := _ParamCheckModule.contract.UnpackLog(event, "RuleConfigured", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}

// ParamCheckModuleRuleUpdatedIterator is returned from FilterRuleUpdated and is used to iterate over the raw logs and unpacked data for RuleUpdated events raised by the ParamCheckModule contract.
type ParamCheckModuleRuleUpdatedIterator struct {
	Event *ParamCheckModuleRuleUpdated // Event containing the contract specifics and raw log

	contract *bind.BoundContract // Generic contract to use for unpacking event data
	event    string              // Event name to use for unpacking event data

	logs chan types.Log        // Log channel receiving the found contract events
	sub  ethereum.Subscription // Subscription for errors, completion and termination
	done bool                  // Whether the subscription completed delivering logs
	fail error                 // Occurred error to stop iteration
}

// Next advances the iterator to the subsequent event, returning whether there
// are any more events found. In case of a retrieval or parsing error, false is
// returned and Error() can be queried for the exact failure.
func (it *ParamCheckModuleRuleUpdatedIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(ParamCheckModuleRuleUpdated)
			if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
				it.fail = err
				return false
			}
			it.Event.Raw = log
			return true

		default:
			return false
		}
	}
	// Iterator still in progress, wait for either a data or an error event
	select {
	case log := <-it.logs:
		it.Event = new(ParamCheckModuleRuleUpdated)
		if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
			it.fail = err
			return false
		}
		it.Event.Raw = log
		return true

	case err := <-it.sub.Err():
		it.done = true
		it.fail = err
		return it.Next()
	}
}

// Error returns any retrieval or parsing error occurred during filtering.
func (it *ParamCheckModuleRuleUpdatedIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *ParamCheckModuleRuleUpdatedIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// ParamCheckModuleRuleUpdated represents a RuleUpdated event raised by the ParamCheckModule contract.
type ParamCheckModuleRuleUpdated struct {
	Project   common.Address
	FuncSig   [4]byte
	Updater   common.Address
	Timestamp *big.Int
	Raw       types.Log // Blockchain specific contextual infos
}

// FilterRuleUpdated is a free log retrieval operation binding the contract event 0x1da87949529db79350976c6ce8c7055dc948adbc59fef1fe017774ac5af7c5ae.
//
// Solidity: event RuleUpdated(address indexed project, bytes4 indexed funcSig, address updater, uint256 timestamp)
func (_ParamCheckModule *ParamCheckModuleFilterer) FilterRuleUpdated(opts *bind.FilterOpts, project []common.Address, funcSig [][4]byte) (*ParamCheckModuleRuleUpdatedIterator, error) {

	var projectRule []interface{}
	for _, projectItem := range project {
		projectRule = append(projectRule, projectItem)
	}
	var funcSigRule []interface{}
	for _, funcSigItem := range funcSig {
		funcSigRule = append(funcSigRule, funcSigItem)
	}

	logs, sub, err := _ParamCheckModule.contract.FilterLogs(opts, "RuleUpdated", projectRule, funcSigRule)
	if err != nil {
		return nil, err
	}
	return &ParamCheckModuleRuleUpdatedIterator{contract: _ParamCheckModule.contract, event: "RuleUpdated", logs: logs, sub: sub}, nil
}

// WatchRuleUpdated is a free log subscription operation binding the contract event 0x1da87949529db79350976c6ce8c7055dc948adbc59fef1fe017774ac5af7c5ae.
//
// Solidity: event RuleUpdated(address indexed project, bytes4 indexed funcSig, address updater, uint256 timestamp)
func (_ParamCheckModule *ParamCheckModuleFilterer) WatchRuleUpdated(opts *bind.WatchOpts, sink chan<- *ParamCheckModuleRuleUpdated, project []common.Address, funcSig [][4]byte) (event.Subscription, error) {

	var projectRule []interface{}
	for _, projectItem := range project {
		projectRule = append(projectRule, projectItem)
	}
	var funcSigRule []interface{}
	for _, funcSigItem := range funcSig {
		funcSigRule = append(funcSigRule, funcSigItem)
	}

	logs, sub, err := _ParamCheckModule.contract.WatchLogs(opts, "RuleUpdated", projectRule, funcSigRule)
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(ParamCheckModuleRuleUpdated)
				if err := _ParamCheckModule.contract.UnpackLog(event, "RuleUpdated", log); err != nil {
					return err
				}
				event.Raw = log

				select {
				case sink <- event:
				case err := <-sub.Err():
					return err
				case <-quit:
					return nil
				}
			case err := <-sub.Err():
				return err
			case <-quit:
				return nil
			}
		}
	}), nil
}

// ParseRuleUpdated is a log parse operation binding the contract event 0x1da87949529db79350976c6ce8c7055dc948adbc59fef1fe017774ac5af7c5ae.
//
// Solidity: event RuleUpdated(address indexed project, bytes4 indexed funcSig, address updater, uint256 timestamp)
func (_ParamCheckModule *ParamCheckModuleFilterer) ParseRuleUpdated(log types.Log) (*ParamCheckModuleRuleUpdated, error) {
	event := new(ParamCheckModuleRuleUpdated)
	if err := _ParamCheckModule.contract.UnpackLog(event, "RuleUpdated", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}
