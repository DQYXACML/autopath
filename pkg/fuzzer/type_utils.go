package fuzzer

import (
	"strconv"
	"strings"
)

// parseArrayType 解析数组类型，返回元素类型、固定长度（-1表示动态）及是否为数组
func parseArrayType(typeStr string) (string, int, bool) {
	if !strings.Contains(typeStr, "[") || !strings.HasSuffix(typeStr, "]") {
		return "", 0, false
	}
	lastIdx := strings.LastIndex(typeStr, "[")
	if lastIdx < 0 || lastIdx >= len(typeStr)-1 {
		return "", 0, false
	}
	elemType := typeStr[:lastIdx]
	sizeStr := typeStr[lastIdx+1 : len(typeStr)-1]
	if sizeStr == "" {
		return elemType, -1, true
	}
	size, err := strconv.Atoi(sizeStr)
	if err != nil {
		return elemType, -1, true
	}
	return elemType, size, true
}

func isArrayType(typeStr string) bool {
	_, _, ok := parseArrayType(typeStr)
	return ok
}

func stripArrayDimensions(typeStr string) string {
	for strings.HasSuffix(typeStr, "]") {
		idx := strings.LastIndex(typeStr, "[")
		if idx == -1 {
			break
		}
		typeStr = typeStr[:idx]
	}
	return typeStr
}

func arrayFixedLength(typeStr string) int {
	_, size, ok := parseArrayType(typeStr)
	if !ok || size < 0 {
		return 0
	}
	return size
}
