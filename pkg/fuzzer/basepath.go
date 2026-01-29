package fuzzer

import (
	"os"
	"path/filepath"
)

// resolveBasePath determines the repo root used to locate constraint_rules_v2.json
// and other artifacts. It prefers explicit env vars to avoid cwd-dependent drift.
func resolveBasePath() string {
	// Allow explicit override when monitor is launched from a different cwd.
	for _, env := range []string{"FIREWALL_PROJECT_ROOT", "PROJECT_ROOT", "FW_PROJECT_ROOT"} {
		if v := os.Getenv(env); v != "" {
			return v
		}
	}

	// Fallback to relative paths (monitor usually runs under autopath/).
	basePath := ".."
	if _, err := os.Stat(filepath.Join(basePath, "DeFiHackLabs")); err != nil {
		basePath = "."
	}
	return basePath
}
