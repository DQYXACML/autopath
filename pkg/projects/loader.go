package projects

import (
	"encoding/json"
	"io/ioutil"
)

// LoadConfig 从磁盘加载项目配置
func LoadConfig(path string) (*ProjectConfig, error) {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var config ProjectConfig
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, err
	}

	return &config, nil
}
