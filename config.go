package main

import (
	"github.com/goccy/go-json"
	"os"
)

type AutoLoadRawMessage json.RawMessage

func (j *AutoLoadRawMessage) UnmarshalJSON(data []byte) error {
	var path string
	err := json.Unmarshal(data, &path)
	if err == nil {
		f, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		data = f
	}
	*j = data
	return nil
}

type XrayConfig struct {
	AssetPath string             `json:"AssetPath"`
	Log       AutoLoadRawMessage `json:"Log"`
	Dns       AutoLoadRawMessage `json:"Dns"`
	Inbound   AutoLoadRawMessage `json:"Inbound"`
	Outbound  AutoLoadRawMessage `json:"Outbound"`
	Route     AutoLoadRawMessage `json:"Route"`
	Policy    AutoLoadRawMessage `json:"Policy"`
}
