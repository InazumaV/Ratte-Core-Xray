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
		f, err := os.Open(path)
		if err != nil {
			return err
		}
		defer f.Close()
		return json.NewDecoder(f).Decode(j)
	} else {
		return json.Unmarshal(data, &j)
	}
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
