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

const (
	defLog = `{
	"Level": "error"
}
`
	defDns      = ``
	defInbound  = ``
	defOutbound = `
[
	{
		"protocol": "freedom",
		"tag": "default_direct"
	},
	{
		"protocol": "blackhole",
		"tag": "block"
	}
]
`
	defRoute  = ``
	defPolicy = `
{
	"handshake": 4,
	"connIdle": 300,
	"uplinkOnly": 2,
	"downlinkOnly": 5,
	"statsUserUplink": false,
	"statsUserDownlink": false,
	"bufferSize": 4
}
`
)

func NewXrayConfig() *XrayConfig {
	return &XrayConfig{
		AssetPath: "",
		Log:       AutoLoadRawMessage(defLog),
		Dns:       AutoLoadRawMessage(defDns),
		Inbound:   AutoLoadRawMessage(defInbound),
		Outbound:  AutoLoadRawMessage(defOutbound),
		Route:     AutoLoadRawMessage(defRoute),
		Policy:    AutoLoadRawMessage(defPolicy),
	}
}
