package main

import (
	"errors"
	"fmt"
	"github.com/InazumaV/Ratte-Interface/core"
	"github.com/goccy/go-json"
	coreConf "github.com/xtls/xray-core/infra/conf"
)

func getV2rayInboundConfig(p *core.NodeInfo, inbound *coreConf.InboundDetourConfig) error {
	setsNUll := false
	if inbound.Settings == nil {
		setsNUll = true
	} else {
		if len(*inbound.Settings) == 0 {
			setsNUll = true
		}
	}
	netSets := json.RawMessage{}
	var netProtocol string
	// Set vmess
	switch p.Type {
	case "vless":
		inbound.Protocol = "vless"
		if setsNUll {
			var err error
			s, err := json.Marshal(&coreConf.VLessInboundConfig{
				Decryption: "none",
			})
			if err != nil {
				return fmt.Errorf("marshal vless config error: %s", err)
			}
			inbound.Settings = (*json.RawMessage)(&s)
		}
		if len(p.VLess.NetworkSettings) == 0 {
			return nil
		}
		netSets = p.VLess.NetworkSettings
		netProtocol = p.VLess.Network
	case "vmess":
		inbound.Protocol = "vmess"
		if setsNUll {
			s, err := json.Marshal(&coreConf.VMessInboundConfig{})
			if err != nil {
				return fmt.Errorf("marshal vmess settings error: %s", err)
			}
			inbound.Settings = (*json.RawMessage)(&s)
		}
		if len(p.VMess.NetworkSettings) == 0 {
			return nil
		}
		netSets = p.VMess.NetworkSettings
		netProtocol = p.VMess.Network
	}
	if len(netSets) == 0 {
		return nil
	}

	tp := coreConf.TransportProtocol(netProtocol)
	inbound.StreamSetting = &coreConf.StreamConfig{Network: &tp}
	switch netProtocol {
	case "tcp":
		err := json.Unmarshal(netSets, &inbound.StreamSetting.TCPSettings)
		if err != nil {
			return fmt.Errorf("unmarshal tcp settings error: %s", err)
		}
	case "ws":
		err := json.Unmarshal(netSets, &inbound.StreamSetting.WSSettings)
		if err != nil {
			return fmt.Errorf("unmarshal ws settings error: %s", err)
		}
	case "grpc":
		err := json.Unmarshal(netSets, &inbound.StreamSetting.GRPCConfig)
		if err != nil {
			return fmt.Errorf("unmarshal grpc settings error: %s", err)
		}
	default:
		return errors.New("the network type is not vail")
	}
	return nil
}
