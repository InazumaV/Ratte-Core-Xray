package xray

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/InazumaV/Ratte-Interface/core"
	"github.com/goccy/go-json"
	coreConf "github.com/xtls/xray-core/infra/conf"
)

func parseV2rayInboundConfig(p *core.NodeInfo, inbound *coreConf.InboundDetourConfig) error {
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
		err := json.Unmarshal(netSets, &inbound.StreamSetting.GRPCSettings)
		if err != nil {
			return fmt.Errorf("unmarshal grpc settings error: %s", err)
		}
	default:
		return errors.New("the network type is not vail")
	}
	return nil
}

func parseShadowsocksInboundConfig(n *core.NodeInfo, inbound *coreConf.InboundDetourConfig) error {
	setsNUll := false
	if inbound.Settings == nil {
		setsNUll = true
	} else {
		if len(*inbound.Settings) == 0 {
			setsNUll = true
		}
	}
	inbound.Protocol = "shadowsocks"
	s := n.Shadowsocks
	settings := &coreConf.ShadowsocksServerConfig{
		Cipher: s.Cipher,
	}
	if !setsNUll {
		err := json.Unmarshal(*inbound.Settings, &settings)
		if err != nil {
			return fmt.Errorf("unmarshal shadowsocks settings error: %s", err)
		}
	}
	p := make([]byte, 32)
	_, err := rand.Read(p)
	if err != nil {
		return fmt.Errorf("generate random password error: %s", err)
	}
	randomPasswd := hex.EncodeToString(p)
	cipher := s.Cipher
	if s.ServerKey != "" {
		settings.Password = s.ServerKey
		randomPasswd = base64.StdEncoding.EncodeToString([]byte(randomPasswd))
		cipher = ""
	}
	defaultSSuser := &coreConf.ShadowsocksUserConfig{
		Cipher:   cipher,
		Password: randomPasswd,
	}
	settings.Users = append(settings.Users, defaultSSuser)
	settings.NetworkList = &coreConf.NetworkList{"tcp", "udp"}
	t := coreConf.TransportProtocol("tcp")
	inbound.StreamSetting = &coreConf.StreamConfig{Network: &t}
	sets, err := json.Marshal(settings)
	inbound.Settings = (*json.RawMessage)(&sets)
	if err != nil {
		return fmt.Errorf("marshal shadowsocks settings error: %s", err)
	}
	return nil
}

func parseTrojanInboundConfig(inbound *coreConf.InboundDetourConfig) error {
	setsNUll := false
	if inbound.Settings == nil {
		setsNUll = true
	} else {
		if len(*inbound.Settings) == 0 {
			setsNUll = true
		}
	}
	inbound.Protocol = "trojan"
	if setsNUll {
		s := []byte("{}")
		inbound.Settings = (*json.RawMessage)(&s)
	}
	t := coreConf.TransportProtocol("tcp")
	inbound.StreamSetting = &coreConf.StreamConfig{Network: &t}
	return nil
}
