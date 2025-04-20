package xray

import (
	"context"
	"errors"
	"fmt"
	"github.com/InazumaV/Ratte-Core-Xray/common"
	"github.com/InazumaV/Ratte-Core-Xray/limiter"
	e2 "github.com/InazumaV/Ratte-Interface/common/errors"
	"github.com/InazumaV/Ratte-Interface/core"
	"github.com/InazumaV/Ratte-Interface/params"
	"github.com/goccy/go-json"
	mapS "github.com/mitchellh/mapstructure"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/serial"
	xc "github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/inbound"
	"github.com/xtls/xray-core/features/outbound"
	coreConf "github.com/xtls/xray-core/infra/conf"
	"strconv"
	"strings"
)

func (c *Xray) getInboundConfig(
	name string,
	n *core.NodeInfo,
	exp *ExpendNodeOptions,
	tls *core.TlsOptions,
) (ind *xc.InboundHandlerConfig, err error) {
	in := &coreConf.InboundDetourConfig{}
	if len(exp.RawInbound) > 0 {
		err = json.Unmarshal(exp.RawInbound, in)
		if err != nil {
			return nil, err
		}
	}
	var netProtocol string // network protocol
	var port uint32
	var common *params.CommonNodeParams
	enableTls := false
	switch n.Type {
	case "vmess":
		netProtocol = n.VMess.Network
		common = &n.VMess.CommonNodeParams
		if n.VMess.TlsType == 1 {
			enableTls = true
		}
		err = parseV2rayInboundConfig(n, in)
	case "vless":
		netProtocol = n.VLess.Network
		common = &n.VLess.CommonNodeParams
		if n.VLess.TlsType == 1 {
			enableTls = true
		}
		err = parseV2rayInboundConfig(n, in)
	case "trojan":
		netProtocol = "tcp"
		common = (*params.CommonNodeParams)(n.Trojan)
		enableTls = true
		err = parseTrojanInboundConfig(in)
	case "shadowsocks":
		netProtocol = "tcp"
		common = &n.Shadowsocks.CommonNodeParams
		err = parseShadowsocksInboundConfig(n, in)
	default:
		return nil, fmt.Errorf("unsupported node type: %s", n.Type)
	}
	if err != nil {
		return nil, err
	}
	p, _ := strconv.Atoi(common.Port)
	port = uint32(p)
	if port == 0 {
		return nil, fmt.Errorf("invalid port: %d", port)
	}
	// Set network protocol
	// Set server port
	in.PortList = &coreConf.PortList{
		Range: []coreConf.PortRange{
			{
				From: port,
				To:   port,
			}},
	}
	// Set Listen IP address
	ipAddress := net.ParseAddress(n.OtherOptions["SendIp"].(string))
	in.ListenOn = &coreConf.Address{Address: ipAddress}
	// Set SniffingConfig
	if in.SniffingConfig == nil {
		sniffingConfig := &coreConf.SniffingConfig{
			Enabled:      true,
			DestOverride: &coreConf.StringList{"http", "tls"},
		}
		in.SniffingConfig = sniffingConfig
	}

	switch netProtocol {
	case "tcp":
		if in.StreamSetting.TCPSettings == nil {
			tcpSetting := &coreConf.TCPConfig{
				AcceptProxyProtocol: common.ProxyProtocol,
			} //Enable proxy protocol
			in.StreamSetting.TCPSettings = tcpSetting
		} else {
			in.StreamSetting.TCPSettings.AcceptProxyProtocol = common.ProxyProtocol
		}
	case "ws":
		if in.StreamSetting.WSSettings == nil {
			in.StreamSetting.WSSettings = &coreConf.WebSocketConfig{
				AcceptProxyProtocol: common.ProxyProtocol,
			} //Enable proxy protocol
		} else {
			in.StreamSetting.WSSettings.AcceptProxyProtocol = common.ProxyProtocol
		}
	default:
		socketConfig := &coreConf.SocketConfig{
			AcceptProxyProtocol: common.ProxyProtocol,
			TFO:                 common.ProxyProtocol,
		} //Enable proxy protocol
		in.StreamSetting.SocketSettings = socketConfig
	}
	if enableTls {
		if tls.CertPath == "" || tls.KeyPath == "" {
			return nil, errors.New("cert or key path is not vail")
		}
		in.StreamSetting.Security = "tls"
		if in.StreamSetting.TLSSettings == nil {
			tlss := in.StreamSetting.TLSSettings
			tlss.Certs = append(tlss.Certs, &coreConf.TLSCertConfig{
				CertFile:     tls.CertPath,
				KeyFile:      tls.KeyPath,
				OcspStapling: 3600,
			})
		} else {
			in.StreamSetting.TLSSettings = &coreConf.TLSConfig{
				Certs: []*coreConf.TLSCertConfig{
					{
						CertFile:     tls.CertPath,
						KeyFile:      tls.KeyPath,
						OcspStapling: 3600,
					},
				},
			}
		}
	}
	in.Tag = name
	return in.Build()
}

func (c *Xray) getOutboundConfig(name string, exp *ExpendNodeOptions) (outH *xc.OutboundHandlerConfig, err error) {
	var rawC json.RawMessage
	oc := &coreConf.OutboundDetourConfig{
		Protocol: "freedom",
	}
	if len(exp.RawOutbound) > 0 {
		err = json.Unmarshal(rawC, &oc)
	}
	oc.Tag = name
	return oc.Build()
}

type ruleObj struct {
	DomainMatcher string   `json:"domainMatcher"`
	Type          string   `json:"type"`
	Domain        []string `json:"domain"`
	Ip            []string `json:"ip"`
	Port          any      `json:"port"`
	SourcePort    string   `json:"sourcePort"`
	Network       string   `json:"network"`
	Source        []string `json:"source"`
	User          []string `json:"user"`
	InboundTag    []string `json:"inboundTag"`
	Protocol      []string `json:"protocol"`
	Attrs         struct {
		Method string `json:":method"`
	} `json:"attrs"`
	OutboundTag string `json:"outboundTag"`
	BalancerTag string `json:"balancerTag"`
	RuleTag     string `json:"ruleTag"`
}

func (c *Xray) addRulesRouting(rs []string) error {
	rules := make([]json.RawMessage, 0, len(rs))
	for i, r := range rs {
		var temp ruleObj
		rO := strings.Split(r, "!")
		tag := fmt.Sprintf("block-%d", i)
		if len(rO) == 1 {
			temp = ruleObj{
				DomainMatcher: "hybrid",
				Domain:        []string{rO[0]},
				OutboundTag:   "block",
				RuleTag:       tag,
			}
		} else {
			switch rO[0] {
			case "domain":
				temp = ruleObj{
					DomainMatcher: "hybrid",
					Domain:        []string{rO[1]},
					OutboundTag:   "block",
					RuleTag:       tag,
				}
			case "port":
				temp = ruleObj{
					DomainMatcher: "hybrid",
					Port:          rO[1],
					OutboundTag:   "block",
					RuleTag:       tag,
				}
			}
		}
		b, err := json.Marshal(temp)
		if err != nil {
			return err
		}
		rules = append(rules, b)
	}
	rc := &coreConf.RouterConfig{
		DomainMatcher:  "hybrid",
		DomainStrategy: common.NewValue("AsIs"),
		RuleList:       rules,
	}

	tc, err := rc.Build()
	if err != nil {
		return fmt.Errorf("failed to build router config: %v", err)
	}
	return c.ru.AddRule(serial.ToTypedMessage(tc), true)
}

func (c *Xray) delRulesRouting(r []string) error {
	for i := range r {
		tag := fmt.Sprintf("block-%d", i)
		if err := c.ru.RemoveRule(tag); err != nil {
			return fmt.Errorf("remove rule %s error: %v", tag, err)
		}
	}
	return nil
}

type ExpendNodeOptions struct {
	SendIp      string          `mapstructure:"SendIp"`
	RawOutbound json.RawMessage `mapstructure:"RawOutbound"`
	RawInbound  json.RawMessage `mapstructure:"RawInbound"`
}

func (c *Xray) AddNode(p *core.AddNodeParams) (err error) {
	defer func() {
		if err != nil {
			err = e2.NewStringFromErr(err)
		}
	}()
	expO := &ExpendNodeOptions{}
	err = mapS.Decode(p.NodeInfo.ExpandParams.OtherOptions, expO)
	if err != nil {
		return fmt.Errorf("unmarshal expend node options failed: %s", err)
	}
	in, err := c.getInboundConfig(p.Name, p.NodeInfo, expO, &p.TlsOptions)
	if err != nil {
		return fmt.Errorf("get inbound config error: %s", err)
	}
	out, err := c.getOutboundConfig(common.FormatDefaultOutboundName(p.Name), expO)
	if err != nil {
		return fmt.Errorf("get outbound config error: %s", err)
	}
	limit := p.NodeInfo.Limit
	_ = c.dispatcher.AddLimiter(
		p.Name,
		limiter.NewLimiter(
			limit.IPLimit,
			limit.SpeedLimit,
			p.NodeInfo.Rules),
	)
	rawInH, err := xc.CreateObject(c.Server, in)
	if err != nil {
		return err
	}
	inH, ok := rawInH.(inbound.Handler)
	if !ok {
		return fmt.Errorf("not an InboundHandler: %s", err)
	}
	err = c.ihm.AddHandler(context.Background(), inH)
	if err != nil {
		return fmt.Errorf("add inbound handler error: %s", err)
	}
	rawOutH, err := xc.CreateObject(c.Server, out)
	if err != nil {
		return err
	}
	handler, ok := rawOutH.(outbound.Handler)
	if !ok {
		return fmt.Errorf("not an OutboundHandler: %s", err)
	}
	if err = c.ohm.AddHandler(context.Background(), handler); err != nil {
		return fmt.Errorf("add outbound handler error: %s", err)
	}
	c.nodes.Set(p.Name, p.NodeInfo)
	return nil
}

func (c *Xray) DelNode(name string) (err error) {
	defer func() {
		if err != nil {
			err = e2.NewStringFromErr(err)
		}
	}()
	err = c.ihm.RemoveHandler(context.Background(), name)
	if err != nil {
		return fmt.Errorf("remove inbound %s error: %v", name, err)
	}
	err = c.ohm.RemoveHandler(context.Background(), common.FormatDefaultOutboundName(name))
	if err != nil {
		return fmt.Errorf("remove outbound %s error: %v", name, err)
	}

	n, _ := c.nodes.Get(name)
	c.nodes.Remove(name)
	_ = c.dispatcher.RemoveLimiter(name)
	err = c.delRulesRouting(n.Rules)
	if err != nil {
		return fmt.Errorf("remove rules routing error: %v", err)
	}
	return nil
}
