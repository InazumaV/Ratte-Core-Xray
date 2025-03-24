package main

import (
	"fmt"
	"github.com/InazumaV/Ratte-Core-Xray/dispatcher"
	"github.com/InazumaV/Ratte-Interface/core"
	"github.com/goccy/go-json"
	"github.com/orcaman/concurrent-map/v2"
	log "github.com/sirupsen/logrus"
	"github.com/xtls/xray-core/app/proxyman"
	"github.com/xtls/xray-core/app/stats"
	"github.com/xtls/xray-core/common/serial"
	xc "github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/inbound"
	"github.com/xtls/xray-core/features/outbound"
	"github.com/xtls/xray-core/features/routing"
	statsFeature "github.com/xtls/xray-core/features/stats"
	coreConf "github.com/xtls/xray-core/infra/conf"
	"os"
	"path"
	"sync"
)

var _ core.Core = (*Xray)(nil)

// Xray Structure
type Xray struct {
	access     sync.Mutex
	Server     *xc.Instance
	ihm        inbound.Manager
	ohm        outbound.Manager
	shm        statsFeature.Manager
	ru         routing.Router
	nodes      cmap.ConcurrentMap[string, *core.NodeInfo]
	dispatcher *dispatcher.DefaultDispatcher
}

func NewXray() *Xray {
	return &Xray{}
}

func buildCore(dataPath string, c *XrayConfig) (*xc.Instance, error) {
	err := os.Setenv("XRAY_LOCATION_ASSET", path.Join(dataPath, c.AssetPath))
	if err != nil {
		return nil, err
	}
	// Load log config
	coreLogConfig := &coreConf.LogConfig{}
	if len(c.Log) > 0 {
		err = json.Unmarshal(c.Log, coreLogConfig)
		if err != nil {
			return nil, fmt.Errorf("decode log config error: %w", err)
		}
	}

	// Load dns config
	coreDnsConfig := &coreConf.DNSConfig{}
	os.Setenv("XRAY_DNS_PATH", "")
	if len(c.Dns) > 0 {
		err = json.Unmarshal(c.Dns, coreDnsConfig)
		if err != nil {
			return nil, fmt.Errorf("decode dns config error: %w", err)
		}
	}
	dnsConfig, err := coreDnsConfig.Build()
	if err != nil {
		return nil, fmt.Errorf("build dns config error: %w", err)
	}

	// Load route config
	coreRouterConfig := &coreConf.RouterConfig{}
	if len(c.Route) > 0 {
		err = json.Unmarshal(c.Route, coreRouterConfig)
		if err != nil {
			return nil, fmt.Errorf("decode route config error: %w", err)
		}
	}
	routeConfig, err := coreRouterConfig.Build()
	if err != nil {
		return nil, fmt.Errorf("build route config error: %w", err)
	}

	// Load inbound config
	var coreCustomInboundConfig []coreConf.InboundDetourConfig
	if len(coreCustomInboundConfig) > 0 {
		err = json.Unmarshal(c.Inbound, &coreCustomInboundConfig)
		if err != nil {
			return nil, fmt.Errorf("decode inbound config error: %w", err)
		}
	}
	var inBoundConfig []*xc.InboundHandlerConfig
	for _, config := range coreCustomInboundConfig {
		oc, err := config.Build()
		if err != nil {
			return nil, fmt.Errorf("build inbound(tag=%s) config error: %w",
				config.Tag, err)
		}
		inBoundConfig = append(inBoundConfig, oc)
	}

	// Load outbound config
	var coreCustomOutboundConfig []coreConf.OutboundDetourConfig
	if len(c.Outbound) > 0 {
		err = json.Unmarshal(c.Outbound, &coreCustomOutboundConfig)
		if err != nil {
			return nil, fmt.Errorf("decode outbound config error: %w", err)
		}
	}
	var foundBlock bool
	var outBoundConfig []*xc.OutboundHandlerConfig
	for _, config := range coreCustomOutboundConfig {
		oc, err := config.Build()
		if err != nil {
			return nil, fmt.Errorf("build outbound config error: %w", err)
		}
		if config.Tag == "block" {
			foundBlock = true
		}
		outBoundConfig = append(outBoundConfig, oc)
	}

	if !foundBlock {
		oc, err := (&coreConf.OutboundDetourConfig{
			Protocol: "blackhole",
			Tag:      "block",
		}).Build()
		if err != nil {
			return nil, fmt.Errorf("build block outbound config error: %w", err)
		}
		outBoundConfig = append(outBoundConfig, oc)
	}

	// Load policy config
	var policy = &coreConf.Policy{}
	if len(c.Policy) > 0 {
		err = json.Unmarshal(c.Policy, policy)
		if err != nil {
			return nil, fmt.Errorf("decode policy error: %w", err)
		}
	}
	corePolicyConfig := &coreConf.PolicyConfig{}
	corePolicyConfig.Levels = map[uint32]*coreConf.Policy{0: policy}
	policyConfig, _ := corePolicyConfig.Build()
	// Build Xray config
	config := &xc.Config{
		App: []*serial.TypedMessage{
			serial.ToTypedMessage(coreLogConfig.Build()),
			serial.ToTypedMessage(&dispatcher.Config{}),
			serial.ToTypedMessage(&stats.Config{}),
			serial.ToTypedMessage(&proxyman.InboundConfig{}),
			serial.ToTypedMessage(&proxyman.OutboundConfig{}),
			serial.ToTypedMessage(policyConfig),
			serial.ToTypedMessage(dnsConfig),
			serial.ToTypedMessage(routeConfig),
		},
		Inbound:  inBoundConfig,
		Outbound: outBoundConfig,
	}
	server, err := xc.New(config)
	if err != nil {
		return nil, fmt.Errorf("new xray error: %w", err)
	}
	switch coreLogConfig.LogLevel {
	case "debug":
		log.SetLevel(log.DebugLevel)
	case "info":
		log.SetLevel(log.InfoLevel)
	case "warning":
		log.SetLevel(log.WarnLevel)
	case "error":
		log.SetLevel(log.ErrorLevel)
	case "none":
		log.SetLevel(log.PanicLevel)
	}
	return server, nil
}

// Start the Xray
func (c *Xray) Start(dataPath string, config []byte) error {
	var cf = NewXrayConfig()
	err := json.Unmarshal(config, cf)
	if err != nil {
		return err
	}
	c.Server, err = buildCore(dataPath, cf)
	if err != nil {
		return err
	}
	c.access.Lock()
	defer c.access.Unlock()
	if err := c.Server.Start(); err != nil {
		return err
	}
	c.shm = c.Server.GetFeature(statsFeature.ManagerType()).(statsFeature.Manager)
	c.ihm = c.Server.GetFeature(inbound.ManagerType()).(inbound.Manager)
	c.ohm = c.Server.GetFeature(outbound.ManagerType()).(outbound.Manager)
	c.ru = c.Server.GetFeature(routing.RouterType()).(routing.Router)
	c.dispatcher = c.Server.GetFeature(routing.DispatcherType()).(*dispatcher.DefaultDispatcher)
	return nil
}

// Close  the core
func (c *Xray) Close() error {
	c.access.Lock()
	defer c.access.Unlock()
	c.ihm = nil
	c.ohm = nil
	c.shm = nil
	c.dispatcher = nil
	err := c.Server.Close()
	if err != nil {
		return err
	}
	return nil
}

func (c *Xray) Protocols() []string {
	return []string{
		"vmess",
		"vless",
		"shadowsocks",
		"trojan",
	}
}

func (c *Xray) Type() string {
	return "RatteCoreXray"
}
