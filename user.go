package xray

import (
	"context"
	"encoding/base64"
	"fmt"
	"github.com/InazumaV/Ratte-Core-Xray/common"
	"github.com/InazumaV/Ratte-Interface/common/errors"
	"github.com/InazumaV/Ratte-Interface/core"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/infra/conf"
	"github.com/xtls/xray-core/proxy"
	"github.com/xtls/xray-core/proxy/shadowsocks"
	"github.com/xtls/xray-core/proxy/shadowsocks_2022"
	"github.com/xtls/xray-core/proxy/trojan"
	"github.com/xtls/xray-core/proxy/vless"
	"google.golang.org/protobuf/proto"
	"strings"
)

func (c *Xray) getUserManager(nodeName string) (proxy.UserManager, error) {
	handler, err := c.ihm.GetHandler(context.Background(), nodeName)
	if err != nil {
		return nil, fmt.Errorf("no such inbound tag: %s", err)
	}
	inboundInstance, ok := handler.(proxy.GetInbound)
	if !ok {
		return nil, fmt.Errorf("handler %s is not implement proxy.GetInbound", nodeName)
	}
	userManager, ok := inboundInstance.GetInbound().(proxy.UserManager)
	if !ok {
		return nil, fmt.Errorf("handler %s is not implement proxy.UserManager", nodeName)
	}
	return userManager, nil
}

func getProtocolUser(email string, message proto.Message) *protocol.User {
	return &protocol.User{
		Level:   0,
		Email:   email,
		Account: serial.ToTypedMessage(message),
	}
}

func getCipherFromString(c string) shadowsocks.CipherType {
	switch strings.ToLower(c) {
	case "aes-128-gcm", "aead_aes_128_gcm":
		return shadowsocks.CipherType_AES_128_GCM
	case "aes-256-gcm", "aead_aes_256_gcm":
		return shadowsocks.CipherType_AES_256_GCM
	case "chacha20-poly1305", "aead_chacha20_poly1305", "chacha20-ietf-poly1305":
		return shadowsocks.CipherType_CHACHA20_POLY1305
	case "none", "plain":
		return shadowsocks.CipherType_NONE
	default:
		return shadowsocks.CipherType_UNKNOWN
	}
}

func (c *Xray) AddUsers(p *core.AddUsersParams) (err error) {
	defer func() {
		if err != nil {
			err = errors.NewStringFromErr(err)
		}
	}()
	users := make([]*protocol.User, 0)
	ni, _ := c.nodes.Get(p.NodeName)
	switch ni.Type {
	case "vmess":
		users = common.BuildSlice[core.UserInfo, *protocol.User](p.Users, func(v core.UserInfo) *protocol.User {
			vmessAccount := &conf.VMessAccount{
				ID:       v.Key[0],
				Security: "auto",
			}
			return getProtocolUser(common.FormatUserEmail(p.NodeName, v.Name), vmessAccount.Build())
		})
	case "vless":
		users = common.BuildSlice[core.UserInfo, *protocol.User](p.Users, func(v core.UserInfo) *protocol.User {
			vlessAccount := &vless.Account{
				Id: v.Key[0],
			}
			vlessAccount.Flow = ni.VLess.Flow
			return getProtocolUser(common.FormatUserEmail(p.NodeName, v.Name), vlessAccount)
		})
	case "shadowsocks":
		users = common.BuildSlice[core.UserInfo](p.Users, func(v core.UserInfo) *protocol.User {
			var m proto.Message
			if ni.Shadowsocks.ServerKey == "" {
				ssAccount := &shadowsocks.Account{
					Password:   v.Key[0],
					CipherType: getCipherFromString(ni.Shadowsocks.Cipher),
				}
				m = ssAccount
			} else {
				var keyLength int
				switch ni.Shadowsocks.Cipher {
				case "2022-blake3-aes-128-gcm":
					keyLength = 16
				case "2022-blake3-aes-256-gcm":
					keyLength = 32
				}
				ssAccount := &shadowsocks_2022.Account{
					Key: base64.StdEncoding.EncodeToString([]byte(v.Key[0][:keyLength])),
				}
				m = ssAccount
			}
			return getProtocolUser(common.FormatUserEmail(p.NodeName, v.Name), m)
		})
	case "trojan":
		users = common.BuildSlice[core.UserInfo](p.Users, func(v core.UserInfo) *protocol.User {
			trojanAccount := &trojan.Account{
				Password: v.Key[0],
			}
			return getProtocolUser(common.FormatUserEmail(p.NodeName, v.Name), trojanAccount)
		})
	default:
		return fmt.Errorf("unsupported node type: %s", ni.Type)
	}
	man, err := c.getUserManager(p.NodeName)
	if err != nil {
		return fmt.Errorf("get user manager error: %s", err)
	}
	for _, u := range users {
		mUser, err := u.ToMemoryUser()
		if err != nil {
			return err
		}
		err = man.AddUser(context.Background(), mUser)
		if err != nil {
			return err
		}
	}
	return nil
}

func (c *Xray) GetUserTraffic(p *core.GetUserTrafficParams) *core.GetUserTrafficResponse {
	Rsp := &core.GetUserTrafficResponse{}
	upName := "user>>>" + common.FormatUserEmail(p.NodeName, p.Username) + ">>>traffic>>>uplink"
	downName := "user>>>" + common.FormatUserEmail(p.NodeName, p.Username) + ">>>traffic>>>downlink"
	upCounter := c.shm.GetCounter(upName)
	downCounter := c.shm.GetCounter(downName)
	if upCounter != nil {
		Rsp.Up = upCounter.Value()
	}
	if downCounter != nil {
		Rsp.Down = downCounter.Value()
	}
	return Rsp
}

func (c *Xray) ResetUserTraffic(p *core.ResetUserTrafficParams) (err error) {
	defer func() {
		if err != nil {
			err = errors.NewStringFromErr(err)
		}
	}()
	upName := "user>>>" + common.FormatUserEmail(p.NodeName, p.Username) + ">>>traffic>>uplink"
	downName := "user>>>" + common.FormatUserEmail(p.NodeName, p.Username) + ">>>traffic>>>downlink"
	upCounter := c.shm.GetCounter(upName)
	downCounter := c.shm.GetCounter(downName)
	if upCounter != nil {
		upCounter.Set(0)
	}
	if downCounter != nil {
		downCounter.Set(0)
	}
	return nil
}

func (c *Xray) DelUsers(p *core.DelUsersParams) (err error) {
	defer func() {
		if err != nil {
			err = errors.NewStringFromErr(err)
		}
	}()
	userManager, err := c.getUserManager(p.NodeName)
	if err != nil {
		return fmt.Errorf("get user manager error: %s", err)
	}
	var up, down, user string
	for i := range p.Users {
		user = p.Users[i]
		err = userManager.RemoveUser(context.Background(), user)
		if err != nil {
			return err
		}
		up = "user>>>" + common.FormatUserEmail(p.NodeName, p.Users[i]) + ">>>traffic>>>uplink"
		down = "user>>>" + common.FormatUserEmail(p.NodeName, p.Users[i]) + ">>>traffic>>>downlink"
		c.shm.UnregisterCounter(up)
		c.shm.UnregisterCounter(down)
	}
	return nil
}
