package dingtalk

import (
	"github.com/operatoronline/Operator-OS/pkg/bus"
	"github.com/operatoronline/Operator-OS/pkg/channels"
	"github.com/operatoronline/Operator-OS/pkg/config"
)

func init() {
	channels.RegisterFactory("dingtalk", func(cfg *config.Config, b *bus.MessageBus) (channels.Channel, error) {
		return NewDingTalkChannel(cfg.Channels.DingTalk, b)
	})
}
