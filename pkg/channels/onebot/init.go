package onebot

import (
	"github.com/operatoronline/Operator-OS/pkg/bus"
	"github.com/operatoronline/Operator-OS/pkg/channels"
	"github.com/operatoronline/Operator-OS/pkg/config"
)

func init() {
	channels.RegisterFactory("onebot", func(cfg *config.Config, b *bus.MessageBus) (channels.Channel, error) {
		return NewOneBotChannel(cfg.Channels.OneBot, b)
	})
}
