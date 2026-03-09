package operator

import (
	"github.com/operatoronline/Operator-OS/pkg/bus"
	"github.com/operatoronline/Operator-OS/pkg/channels"
	"github.com/operatoronline/Operator-OS/pkg/config"
)

func init() {
	channels.RegisterFactory("operator", func(cfg *config.Config, b *bus.MessageBus) (channels.Channel, error) {
		return NewOperatorChannel(cfg.Channels.Operator, b)
	})
}
