package whatsapp

import (
	"path/filepath"

	"github.com/operatoronline/Operator-OS/pkg/bus"
	"github.com/operatoronline/Operator-OS/pkg/channels"
	"github.com/operatoronline/Operator-OS/pkg/config"
)

func init() {
	channels.RegisterFactory("whatsapp_native", func(cfg *config.Config, b *bus.MessageBus) (channels.Channel, error) {
		waCfg := cfg.Channels.WhatsApp
		storePath := waCfg.SessionStorePath
		if storePath == "" {
			storePath = filepath.Join(cfg.WorkspacePath(), "whatsapp")
		}
		return NewWhatsAppNativeChannel(waCfg, b, storePath)
	})
}
