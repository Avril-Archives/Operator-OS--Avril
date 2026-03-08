package configstore

import (
	"errors"
	"os"
	"path/filepath"

	operatorconfig "github.com/operatoronline/Operator-OS/pkg/config"
)

const (
	configDirName  = ".operator"
	configFileName = "config.json"
)

func ConfigPath() (string, error) {
	dir, err := ConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, configFileName), nil
}

func ConfigDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, configDirName), nil
}

func Load() (*operatorconfig.Config, error) {
	path, err := ConfigPath()
	if err != nil {
		return nil, err
	}
	return operatorconfig.LoadConfig(path)
}

func Save(cfg *operatorconfig.Config) error {
	if cfg == nil {
		return errors.New("config is nil")
	}
	path, err := ConfigPath()
	if err != nil {
		return err
	}
	return operatorconfig.SaveConfig(path, cfg)
}
