package main

import (
	"encoding/json"
	"os"
	"sync"

	log "github.com/sirupsen/logrus"
	"github.com/urfave/cli/v2"
)

type Config struct {
	BindDomain              string              `json:"BindDomain"`
	BaseDN                  string              `json:"BaseDN"`
	Filter                  string              `json:"Filter"`
	MemberSearchAttribute   string              `json:"MemberSearchAttribute"`
	GroupRoles              map[string][]string `json:"GroupRoles"`
	UserRoles               map[string][]string `json:"UserRoles"`
	RestrictNamespaceAccess bool                `json:"RestrictNamespaceAccess"`
	UserNamespaces          map[string][]string `json:"UserNamespaces"`
	GroupNamespaces         map[string][]string `json:"GroupNamespaces"`
}

var (
	config     *Config
	configLock = new(sync.RWMutex)
	configfile *string
)

func loadConfig(c *cli.Context) {
	log.Info("config file: ", c.String("config"))
	configFile, err := os.Open(c.String("config"))
	if err != nil {
		log.Error("Error opening config file", err.Error())
		os.Exit(1)
	}

	jsonParser := json.NewDecoder(configFile)
	if err = jsonParser.Decode(&config); err != nil {
		log.Error("Parsing config file", err.Error())
		os.Exit(1)
	}
}

func GetConfig() *Config {
	configLock.RLock()
	defer configLock.RUnlock()
	return config
}
