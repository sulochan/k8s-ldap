package main

import (
	"encoding/json"
	"flag"
	"os"
	"sync"

	log "github.com/sirupsen/logrus"
)

type Config struct {
	BindDomain string `json:"BindDomain"`
	BaseDN     string `json:"BaseDN"`
	Filter     string `json:"Filter"`
	MemberSearchAttribute string `json:"MemberSearchAttribute"`
	GroupRoles map[string][]string `json:"GroupRoles"`
	UserRoles  map[string][]string `json:"UserRoles"`
}

var (
	config     *Config
	configLock = new(sync.RWMutex)
	configfile *string
)

func init() {
	configfile = flag.String("config", "./config.json", "Path to config file")
	flag.Parse()
	loadConfig(true)
}

func loadConfig(fail bool) {
	configFile, err := os.Open(*configfile)
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
