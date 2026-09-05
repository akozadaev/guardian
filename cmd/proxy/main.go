package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/akozadaev/guardian/internal/config"
	"github.com/akozadaev/guardian/internal/server"
)

func main() {
	cfgPath := flag.String("config", "configs/config.yaml", "path to config file")
	flag.Parse()

	cfg, err := config.LoadOrDefault(*cfgPath)
	if err != nil {
		fatal("config: %v", err)
	}

	app, err := server.New(cfg)
	if err != nil {
		fatal("init: %v", err)
	}

	if err := app.Run(); err != nil {
		fatal("run: %v", err)
	}
}

func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}
