package main

import (
	"os"

	"github.com/nmapaye/panoptes/internal/cli"
)

func main() {
	if err := cli.Execute(); err != nil {
		os.Exit(1)
	}
}
