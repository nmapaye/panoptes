package main

import (
	"os"

	"github.com/yourname/panoptes/internal/cli"
)

func main() {
	if err := cli.Execute(); err != nil {
		os.Exit(1)
	}
}
