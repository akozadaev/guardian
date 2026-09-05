package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/akozadaev/guardian/internal/openapi"
)

func main() {
	output := flag.String("output", "docs/openapi.yaml", "путь к выходному файлу")
	flag.Parse()

	data, err := openapi.Generate()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if err := os.WriteFile(*output, data, 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "write OpenAPI: %v\n", err)
		os.Exit(1)
	}
}
