package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"
)

const usageText = `Usage: %s [options] <filepath> <oci-url>

Push a layer to OCI registry.

Arguments:
  filepath        Path to the file to push (e.g., ./main.tar.gz)
  oci-url         OCI URL (e.g., oci://registry:5000/repo/image:tag)

Options:
  -h, --help     Show this help message
`

func main() {
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, usageText, os.Args[0])
		flag.PrintDefaults()
	}

	// Parse flags
	flag.Parse()

	// Check for required positional arguments
	if flag.NArg() != 2 {
		flag.Usage()
		os.Exit(1)
	}

	filepath := flag.Arg(0)
	ociURL := flag.Arg(1)

	// Validate inputs
	if err := validateInputs(filepath, ociURL); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	client := Client{}
	hash, err := client.PushLayer(
		context.Background(),
		filepath,
		ociURL,
	)
	if err != nil {
		panic(err)
	}

	println(hash)
}

func validateInputs(filepath, ociURL string) error {
	// Check if file exists
	if _, err := os.Stat(filepath); os.IsNotExist(err) {
		return fmt.Errorf("file does not exist: %s", filepath)
	}

	// Basic OCI URL validation
	if !strings.HasPrefix(ociURL, "oci://") {
		return fmt.Errorf("invalid OCI URL format, must start with 'oci://'")
	}

	return nil
}
