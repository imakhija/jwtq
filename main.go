package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "error: no token provided")
		fmt.Fprintln(os.Stderr, "usage: jwtq <token>")
		os.Exit(1)
	}

	token := os.Args[1]

	segments := strings.Split(token, ".")
	if len(segments) != 3 {
		fmt.Fprintln(os.Stderr, "error: invalid token")
		os.Exit(1)
	}

	header := segments[0]
	payload := segments[1]

	headerDecoded, err := decode("header", header)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	payloadDecoded, err := decode("payload", payload)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	fmt.Println(headerDecoded)
	fmt.Println(payloadDecoded)
}

func decode(segmentType string, encodedSegment string) (string, error) {
	bytes, err := base64.RawURLEncoding.DecodeString(encodedSegment)
	if err != nil {
		return "", fmt.Errorf("decoding %s: %w", segmentType, err)
	}

	var parsed map[string]any
	if err := json.Unmarshal(bytes, &parsed); err != nil {
		return "", fmt.Errorf("parsing %s: %w", segmentType, err)
	}

	decoded, err := json.MarshalIndent(parsed, "", "  ")
	if err != nil {
		return "", fmt.Errorf("formatting %s: %w", segmentType, err)
	}

	return string(decoded), nil
}
