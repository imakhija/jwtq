package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"
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

	encodedHeader := segments[0]
	encodedPayload := segments[1]

	headerFields, err := decode("header", encodedHeader)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	claims, err := decode("payload", encodedPayload)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	fmt.Println("Header")
	fmt.Println(prettify(headerFields))
	fmt.Println("\nPayload")
	fmt.Println(prettify(claims))

	fmt.Println("\nTime Claims")
	timeClaimKeys := []string{"iat", "nbf", "exp"}
	for _, name := range timeClaimKeys {
		t, exists := claimTime(claims, name)
		if exists {
			fmt.Printf("%-5s %s\n", name, t.Format("2006-01-02 15:04:05 UTC"))
			continue
		}
		fmt.Printf("%-5s %s\n", name, "unset")
	}
}

func decode(segmentType string, encodedSegment string) (map[string]any, error) {
	decodedBytes, err := base64.RawURLEncoding.DecodeString(encodedSegment)
	if err != nil {
		return nil, fmt.Errorf("decoding %s: %w", segmentType, err)
	}

	var parsed map[string]any
	if err := json.Unmarshal(decodedBytes, &parsed); err != nil {
		return nil, fmt.Errorf("parsing %s: %w", segmentType, err)
	}

	return parsed, nil
}

func prettify(fields map[string]any) string {
	prettified, _ := json.MarshalIndent(fields, "", "  ")
	return string(prettified)
}

func claimTime(claims map[string]any, key string) (time.Time, bool) {
	unix, exists := claims[key].(float64)
	if exists {
		return time.Unix(int64(unix), 0).UTC(), true
	}
	return time.Time{}, false
}
