package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"hash"
	"os"
	"strings"
	"time"
)

func main() {
	secret := flag.String("secret", "", "Secret used to sign the token")
	jsonOutput := flag.Bool("json", false, "JSON output")
	noColor := flag.Bool("no-color", false, "No color in output")

	flag.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: jwtq [flags] <token>")
		flag.PrintDefaults()
	}
	flag.Parse()

	if len(flag.Args()) < 1 {
		fmt.Fprintln(os.Stderr, "error: no token provided")
		flag.Usage()
		os.Exit(1)
	}

	if len(flag.Args()) > 1 {
		fmt.Fprintf(os.Stderr, "error: unexpected arguments %v (flags must come before the token)\n", flag.Args()[1:])
		flag.Usage()
		os.Exit(1)
	}

	token := flag.Arg(0)

	fmt.Println("JSON output:", *jsonOutput)
	fmt.Println("no color:", *noColor)

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

	fmt.Println("\nHeader")
	fmt.Println(prettify(headerFields))
	fmt.Println("\nPayload")
	fmt.Println(prettify(claims))

	fmt.Println("\nTime Claims")
	timeClaimKeys := []string{"iat", "nbf", "exp"}
	now := time.Now()
	for _, name := range timeClaimKeys {
		t, exists := claimTime(claims, name)
		if exists {
			status := claimStatus(name, t, now)
			fmt.Printf("%-5s %-25s %s\n", name, t.Format("2006-01-02 15:04:05 MST"), status)
			continue
		}
		fmt.Printf("%-5s %s\n", name, "unset")
	}
	fmt.Println("")

	if *secret == "" {
		fmt.Println("signature unverified; no secret provided")
	} else {
		signature := segments[2]
		signatureBytes, err := base64.RawURLEncoding.DecodeString(signature)
		if err != nil {
			fmt.Fprintf(os.Stderr, "decoding signature: %v\n", err)
			os.Exit(1)
		}
		signingInput := encodedHeader + "." + encodedPayload
		signingAlg, _ := headerFields["alg"].(string)
		valid, err := verifyHMAC(signingAlg, signingInput, signatureBytes, *secret)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
		} else if valid {
			fmt.Printf("%s signature verified\n", signingAlg)
		} else {
			fmt.Println("signature verification failed")
		}
	}
}

func verifyHMAC(signingAlg string, signingInput string, signatureBytes []byte, secret string) (bool, error) {
	var h func() hash.Hash

	switch signingAlg {
	case "HS256":
		h = sha256.New
	case "HS384":
		h = sha512.New384
	case "HS512":
		h = sha512.New
	case "":
		return false, fmt.Errorf("no signing algorithm in header")
	default:
		return false, fmt.Errorf("unsupported signing algorithm %q", signingAlg)
	}

	mac := hmac.New(h, []byte(secret))
	mac.Write([]byte(signingInput))
	return hmac.Equal(mac.Sum(nil), signatureBytes), nil
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

func pluralize(n int, unit string) string {
	if n == 1 {
		return fmt.Sprintf("%d %s", n, unit)
	}
	return fmt.Sprintf("%d %ss", n, unit)
}

func claimStatus(key string, t time.Time, now time.Time) string {
	d := t.Sub(now)
	if d < 0 {
		d = -d
	}

	const (
		month = 730 * time.Hour
		year  = 8760 * time.Hour
	)

	var description string
	switch {
	case d < time.Minute:
		description = pluralize(int(d.Seconds()), "second")
	case d < time.Hour:
		description = pluralize(int(d.Minutes()), "minute")
	case d < 24*time.Hour:
		description = pluralize(int(d.Hours()), "hour")
	case d < month:
		description = pluralize(int(d.Hours()/24), "day")
	case d < year:
		description = pluralize(int(d/month), "month")
	default:
		description = pluralize(int(d/year), "year")
	}

	switch key {
	case "exp":
		if t.After(now) {
			return "valid, expires in " + description
		}
		return "expired " + description + " ago"
	case "nbf":
		if t.After(now) {
			return "will be valid in " + description
		}
		return "already valid"
	default:
		if t.After(now) {
			return "will be issued in " + description
		}
		return "issued " + description + " ago"
	}
}
