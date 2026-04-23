// nidhogg-keygen prints a fresh Ed25519 keypair in base64 form, ready
// to paste into client.json ("private_key") and the server's
// "authorized_keys" array. Nothing is written to disk — the operator
// places the values where they are needed.
package main

import (
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/aesleif/nidhogg/internal/transport"
)

func main() {
	name := flag.String("name", "", "optional comment appended to the public key entry")
	asJSON := flag.Bool("json", false, "print {\"private_key\":..,\"public_key\":..} instead of prose")
	flag.Parse()

	pub, priv, err := transport.GenerateKeypair()
	if err != nil {
		fmt.Fprintf(os.Stderr, "generate keypair: %v\n", err)
		os.Exit(1)
	}

	privB64 := base64.StdEncoding.EncodeToString(priv)
	pubB64 := base64.StdEncoding.EncodeToString(pub)
	pubEntry := pubB64
	if strings.TrimSpace(*name) != "" {
		pubEntry = pubB64 + " " + strings.TrimSpace(*name)
	}

	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(map[string]string{
			"private_key": privB64,
			"public_key":  pubEntry,
		})
		return
	}

	fmt.Println("# Paste into client.json under \"private_key\":")
	fmt.Println(privB64)
	fmt.Println()
	fmt.Println("# Paste into server.json \"authorized_keys\" array:")
	fmt.Println(pubEntry)
}
