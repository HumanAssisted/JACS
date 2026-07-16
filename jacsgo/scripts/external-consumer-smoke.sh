#!/usr/bin/env bash
set -euo pipefail

version="${1:-}"
if [[ ! "$version" =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z][0-9A-Za-z.-]*)?$ ]]; then
  echo "usage: $0 vX.Y.Z" >&2
  exit 2
fi

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
cd "$work"

go mod init example.invalid/jacsgo-external-smoke
cat > main.go <<'GO'
package main

import (
	"fmt"

	jacs "github.com/HumanAssisted/JACS/jacsgo"
)

func main() {
	algorithm := "ed25519"
	agent, _, err := jacs.EphemeralSimpleAgent(&algorithm)
	if err != nil {
		panic(err)
	}
	defer agent.Close()

	signed, err := agent.SignMessage(map[string]interface{}{
		"action": "approve",
		"amount": 100,
	})
	if err != nil {
		panic(err)
	}
	verified, err := agent.Verify(signed.Raw)
	if err != nil {
		panic(err)
	}
	if !verified.Valid || verified.SignerID == "" {
		panic("external sign/verify contract did not authenticate a signer")
	}
	fmt.Printf("jacsgo external consumer: valid=%t signer=%s\n", verified.Valid, verified.SignerID)
}
GO

go get "github.com/HumanAssisted/JACS/jacsgo@${version}"
go mod vendor
go run "github.com/HumanAssisted/JACS/jacsgo/cmd/jacsgo-install@${version}" -version "$version"
go build -o jacsgo-smoke .
./jacsgo-smoke
