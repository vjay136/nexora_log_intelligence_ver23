//go:build !linux

package terminalaccess

import "errors"

func executeHelper(string, []string, []string) error {
	return errors.New("NLI terminal helpers require Linux")
}
