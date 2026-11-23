// Package terminalaccess supplies the private terminal PATH wrappers. Elevated
// execution is restricted to explicit NLI service/journal operations; no shell
// string, arbitrary executable, pager or operator-supplied environment is used.
package terminalaccess

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"unicode"
)

const HelperBinary = "/usr/bin/nli-node-terminal"

var units = map[string]bool{"nli-agent.service": true, "nli-client-control.service": true, "nli-controller-agent.service": true, "nli-node-terminal.service": true}
var actions = map[string]bool{"status": true, "is-active": true, "is-enabled": true, "restart": true, "daemon-reload": true}

func validUnit(value string) (string, error) {
	if !strings.HasSuffix(value, ".service") {
		value += ".service"
	}
	if !units[value] {
		return "", errors.New("only the four NLI runtime service units are permitted")
	}
	return value, nil
}
func validArgs(args []string) error {
	if len(args) > 64 {
		return errors.New("too many terminal helper arguments")
	}
	for _, arg := range args {
		if len(arg) > 256 || strings.ContainsFunc(arg, unicode.IsControl) {
			return errors.New("invalid terminal helper argument")
		}
	}
	return nil
}
func SystemctlArgs(args []string) ([]string, error) {
	if err := validArgs(args); err != nil {
		return nil, err
	}
	action := ""
	selected := []string{}
	quiet, full := false, false
	for _, arg := range args {
		switch arg {
		case "--no-pager", "--no-ask-password":
			continue
		case "--full", "-l":
			full = true
			continue
		case "--quiet", "-q":
			quiet = true
			continue
		}
		if action == "" {
			if !actions[arg] {
				return nil, errors.New("permitted actions: status, is-active, is-enabled, restart, daemon-reload")
			}
			action = arg
			continue
		}
		unit, err := validUnit(arg)
		if err != nil {
			return nil, err
		}
		selected = append(selected, unit)
	}
	if action == "" {
		return nil, errors.New("an explicit NLI service action is required")
	}
	if action == "daemon-reload" {
		if len(selected) != 0 || quiet || full {
			return nil, errors.New("daemon-reload takes no extra arguments")
		}
		return []string{"--no-pager", "--no-ask-password", action}, nil
	}
	if len(selected) == 0 {
		return nil, errors.New("an explicit NLI service unit is required")
	}
	if quiet && action != "is-active" && action != "is-enabled" {
		return nil, errors.New("quiet is supported only for is-active/is-enabled")
	}
	if full && action != "status" {
		return nil, errors.New("full is supported only for status")
	}
	for _, unit := range selected {
		if unit == "nli-node-terminal.service" && action != "status" {
			return nil, errors.New("terminal broker permits status only")
		}
	}
	result := []string{"--no-pager", "--no-ask-password"}
	if quiet {
		result = append(result, "--quiet")
	}
	if full {
		result = append(result, "--full")
	}
	result = append(result, action)
	return append(result, selected...), nil
}
func JournalArgs(args []string) ([]string, error) {
	if err := validArgs(args); err != nil {
		return nil, err
	}
	selected := []string{}
	options := []string{}
	lines := 200
	follow := false
	valueAt := func(index *int, inline string) (string, error) {
		if inline != "" {
			return inline, nil
		}
		*index = *index + 1
		if *index >= len(args) {
			return "", errors.New("journal option needs a value")
		}
		return args[*index], nil
	}
	for i := 0; i < len(args); i++ {
		arg := args[i]
		name, inline, hasEq := strings.Cut(arg, "=")
		if !hasEq {
			inline = ""
		}
		switch {
		case arg == "--no-pager":
			continue
		case arg == "-f" || arg == "--follow":
			follow = true
		case name == "-u" || name == "--unit" || strings.HasPrefix(arg, "-u") && !strings.HasPrefix(arg, "--"):
			if strings.HasPrefix(arg, "-u") && !strings.HasPrefix(arg, "--") && len(arg) > 2 {
				inline = arg[2:]
			}
			value, err := valueAt(&i, inline)
			if err != nil {
				return nil, err
			}
			unit, err := validUnit(value)
			if err != nil {
				return nil, err
			}
			selected = append(selected, unit)
		case name == "-n" || name == "--lines" || strings.HasPrefix(arg, "-n") && !strings.HasPrefix(arg, "--"):
			if strings.HasPrefix(arg, "-n") && !strings.HasPrefix(arg, "--") && len(arg) > 2 {
				inline = arg[2:]
			}
			value, err := valueAt(&i, inline)
			if err != nil {
				return nil, err
			}
			number, err := strconv.Atoi(value)
			if err != nil || number < 1 || number > 1000 {
				return nil, errors.New("journal lines must be 1..1000")
			}
			lines = number
		case name == "--since" || name == "--until":
			value, err := valueAt(&i, inline)
			if err != nil || strings.TrimSpace(value) == "" || len(value) > 128 {
				return nil, errors.New("journal time needs a bounded value")
			}
			options = append(options, name+"="+value)
		case name == "-o" || name == "--output":
			value, err := valueAt(&i, inline)
			if err != nil {
				return nil, err
			}
			switch value {
			case "short", "short-iso", "short-precise", "json", "cat":
			default:
				return nil, errors.New("unsupported journal output mode")
			}
			options = append(options, "--output="+value)
		case name == "-b" || name == "--boot":
			value := "0"
			if inline != "" {
				value = inline
			} else if i+1 < len(args) {
				if _, err := strconv.Atoi(args[i+1]); err == nil {
					i++
					value = args[i]
				}
			}
			number, err := strconv.Atoi(value)
			if err != nil || number > 0 || number < -10 {
				return nil, errors.New("journal boot must be 0 or one of the previous ten boots")
			}
			options = append(options, "--boot="+value)
		default:
			return nil, fmt.Errorf("unsupported journal option %q; select an NLI unit with -u", arg)
		}
	}
	if len(selected) == 0 {
		return nil, errors.New("journal access requires an explicit NLI service unit")
	}
	result := []string{"--no-pager", "--lines=" + strconv.Itoa(lines)}
	for _, unit := range selected {
		result = append(result, "--unit="+unit)
	}
	if follow {
		result = append(result, "--follow")
	}
	return append(result, options...), nil
}
func helperInvocation(argv []string) (string, []string, error) {
	if len(argv) == 0 {
		return "", nil, nil
	}
	kind := ""
	args := argv[1:]
	switch filepath.Base(argv[0]) {
	case "sudo":
		if len(args) > 0 && args[0] == "-n" {
			args = args[1:]
		}
		if len(args) == 0 || (args[0] != "systemctl" && args[0] != "journalctl") {
			return "", nil, errors.New("terminal sudo supports only NLI systemctl and journalctl helpers")
		}
		if args[0] == "systemctl" {
			kind = "--systemctl"
		} else {
			kind = "--journal"
		}
		args = args[1:]
	case "systemctl":
		kind = "--systemctl"
	case "journalctl":
		kind = "--journal"
	}
	if kind == "" && len(args) > 0 && (args[0] == "--systemctl" || args[0] == "--journal") {
		kind, args = args[0], args[1:]
	}
	return kind, args, nil
}
func RunIfHelper() (bool, error) {
	kind, args, invocationErr := helperInvocation(os.Args)
	if invocationErr != nil {
		return true, invocationErr
	}
	if kind == "" {
		return false, nil
	}
	var canonical []string
	var err error
	if kind == "--systemctl" {
		canonical, err = SystemctlArgs(args)
	} else {
		canonical, err = JournalArgs(args)
	}
	if err != nil {
		return true, err
	}
	return true, executeHelper(kind, args, canonical)
}
