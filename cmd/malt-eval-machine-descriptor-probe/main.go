// Command malt-eval-machine-descriptor-probe emits a descriptor template from
// the exact host probe used by paper evaluator workers. The maintainer supplies
// the campaign ID and classification evidence; the resulting file is then
// pinned by SHA-256 and byte length in E0/campaign registration.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/dewebprotocol/malt-client/internal/evaluation/machine"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(args []string) error {
	flags := flag.NewFlagSet("malt-eval-machine-descriptor-probe", flag.ContinueOnError)
	id := flags.String("id", "", "campaign machine descriptor ID")
	classification := flags.String("classification", "", "general-purpose or low-power-arm")
	evidence := flags.String("classification-evidence-source", "", "registered vendor/product evidence source")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("unexpected positional arguments")
	}
	identity, err := machine.Probe()
	if err != nil {
		return err
	}
	descriptor, err := machine.NewDescriptor(strings.TrimSpace(*id), strings.TrimSpace(*classification), strings.TrimSpace(*evidence), identity)
	if err != nil {
		return err
	}
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	return encoder.Encode(descriptor)
}
