package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"

	malt "github.com/dewebprotocol/malt"
	"github.com/dewebprotocol/malt/auth/proof/prooflist"
	"github.com/dewebprotocol/malt/protocol"
	clientverifier "github.com/dewebprotocol/malt/sdk/verifier"
	cid "github.com/ipfs/go-cid"
	"github.com/spf13/cobra"
)

func init() {
	rootCmd.AddCommand(verifyCmd)
}

var verifyCmd = &cobra.Command{
	Use:   "verify --root <trusted-root> --query <canonical-query> --prooflist <file|->",
	Short: "Verify a resolve result locally",
	Long: `Verify a resolve result against caller-selected root and query inputs.
The ProofList can be provided as a JSON file or via stdin. The input may be a
bare resolve ProofList or a resolve response containing target and prooflist.
Primitive read evidence must be verified through the read contract rather than
being relabeled as resolve evidence.

Examples:
  malt verify --root "$ROOT" --query "docs/readme.md" --prooflist resolve.json
  malt verify --root "$ROOT" --query "docs/readme.md" --prooflist -
  malt verify --root "$ROOT" --query "" --prooflist root-identity.json`,
	Args: cobra.NoArgs,
	RunE: runVerify,
}

func init() {
	verifyCmd.Flags().String("prooflist", "", "Path to ProofList JSON file, resolve JSON file, or - for stdin")
	verifyCmd.Flags().String("root", "", "Caller-selected trusted root CID")
	verifyCmd.Flags().String("query", "", "Caller-selected canonical ProofList query")
	_ = verifyCmd.MarkFlagRequired("prooflist")
	_ = verifyCmd.MarkFlagRequired("root")
	_ = verifyCmd.MarkFlagRequired("query")
}

func runVerify(cmd *cobra.Command, args []string) error {
	pl, err := readProofListInput(cmd)
	if err != nil {
		return err
	}
	trustedRoot, err := readTrustedRoot(cmd)
	if err != nil {
		return err
	}
	if !pl.Root.Equals(trustedRoot) {
		return fmt.Errorf("ProofList root %s does not match trusted root %s", pl.Root, trustedRoot)
	}
	expectedQuery, err := readExpectedQuery(cmd)
	if err != nil {
		return err
	}
	if pl.Query != expectedQuery {
		return fmt.Errorf("ProofList query %q does not match expected query %q", pl.Query, expectedQuery)
	}
	portable, err := clientverifier.NewDefault()
	if err != nil {
		return fmt.Errorf("initializing local verifier: %w", err)
	}
	path, err := malt.ParseSegmentPath(expectedQuery)
	if err != nil {
		return fmt.Errorf("invalid resolve query: %w", err)
	}
	target, err := proofListTerminalTarget(*pl)
	if err != nil {
		return fmt.Errorf("resolve ProofList shape: %w", err)
	}
	verification := protocol.ResolveVerification{
		Request: protocol.ResolveRequest{
			Profile:  protocol.ResolveProfile,
			Root:     trustedRoot.String(),
			Segments: path.Segments(),
		},
		Result: protocol.ResolveResult{
			Profile:   protocol.ResolveProfile,
			Target:    target.String(),
			ProofList: *pl,
		},
	}
	if err := portable.VerifyResolve(cmd.Context(), verification); err != nil {
		return fmt.Errorf("verifying resolve result locally: %w", err)
	}
	return reportLocalVerification(true)
}

func reportLocalVerification(valid bool) error {
	if valid {
		fmt.Println("valid: true")
		fmt.Fprintf(os.Stderr, "ProofList verified locally\n")
		return nil
	}
	fmt.Println("valid: false")
	fmt.Fprintf(os.Stderr, "local ProofList verification failed\n")
	return malt.ErrVerifierRejected
}

func readExpectedQuery(cmd *cobra.Command) (string, error) {
	raw, err := cmd.Flags().GetString("query")
	if err != nil {
		return "", fmt.Errorf("reading --query: %w", err)
	}
	flag := cmd.Flags().Lookup("query")
	if raw == "" && (flag == nil || !flag.Changed) {
		return "", fmt.Errorf("--query flag is required")
	}
	return raw, nil
}

func readTrustedRoot(cmd *cobra.Command) (cid.Cid, error) {
	raw, err := cmd.Flags().GetString("root")
	if err != nil || raw == "" {
		return cid.Undef, fmt.Errorf("--root flag is required")
	}
	root, err := cid.Decode(raw)
	if err != nil {
		return cid.Undef, fmt.Errorf("invalid trusted root: %w", err)
	}
	return root, nil
}

func readProofListInput(cmd *cobra.Command) (*prooflist.ProofList, error) {
	proofPath, _ := cmd.Flags().GetString("prooflist")
	if proofPath == "" {
		return nil, fmt.Errorf("--prooflist flag is required")
	}

	var (
		data []byte
		err  error
	)
	if proofPath == "-" {
		data, err = io.ReadAll(os.Stdin)
	} else {
		data, err = os.ReadFile(proofPath)
	}
	if err != nil {
		return nil, fmt.Errorf("reading ProofList: %w", err)
	}

	var wrapped struct {
		Target    string               `json:"target"`
		ProofList *prooflist.ProofList `json:"prooflist"`
	}
	if err := json.Unmarshal(data, &wrapped); err == nil && wrapped.ProofList != nil {
		if wrapped.Target != "" {
			lastTarget, err := proofListTerminalTarget(*wrapped.ProofList)
			if err != nil {
				return nil, fmt.Errorf("resolve ProofList shape: %w", err)
			}
			if wrapped.Target != lastTarget.String() {
				return nil, fmt.Errorf("resolve target %s does not match ProofList terminal target %s", wrapped.Target, lastTarget.String())
			}
		}
		return wrapped.ProofList, nil
	}

	var pl prooflist.ProofList
	if err := json.Unmarshal(data, &pl); err != nil {
		return nil, fmt.Errorf("parsing ProofList: %w", err)
	}
	return &pl, nil
}

func proofListTerminalTarget(pl prooflist.ProofList) (cid.Cid, error) {
	if len(pl.Steps) != 0 {
		return pl.LastStepTarget()
	}
	if !pl.Root.Defined() {
		return cid.Undef, fmt.Errorf("prooflist root is undefined")
	}
	if pl.Query != "" {
		return cid.Undef, fmt.Errorf("zero-step ProofList has non-empty query %q", pl.Query)
	}
	return pl.Root, nil
}
