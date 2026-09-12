package unixfs

import "github.com/dewebprotocol/malt-core/auth/input"

// AuthenticationSteps applies this application's relative-path policy and
// returns explicit labels for nested directory Roots. A flattened path index
// instead supplies its complete path as one label; that projection belongs to
// the flat-layout adapter and is not encoded by Prefix or AA.
func AuthenticationSteps(path string) ([]input.Value, error) {
	segments, err := ParsePath(path)
	if err != nil {
		return nil, err
	}
	steps := make([]input.Value, len(segments))
	for i, segment := range segments {
		steps[i] = input.LabelValue([]byte(segment))
	}
	return steps, nil
}
