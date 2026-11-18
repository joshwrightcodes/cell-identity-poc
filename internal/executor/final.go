package executor

import "fmt"

// Final is the error that an Effect returns when the operation ends with a final outcome other than
// applied. The executor records the outcome, the reason and the detail as the result of the
// operation, so a repeated operation ID answers already_applied and the effect does not run again.
type Final struct{ Outcome, Reason, Detail string }

// Error describes the outcome.
func (f *Final) Error() string {
	return fmt.Sprintf("final outcome %s: %s %s", f.Outcome, f.Reason, f.Detail)
}
