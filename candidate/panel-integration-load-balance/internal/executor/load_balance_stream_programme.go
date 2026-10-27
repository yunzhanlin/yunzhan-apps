package executor

// Filled only by the frozen release build, never by a request/environment or
// caller-created receipt. Ordinary unbound go builds cannot create the account.
// This binds a cohort; it does not replace the actual parent ELF/kernel witness.
var loadBalanceStreamCompiledProgrammeInputsSHA256 string

func loadBalanceStreamProgrammeInputsMatch(expected, observed string) bool {
	return loadBalanceStreamAccountHash(expected) && loadBalanceStreamAccountHash(observed) && expected == observed
}
