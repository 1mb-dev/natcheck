// Package classify turns probe results into a NAT-type verdict.
//
// Classification follows RFC 5780 mapping-behavior categories
// (Endpoint-Independent, Address-Dependent, Address and Port-Dependent) and
// emits legacy RFC 3489 terms ("cone", "symmetric") for human readers.
//
// Scaffold only. See docs/TRD.md for the target API.
package classify
