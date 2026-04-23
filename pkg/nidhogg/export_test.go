package nidhogg

// NewClientWithRootCAs is a test-only constructor exposed to tests in
// this package and external test packages. It lets tests inject a
// custom TLS trust anchor (e.g. the httptest server's self-signed cert)
// without widening the production API surface with an InsecureSkipVerify
// flag or an exported RootCAs field.
var NewClientWithRootCAs = newClient
