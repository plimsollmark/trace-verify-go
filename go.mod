module github.com/plimsollmark/trace-verify-go

go 1.26.0

// Build with the 1.26.6 toolchain: govulncheck finds html/template advisories
// reachable from cmd/trace-conformance in earlier 1.26 releases.
toolchain go1.26.6
