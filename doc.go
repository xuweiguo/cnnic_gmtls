// Package gmtls implements GM/TLS (SM2/SM3/SM4) primitives and handshakes.
//
// The public API keeps gmtls-specific key and certificate types to ease migration
// from existing GM/T stacks while relying on github.com/emmansun/gmsm for the
// cryptographic core.
package gmtls
