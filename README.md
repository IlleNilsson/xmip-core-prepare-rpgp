# xmip-core-prepare-rpgp

The rpgp OpenPGP engine, a technology of
[xmip-core-prepare](https://github.com/IlleNilsson/xmip-core-prepare): the
first engine Encryption and Signature choose among for OpenPGP (RFC 9580),
by a step's `engine = "rpgp"`. `rpgp` (MIT or Apache-2.0) reads and writes a
message a piece at a time, its packets cut into partial bodies: Encryption
decrypts with this end's key on receive and encrypts to the recipients on
send; Signature verifies against the signers on receive, the content written
as it is read and the step failed where no signer signed, and signs with this
end's key on send. Keys are files, armored or binary, their bindings checked
when the step is opened; a passphrase-protected key is not opened yet.

Offline (ADR-0045, amendment 2026-10-22): no key server, directory or
revocation is looked up; a key's preferred key server is data, never an
address reached.
## Toolchain

`rust-toolchain.toml` pins the toolchain for the whole estate. Do not change it
here.

## Verification

The included workflow is manual-only and calls the versioned shared workflow at
`IlleNilsson/.github@v1`.
