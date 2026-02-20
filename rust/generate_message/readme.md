
# Crate `generate_message`

## Overview

This crate is intended to support [Zigner](https://github.com/rotkonetworks/zigner) from the active (non air-gapped) side.

This crate is mainly used to:

 - fetch network data through rpc calls
 - prepare Zigner update and derivation import payloads
 - generate Zigner update QR codes, either signed or unsigned, and derivations import QR codes, to be scanned into Zigner
 - maintain the hot database on the network-connected device, to store and manage the data that went into update QR codes
 - maintain Zigner default network metadata set in `defaults` crate and prepare the cold database for the Zigner release

## Current usage

Program is run by

`$ cargo run COMMAND [KEY(s)]`

## Usage tutorial

Please refer to the [Add New Network](../../docs/src/tutorials/Add-New-Network.md) guide.
