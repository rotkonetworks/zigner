
# Crate `definitions`

## Overview

This lib crate is a part of [Zigner](https://github.com/rotkonetworks/zigner).

It contains main definitions used both on the Zigner side and on the Active side. "Zigner side" means everything that happens in the application itself, on the air-gapped device. This includes types used to store in database and move around the network metadata, network specs, user identities non-secret information, etc. "Active side" means whatever is related to Zigner management that happens **not** on Zigner itself, but rather on a network-connected device.

Generally speaking, there are two types of the databases: cold one and hot one. Zigner operates with the cold one. External database on network-connected device is the hot one. However, the cold database itself needs to be pre-generated before being introduced into Zigner on loading. Therefore, when Zigner side is mentioned, it could be only the cold database within Zigner, but the Active side could deal with both cold database preparation prior to moving it into Zigner or hot database procedures.
