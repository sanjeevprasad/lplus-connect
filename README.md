# L+ Connect — unofficial Linux client for OnePlus/OPPO phones

**L+ Connect (binary `lplus`) is an independent, unofficial Linux client for
OnePlus O+ Connect.** Pair and connect OnePlus/OPPO phones over your network
or USB, see them in a device wall with persistent pairing bonds, mirror the
phone screen, and transfer files — one binary, one process, Wayland-first.

Nothing here ships from, or is endorsed by, the vendor. The wire protocols
were reverse-engineered from the vendor's desktop and phone-side apps (wire
captures, decompilation, protocol notes — see
[`../PROTOCOL.md`](../PROTOCOL.md)); the desktop UI is a port of the vendor's
own renderer. See the [disclaimer](#disclaimer) before connecting a device.

## Use it

```sh
cargo run                     # daemon + desktop window
cargo run -- daemon           # headless, logs to stdout
```

The PC's advertised name and address come from `~/.config/lplus/settings.json`
(falling back to the machine hostname and primary interface); pairing bonds
and other state live in the same directory.

## Develop it

```sh
cargo test                               # daemon + UI tests
cargo clippy --all-targets -- -D warnings
./check.sh                               # gitleaks + cargo deny
```

Internals — architecture, IPC channel registry, device model, UI module map,
route coverage, runbook — are documented in [**`GUI.md`**](GUI.md).

## Disclaimer

L+ Connect is an independent project and is neither affiliated with, nor
authorized, sponsored, or approved by, OnePlus Technology or OPPO Guangdong
Mobile. It is provided "as is", without warranty of any kind, and you use it
at your own risk: the maintainers are not liable for any damages arising from
its use, including any action the vendor takes on your account, phone, or
devices, or any breakage introduced by a vendor app or firmware update.
Connecting a phone, mirroring, and file transfers act on your devices — keep
the device lists and captures you expose in mind when connecting.

UI icons are Lucide (ISC) glyphs embedded from the `lucide-static-svg`
crate. The `lplus` code is MIT (see `LICENSE`).

OnePlus, OPPO, O+ Connect and HeyO+ are trademarks of their respective
companies. All other trademarks are the property of their respective owners.
