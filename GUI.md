# O+ Connect PC (Electron) → Linux port

Sources: `../winzip/resources/app.asar` (O+Connect
17.100.10 Windows build, extracted to `vendor/` here), second source
`../mac/O+Connect.app` (paths relative to this crate).

**One crate, one binary**: this crate (`lplus`) IS the product. `cargo run`
starts the backend **in-process** and opens the GPUI window; the same
process serves the HTTP seam (`POST /__ipc`, `GET /__events`) on
`127.0.0.1:1421` — the attach transport for `lplus gui`, `--probe-transport`
and curl-level debugging. The GUI code lives in `src/gui/` (seam: `ipc.rs`
dispatch registry, `server.rs`, `devices.rs`, `cast.rs`); the desktop UI
port is `src/ui/`. The legacy
`loopback/pair/connect/sdpd/ble` subcommands stay for dev/CI.

**Status: the GPUI port (`src/ui/`) is the UI.** The vendored
`vendor/renderer/index.html` bundle (Vue 3.5 + Element Plus + vue-router +
vuex + vue-i18n) is no longer served or booted — the in-page Electron-era
shim (`shim.js`) was removed together with the browser path. The bundle
stays in the tree as the behaviour reference: its `.js.map` sources drive
the port's screens, channel names and response shapes. Electron/Node is
replaced in Rust by the IPC channel registry (`src/gui/ipc.rs`), which the
GPUI window calls directly and HTTP clients reach through `POST /__ipc`.

## 1. What the Electron app is

**Main process** — `background.js` (11.9 MB webpack bundle, `package.json`
`"main": "background.js"`, app id `com.oplus.devicespace`). It holds all
business logic and serves every window from a custom `app://` buffer
protocol. Its Node surface: `child_process`, `fs`, `net`, `tls`, `http(s)`,
`os`, `zlib`, `vm`, plus native FFI (`koffi`, `macos-temperature-sensor`).
It owns ~568 `GENERIC_AGENT_*` IPC channel constants (the enum is inlined in
the bundle and matched 1:1 by the renderer). Windows: main (`index.html`),
`about`, `login`/`loginHome`, `miniwindow`, `floatingball`, `globalPopup`,
plus pages under `pages/`.

**Renderer** — Vue **3.5.44** (vue-cli/webpack), `vue-router` (hash mode),
vuex, `vue-i18n`, `element-plus`, axios; 7 HTML entries + `pages/`. `js/`
ships source maps for most chunks — the original sources are recoverable and
were used to drive this port (call sites, response shapes, boot order).

**Renderer's Electron/Node dependency surface**
- Webpack externals resolve at runtime through the **global `require`**:
  `electron`, `events`, `crypto`, `process`, `fs`, `path`, `os`, `util`,
  `assert`, `buffer`, `stream` (+`stream/consumers`), `string_decoder`,
  `zlib`, `net`, `http`, `https`, `url`, `child_process`, and the ajv
  runtime submodules (`ajv/dist/runtime/*`, `ajv-formats/dist/formats`).
- `nodeIntegration:true` / `contextIsolation:false` on every window.
- ~92 direct `ipcRenderer` call sites (69 `invoke`, 13 `send`, 10 `on`)
  plus an internal request/response bus (`IpcRender.js`:
  `send('ipc_main_event', {name,data,callbackId})` → main replies on
  `ipc_renderer_event` with `{callbackId, code, data}`).
- Electron modules beyond `ipcRenderer`: `screen.*` (15 chunks),
  `clipboard` (4), `shell.openExternal` (1), `nativeImage` (1), `app.getPath`
  (electron-store/conf/atomically run **for real** inside the renderer).

## 2. Architecture of the seam

| Concern | Solution |
|---|---|
| `ipcMain` side | `src/gui/ipc.rs`: registry commands; unknown channels answer `{ok:false,__unhandled}` — never a crash. The GPUI window calls `dispatch` in-process; HTTP clients go through `POST /__ipc` on `src/gui/server.rs` (127.0.0.1:1421) |
| Renderer bus (`ipc_main_event`) | `ipc_bus` → `GET /__events` SSE of the process-global `GUI_BUS` (`{callbackId, code, data}` envelopes, exactly the Electron bus helper's shape) |
| Console mirror | `console_log` IPC / `GET /__log` beacon mirror remote client logs onto the host log |
| Reference bundle | `vendor/renderer` is served nowhere; the `.html`/`.js`/`.css` keep the historical `app://`→`/` rewrite so RE diffs against the asar stay line-aligned |
| Locale | The port authors English strings; the bundle's bundled zh packs remain as reference data |
| UI transports | direct (merged default): the window calls `gui::ipc::dispatch` in-process; attach (`gui` subcommand): `POST /__ipc` to a running daemon, `LPLUS_BACKEND=off/1/host:port`. The in-process mock main (stub devices + audit ring) compiles into **test builds only** (`#[cfg(test)]`); shipped builds without a backend keep the vendor `__unhandled` contract. Tests run mock-only and never touch the network |

## 3. IPC channel registry (`src/gui/ipc.rs`)

`ipc_invoke` routes `ipcRenderer.invoke` channels; `ipc_bus` routes bus
`name`s and answers `code_success` envelopes; unknown names are recorded in
a 400-entry audit ring (`ipc_registry` command returns it) and answered with
`{ok:false,__unhandled}`. The GPUI UI's direct transport calls the same
`dispatch` entry point, so every channel is served identically whether it
arrives over the wire or in-process.

| Channel (value as sent) | Status | Answer |
|---|---|---|
| `generic_agent_get_paired_devices` | implemented | `{ok:true,entries,devices,pairedDevices}` from the daemon-backed device model |
| `generic_agent_settings_remove_device` | implemented | `{device_id,removeStateDir}` → `{ok}` (rows actually removed); block-set in `unpaired.json` |
| `generic_agent_get_local_device_id` | implemented | PC device id (`LPLUS_PC_DEVICE_ID` env) |
| `generic_agent_get_cloud_bind` | implemented | `{ok:true,bound:false}` |
| `generic_agent_ensure_running` | implemented | `{ok:true,status:'idle'}` |
| `get_current_connected_device_info_list` | implemented | connected rows of the device model |
| `lplus_sidecar_status` | implemented | `{running,logTailing}` (in-process backend liveness; `logTailing:"in-process backend"`) |
| `connect_device` / `disconnect_device` | implemented | queues `sdpd::Command::{Connect,Disconnect}{ip}` on the backend command channel (`{ok,ip}`; `ok:false` when the channel is closed) |
| `public_get_system_theme` | implemented | `"light"` |
| `settings_get_pc_connect_running` | implemented | `false` |
| `get_main_window_bounds` | implemented | live outer bounds |
| `get_main_window_focus_status` | implemented | live focus state |
| `settings_get_host_name` / `get_http_server_port` / `is_http_server_running` | implemented | PC host name / `null` / `false` |
| bus `ComputerVersion` | implemented | `"17.100.10"` |
| bus `get_and_update_deviceinfo` | implemented | all rows of the device model |
| bus `open_getFeatureEnable` (mydevice connect-button broadcast) | implemented | `{ok:true,enable:true}` |
| bus `isMainWin` | implemented | `true` (single-window port) |
| bus `get_general_config` | implemented | `{}` |
| bus `ipc_event_init`/`ipc_event_destory` | implemented | `{ok:true}`; `ipc_event_init` also records the subscribed event name so device pushes only fan out to subscribers |
| `generic_agent_*` (remaining ~50) | unhandled | typed unhandled + audit |
| bus `shell_share_locale_changed`, `get_app_config_path_to_contents`, `check_if_exist_remote_device`, `note_get_sidebar_width`, `FILE_QUEUE_AVAILABLE`, `initQueue`, `update_get_update_info` | unhandled (observed on boot) | typed unhandled + audit |

### 3.1 Device model (`src/gui/devices.rs`)

```
lplus backend (in-process, same binary)
  sdpd::run(SdpdConfig csp 10152) on the GUI async runtime
  + KMS :36863 · REPL · events bridge :14752 · EPI lanes
  DeviceEvent{kind,ip,name,connected,ts_ms}  tokio broadcast
    ├─ subscribe_devices() ───────────►   (GUI ingest; `lplus daemon`
    │                                      mirrors the same lines to stdout)
    └─ LPLUS_EVENTS_PORT=<p[,p…]> ────►   reconnection NDJSON subscribers
                                          (dev aid: follow an external
                                          daemon's bridge)
                        │
                        ▼
        rows {deviceId,deviceName,ip,isDiscovered,isConnected,…}
        ├── GPUI device wall (ui) ──► renders the cards directly
        ├── GET  /__devices ──────────► attach / curl clients
        │     (row shape = the vendor `devicesList` electron-store entry)
        └── tick(): bus push to subscribers
              {event:"push_search_devices_in_deivce_list",
               data: JSON.stringify(row)}
```

- Ingest is **typed events only** — never log scraping. Every event mirrors
  to stderr as `[presence] event kind=… ip=… connected=… name=… ts_ms=…`.
  Rows are keyed by `ip` (dedupe; never `ip:port`), minted only by
  `epi`/`kms`/`scp_sync` events, and pruned after 5 min without events
  (`ROW_TTL_SECS`; paired rows are exempt). `connected` flips on `epi`/`kms`
  session events (a `connected=false` event means the lane closed);
  `is_discovered` tracks a 120 s event window. Device names come
  exclusively from `scp_sync` events (the phone's model string —
  `CPH2745`); before the first sync a row shows `Phone <octet>`.
  Unclassified event kinds only refresh existing rows, so neighbour
  SSDP/probe chatter stays invisible. Host-local ips (loopback, `--vip`, the
  primary NIC) are filtered: the daemon may report the PC's own side of
  sessions. The adb lane (`adb devices -l`, 5 s) mints USB rows
  (`connectType 128`, `usbSerial`) outside the event path.
- The backend runs in the **same process** (`sdpd::run`).
  `apply_daemon_env()` seeds the env-driven knobs — SCP_*, EPI, KMS(36863),
  LINK_*, REPL, `SCP_INTERACT=accept`, `LPLUS_EVENTS_PORT=14752` — in `main`
  while single-threaded (CLI `--name/--csp/--vip` override `SdpdConfig`).
  Non-defaulted knobs: `LPLUS_USB=1` re-enables the adb/USB device lane
  (hidden by default: Wi-Fi-only device lists; paired bonds stay persisted
  either way); `ODMF_LIVE=1` pipes decoded mirror frames to the in-window
  live preview (`ODMF_PLAYER`/`ODMF_FFMPEG` override the players), and
  `ODMF_LISTEN`/`ODMF_RTP_PORT` move the mirror RTSP/RTP endpoints;
  `LINKPUB` replaces the auto-built `LinkInfoPayload` blob (hex) that the
  LinkSwitchMgr `SERVICE-PUBLISH` carries, `LINKNS` pins the published
  service id instead of rotating candidates.
  Before the backend starts, `preflight_or_die` bind-checks every port the
  daemon takes (csp family, datatrans lanes, UDP 10150/10151, REPL, bridge)
  and **fails loudly** naming each port and the holder (`ss -ltnp` /
  `ss -lunp` lines), never deferring: only one `lplus` owns the network
  stack. A backend bind failure after preflight also exits non-zero.
- Rows are consumed verbatim by the GPUI device wall and `GET /__devices`:
  `protcol_device_id` keeps the renderer's typo and the row shape matches
  the vendor `devicesList` electron-store entry, so attach clients see the
  same JSON mydevice used to render its cards from. The wall re-pulls on a
  2 s timer (event-push refresh in §6 replaces it).
- `devices.rs` unit tests cover: scp_sync mints the named row, epi/kms flip
  `connected`, unclassified kinds never mint rows (noisy neighbour), per-ip
  dedupe, host-side filtering, model-name preference, adb upsert/prune, and
  TTL pruning with the paired exemption (`cargo test`).

Device actions round-trip through the backend command channel: the
renderer's Connect/Disconnect lane (and the `connect_device` /
`disconnect_device` channels) queue
`sdpd::Command::{Connect,Disconnect,KmsBootstrap,SendFrame}`;
`spawn_command_runner` executes them (adb-side steering via `steer.rs`,
EPI sink pushes).

## 4. Verification reference

- Boot (`./target/debug/lplus` under sway/Wayland): the "L+ connect" window
  opens on Home; backend markers `[kms] listening :36863`,
  `[repl] listening 127.0.0.1:47991`, `[events] NDJSON bridge :14752`,
  `sdpd up: :10150 (mcast 239.255.255.250) :10151 (uni)
  tcp[10152,10153,10151,10150,46888,47888,48888]`.
- Event-fed device rows: with the backend live, `GET /__devices` returns
  the paired rows (`deviceName CPH2745`, `isConnected true`) while the log
  shows `[presence] event kind=scp_sync …` / `kind=epi …` lines.
  Unclassified events (neighbour SSDP/probe noise) and
  the PC's own VIP stay out of the list (visibility rules in §3.1).
- Loud port conflict: startup against a machine where a foreign process
  holds the stack exits non-zero naming every port plus the holder's
  `ss -ltnp` line, preflighting csp family, datatrans lanes, UDP
  10150/10151, REPL and the events bridge.
- `--probe-transport` exits 0 only when every probed channel
  (status, connected, found, host-name) is answered by the backend.

## 5. Runbook

```sh
cd oneplus/linux-client    # from the repo root (the dir holding this document)
cargo run                       # daemon + GPUI window
cargo run -- daemon             # headless backend, stdout logs
cargo run -- panel              # daemon + HTTP seam only (no window)
cargo run -- gui                # window attached to a running daemon
./target/debug/lplus --csp 10152          # name from settings.json/hostname, vip auto-detected
./connect.sh <resp> <linkpub-hex>   # one scripted connect attempt (restarts sdpd, taps phone, waits on markers)
./waitlex.sh <ERE> [timeout_s]      # block until regex appears in the live taplog (TAPLOG override honored)
# seam: curl -s -XPOST 127.0.0.1:1421/__ipc \
#   -d '{"cmd":"ipc_invoke","args":{"channel":"get_current_connected_device_info_list","payload":null}}'
```

`lplus` is **the** daemon: default csp 10152, EPI lanes (46888/47888/48888),
KMS (`KMS=1 KMS_PORT=36863 KMS_PWD=lplus-kms-pw`), REPL
(`LPLUS_REPL_PORT`), presence NDJSON bridge (`LPLUS_EVENTS_PORT=14752`),
SCP_*/LINK_* quickstart table applied via `apply_daemon_env()` (every entry
only if the environment doesn't already define it — launch with your own
exported values to override, e.g. `LPLUS_REPL_PORT=47991` for the cast
tooling). If a foreign process holds any of those ports, startup fails
loudly naming port + holder (`ss -ltnp`), so exactly one `lplus` owns the
network stack. Presence follows external bridges only via
`LPLUS_EVENTS_PORT=port[,port…]` (dev aid). Persistent state —
`paired.json`, `unpaired.json`, `settings.json` (host name, pinned
beacon `name`, pairing material `scpKsc`/`linkKpd` — seeded into the
environment at startup) — lives in the
platform config dir (`~/.config/lplus` on XDG; `directories` crate),
override with `LPLUS_STATE_DIR`; files left in the capture out dir are
copied over once on first use.

## 6. Next steps

1. Connect flow: the Connect/Disconnect actions and `connect_device` /
   `disconnect_device` channels are wired to
   `sdpd::Command::{Connect,Disconnect}` (adb steering via `steer.rs`);
   finish the end-to-end flip on live phones and drive `KmsBootstrap` /
   `SendFrame` from UI actions as the lanes mature.
2. Work the audit ring (`ipc_registry`) list above as lanes land; every
   implemented channel = one `route_invoke`/`route_bus` arm.
3. Event-push refresh for the GPUI window (sdpd broadcast → UI) to replace
   its 2 s timer.
4. Typed daemon config: parse the env knobs once into `SdpdConfig`,
   replacing the `DAEMON_ENV` seed table and the per-reader default
   duplicates (`KMS_PWD`, `KMS_PORT`, `LINK_KPD`). Partially landed:
   `--name`/`--vip` resolve at parse time (settings-pinned name →
   hostname; primary-interface VIP) and `settings.json` keys
   `scpKsc`/`linkKpd` seed `SCP_KSC`/`LINK_KPD` before the defaults.
5. Bundle step (deb/appimage), icons/branding.

## 7. UI module map (`src/ui/`)

| Module | Ports |
| --- | --- |
| `src/ui/router.rs` | vendor hash router (`home`, `crossfile/*`, `aiSearch`, `screen`, `screenshare`, `remotecontrol`, `settings`, `uploaddownload`, `generic-agent`, `note`) |
| `src/ui/ipc.rs` | transports (direct / attach; test-only mock filler), vendor channels as a typed strum `Channel` enum + `__unhandled` audit ring |
| `src/ui/stores/connection.rs` | vuex `connection.js`: found/connected merge, `deviceListSort`, connect state machine (incl. on-device permission wait) |
| `src/ui/stores/transfer.rs` | vuex `uploadDownload.js`: queue, progress clamp, clear-finished |
| `src/ui/stores/toast.rs` | vuex `toast.js` |
| `src/ui/app.rs` | root `AppState` entity: pure handlers (TDD), mirroring/account/quality state |
| `src/ui/views.rs` | element trees; tokens from `src/ui/theme.rs` |
| `src/ui/theme.rs` | design tokens **measured from the live renderer** |
| `src/ui/e2e.rs` | gpui `TestApp` integration suite (click-walks the sidebar nav, transfer queue) |

Window flags: `--demo` (manual-connect lane; device mock is test-builds-only),
`--dialog [--usb]`, `--start-home`, `--route <name>` (accepted names:
`settings|screen|aiSearch|crossfile|screenshare|remotecontrol|genericAgent|note|uploaddownload`).

## 8. Vendor parity (measured, not guessed)

Reference captures were taken from the running vendor UI at 1280×800
(headless Chromium against the live renderer on `:1421`, guide-tour overlay
removed) and the port is probed pixel-wise against them with a region
metric (non-white count + mean colour, per screen state): light theme,
white base; vendor-bundled **OPPO Sans 4.0 SC** (`LPLUS_FONT` override);
180 px sidebar (open-licensed icons at measured positions), device wall
card grid, and the manual-connect QR dialog
(`--dialog`, `--usb`) all measured per the token table in `theme.rs`.
Region probes (taken against the vendor build, pre icon swap and pre
sign-in removal): home 15/15, QR dialog 10/10, USB tab 8/8, device
wall 9/9 PASS against vendor references.

## 9. Route coverage

| Vendor route | State |
| --- | --- |
| `#/home` (device wall, found-device cards, connect lifecycle) | ported (connected/paired-device cards are real-backend rows; vendor card UX: Connected/Recently connected tags, ⋮ more-menu with Disconnect/Delete device, per-card disconnect glyph, connected-card quick entries Files/Screencast/Screen Collaborate/Content sync, and the three vendor confirm dialogs — Delete this device?, Disconnect this device? (sharing-aware copy), Connect to a new device?) |
| `#/screen` (mirroring start/stop, quality presets, mute/record) | ported on mock odmf |
| `#/uploaddownload` (+ MiniUploadDownload header chip) | ported (demo queue) |
| `#/settings` (general panel subset) | ported (host name through backend `settings_*`) |
| `#/crossfile` category tiles + list | functional with mock tree; `cross_file_list` gap audited |
| `#/aiSearch` | functional with mock corpus; `ai_search_execute` gap audited |
| `#/generic-agent` | ported on real `generic_agent_*` channels: daemon status, this PC's agent id, cloud bind, pairing bonds with vendor confirm-delete |
| `#/screenshare`, `#/remotecontrol`, `#/note` | honest stubs: pending channels are invoked and land in the audit ring |

## 10. Known gaps / honest stubs

- Device cards vs the vendor: the "Mobile network" warning tag has no
  backend data yet (`deviceCellularStatus`), so it is omitted; the
  Screen Collaborate quick entry is rendered greyed and non-clickable
  until the multi-screen backend channels exist (no
  `isHaveScreenShareAbility` in the rows either — flip the `enabled`
  arg in `card_feature_entry` to re-arm it).

- Icons are open-licensed, not vendor copies: every glyph (nav rail, floor
  controls, QR overlays) is a **Lucide** (ISC) SVG embedded from the
  `lucide-static-svg` crate; glyph tints live in `theme.rs`. Pixel probes
  predate the swap and were measured against the vendor originals.
- Text entry (settings host name, aiSearch query) uses preset chips; a
  `TextInput` pass is pending.
- The window polls the daemon's row model every 2.5 s while the devices
  page is rendered (`AppState::start_presence_ticks`), reconciling
  `ConnectState` against authoritative rows (`ConnectionStore::
  reconcile_with_rows`): a phone-initiated connect or a stale-marked
  session settles on-screen within one poll, in Direct and Attach modes.
- The QR pairing payload awaits the real pairing lane (`get_pairing_qr_code`
  is mock-filled and audited).

## 11. REPL element-click driver

Every user-facing button shares one stable id (`src/ui/views.rs::element`)
between the real GPUI tree (`.id(...)`) and the line REPL:

```
$ echo 'click card-disconnect:192-168-0-100' | nc 127.0.0.1 14321
$ echo 'click confirm'                    | nc 127.0.0.1 14321
```

Ids: `device-connect:<wall-index-or-device-id>`, `card-disconnect:…`,
`menu-delete:…`, `card-more:…`, plus `confirm`/`cancel` (also the dialog's
`{kind}-confirm`/`{kind}-cancel` forms). Clicks queue in sdpd
(`Command::UiClick`) and drain on the presence tick
(`AppState::drain_ui_clicks`), invoking the very handlers the on-screen
buttons call — `request_connect`, `request_disconnect` (+ vendor confirm
dialog), `request_remove_device`, `toggle_more_menu`. Log lines:
`[cmd] ui click queued …` then `[ui] click … (repl)`.
