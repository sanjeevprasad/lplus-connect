# O+ Connect PC (Electron) → Linux port

Sources: `../winzip/resources/app.asar` (O+Connect
17.100.10 Windows build, extracted to `vendor/` here), second source
`../mac/O+Connect.app` (paths relative to this crate).

**Workspace, one shipped binary**: the product is `cargo run` from this
crate: the daemon plus the loopback contract server:

| Member | Role |
| --- | --- |
| `ipc/` (`lplus-ipc`) | the backend contract: `protos/lplus.proto` — `service Lplusd` with one rpc per capability (ping, device wall, connect/disconnect/remove, identity, pairing, probes, event ring, status, cast/ODMF/KMS, sink list/inject, screencast frames), **strictly typed — no JSON carriers**, served as gRPC (`service Lplusd` over tonic/HTTP/2) on `127.0.0.1:1421`; also `Device`, the internal channel structs (`api`, the vendor phone-JSON seam), the event ring and the live-frame bus |
| `lplusd/` (`lplusd`) | phone stack + loopback backend: `scp/scpc/rpc`, `odmf_pc/rtsp`, `d2d`, the service lanes (`lplusd/src/svc/{mod,epi,sdp,scp_server,events,kms,wfd}.rs` — SDP/UNI responder, SCP session server, EPI datatrans, KMS, WFD sink, events bridge) and the contract implementation (`lplusd/src/svc/contract.rs`), plus the backend orchestration (`lplusd/src/backend/{api,cast,devices,ipc}.rs`) |
| `.` (`lplus`) | the wiring: the product binary — preflight, then the service graph + contract server (`cargo run`) |
| `proto/` | the separate phone↔PC wire contract |

`cargo run` starts the backend **in-process** and serves the contract
server (gRPC/HTTP/2 via tonic on `127.0.0.1:1421`) — the sole
machine-facing lane for control clients and automation. The legacy
`loopback/pair/connect/sdpd/ble` subcommands stay for dev/CI.

**Status: backend + contract server ship; the GPUI window port (`ui/`,
`gpui-kit`) was removed 2026-11 (rendered sluggish on this stack).** The
default entry (`cargo run`) starts the daemon + contract server in one
process; control clients drive everything through the contract (§10).
The vendored
`vendor/renderer/index.html` bundle (Vue 3.5 + Element Plus + vue-router +
vuex + vue-i18n) is no longer served or booted — the in-page Electron-era
shim (`shim.js`) was removed together with the browser path. The bundle
stays in the tree as the behaviour reference: its `.js.map` sources drive
the port's screens, channel names and response shapes — and the typed
contract messages mirror those shapes. Control clients reach the daemon
through the contract server (`lplus_ipc::pb` generated gRPC stubs, one rpc per
connection; see §10); there is no other in-process seam.

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
| `ipcMain` side | the contract server (`lplusd/src/svc/contract.rs`, gRPC on 127.0.0.1:1421) is the only control entry point; the webview-era channel registry in `lplusd/src/backend/ipc.rs` was cut with the parked window (the module now owns only the `settings.json` identity blob) |
| Renderer bus (`ipc_main_event`) | the bus arm left with the window; `GUI_BUS` today carries `devices::tick` row pushes. The ring keeps its `bus`/`log` event variants in the schema (`PollEvents`) for the revived renderer's producers |
| Console mirror | `lplus_ipc::push_log_event` records mirrored renderer logs; the producer (the webview console bridge) returns with the window |
| Reference bundle | `vendor/renderer` is served nowhere; the `.html`/`.js`/`.css` keep the historical `app://`→`/` rewrite so RE diffs against the asar stay line-aligned |
| Locale | The port authors English strings; the bundle's bundled zh packs remain as reference data |
| UI transports | the window speaks the contract server's typed rpcs over the generated gRPC client (tonic channel on 127.0.0.1:1421) instead of the deleted in-process dispatcher registry |

## 3. Vendor channel reference (the old `ipc_invoke` surface)

Every capability these webview channels served now lives on the contract
as a typed rpc (§10); the JSON channel layer they rode in on was cut with
the parked window. The table remains as vendor RE reference — `Status`
marks what the daemon serves, `Answer` is the vendor JSON shape the phone
and the future renderer speak, and `__unhandled` rows are daemon-side gaps
to add as new rpcs.

| Channel (value as sent) | Status | Answer |
|---|---|---|
| `generic_agent_get_paired_devices` | implemented | `{ok:true,entries,devices,pairedDevices}` from the daemon-backed device model |
| `generic_agent_settings_remove_device` | implemented | `{device_id,removeStateDir}` → `{ok}` (rows actually removed); block-set in `unpaired.json` |
| `generic_agent_get_local_device_id` | implemented | PC device id (OS-native machine id via `machine-uid`) |
| `generic_agent_get_cloud_bind` | implemented | `{ok:true,bound:false}` |
| `generic_agent_ensure_running` | implemented | `{ok:true,status:'idle'}` |
| `get_current_connected_device_info_list` | implemented | connected rows of the device model |
| `lplus_sidecar_status` | implemented | `{running,logTailing}` (in-process backend liveness; `logTailing:"in-process backend"`) |
| `connect_device` / `disconnect_device` | implemented | queues `svc::epi::Command::{Connect,Disconnect}{ip}` on the EPI command bus (`{ok,ip}`; `ok:false` when the bus has no subscribers) |
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

### 3.1 Device model (`lplusd/src/backend/devices.rs`)

```
lplus backend (in-process, same binary)
  sdpd::run(SdpdConfig csp 10152) on the backend runtime
  + KMS :36863 · events bridge :14752 · EPI lanes · contract server :1421
  DeviceEvent{kind,ip,name,connected,ts_ms}  tokio broadcast
    ├─ subscribe_devices() ───────────►   presence logger mirrors the
    │                                      events to stdout
    └─ LPLUS_EVENTS_PORT=<p[,p…]> ────►   reconnection NDJSON subscribers
                                          (dev aid: follow an external
                                          daemon's bridge)
                        │
                        ▼
        rows {deviceId,deviceName,ip,isDiscovered,isConnected,…}
        ├── ListDevices rpc ────────► control clients (prost Devices)
        ├── event ring ───────────────► PollEvents (presence/bus/log)
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
- The backend runs in the **same process** (`sdpd::run`). Every daemon
  knob is a compiled-in default in the per-service config sections
  (`lplusd/src/config/` bundle + `ScpConfig`/`LinkConfig` in `svc/sdp.rs`,
  `EpiConfig` in `svc/epi.rs`, `KmsConfig` in `svc/kms.rs`, `DatabusConfig`
  /`DialConfig` in `scpc.rs`, `EventsConfig` in `svc/events.rs`,
  `AutolinkConfig` in `svc/autolink.rs`); the environment only overrides
  (keys documented on each field, read once at startup) and
  `settings.json` supplies pairing material (`scpKsc`→KSC pin,
  `linkKpd`). CLI `--name/--csp/--vip` override `SdpdConfig`.
  Excluded by design: `RUST_LOG`, `LPLUS_STATE_DIR`, `LPLUS_USB=1` (adb/USB lane),
  `ODMF_*`/`RTSP*` (mirror/video dev harnesses). Non-defaulted knobs: `LPLUS_USB=1` re-enables the adb/USB device lane
  (hidden by default: Wi-Fi-only device lists; paired bonds stay persisted
  either way); `ODMF_LIVE=1` pipes decoded mirror frames to the in-window
  live preview (`ODMF_PLAYER`/`ODMF_FFMPEG` override the players), and
  `ODMF_LISTEN`/`ODMF_RTP_PORT` move the mirror RTSP/RTP endpoints;
  `LINKPUB` replaces the auto-built `LinkInfoPayload` blob (hex) that the
  LinkSwitchMgr `SERVICE-PUBLISH` carries, `LINKNS` pins the published
  service id instead of rotating candidates.
  Before the backend starts, `preflight_or_die` bind-checks every port the
  daemon takes (csp family, datatrans lanes, UDP 10150/10151, contract server, bridge)
  and **fails loudly** naming each port and the holder (`ss -ltnp` /
  `ss -lunp` lines), never deferring: only one `lplus` owns the network
  stack. A backend bind failure after preflight also exits non-zero.
- Rows are consumed verbatim by the contract server's `ListDevices` rpc:
  `protcol_device_id` keeps the renderer's typo and the row shape matches
  the vendor `devicesList` electron-store entry, so attach clients see the
  same JSON mydevice used to render its cards from. The wall re-pulls on a
  2 s timer (event-push refresh in §6 replaces it).
- `devices.rs` unit tests cover: scp_sync mints the named row, epi/kms flip
  `connected`, unclassified kinds never mint rows (noisy neighbour), per-ip
  dedupe, host-side filtering, model-name preference, adb upsert/prune, and
  TTL pruning with the paired exemption (`cargo test`).

Device actions round-trip through the EPI command bus: the
renderer's Connect/Disconnect lane (and the `connect_device` /
`disconnect_device` channels) queue
`svc::epi::Command::{Connect,Disconnect,KmsBootstrap,RpcConnect,SendFrame}`;
`Epi::spawn_runner` executes them — LAN SCP dial (`scpc::dial_connect`),
the PC-dialed EPI client (`scpc::dial_epi`, which lets a paired device be
connected from the PC side without a phone tap; PROTOCOL.md §7.11), and
DataBus pushes onto the live :46888 sinks.

## 4. Verification reference

- Boot (`./target/debug/lplus`): the log shows
  `[gui] serving contract server 127.0.0.1:1421 (grpc:
  lplus.backend.v1.Lplusd)`, `[kms] listening :36863`,
  `[events] NDJSON bridge :14752`,
  `sdpd up: :10150 (mcast 239.255.255.250) :10151 (uni)
  tcp[10152,10153,10151,10150,46888,47888,48888]`; every capability is
  driven through the gRPC contract (§10).
- Event-fed device rows: with the backend live, the row table reports
  the paired rows (`deviceName CPH2745`, `isConnected true`) while the log
  shows `[presence] event kind=scp_sync …` / `kind=epi …` lines.
  Unclassified events (neighbour SSDP/probe noise) and
  the PC's own VIP stay out of the list (visibility rules in §3.1).
- Loud port conflict: startup against a machine where a foreign process
  holds the stack exits non-zero naming every port plus the holder's
  `ss -ltnp` line, preflighting csp family, datatrans lanes, UDP
  10150/10151, the contract server and the events bridge.

## 5. Runbook

```sh
cd oneplus/linux-client    # from the repo root (the dir holding this document)
cargo run                       # daemon + contract server
cargo run -- daemon             # headless backend, stdout logs
cargo run -- panel              # same as default (backend + contract server)
./target/debug/lplus --csp 10152          # name from settings.json/hostname, vip auto-detected
./connect.sh <resp> <linkpub-hex>   # one scripted connect attempt (restarts sdpd, taps phone, waits on markers)
./waitlex.sh <ERE> [timeout_s]      # block until regex appears in the live taplog (TAPLOG override honored)
# contract: gRPC (HTTP/2) to 127.0.0.1:1421, service lplus.backend.v1.Lplusd
#   (grpcurl reachable; §10 shows the invocations)
```

`lplus` is **the** daemon: default csp 10152, EPI lanes (46888/47888/48888),
KMS (default-on; `KMS_PORT=36863` base, `KMS_PWD=lplus-kms-pw`; bootstrap rotates
`kms_socket_port` over `KMS_PORT`..+`KMS_PORT_ROT`, one listener per port),
boot auto-link (after services start the daemon dials whoever is
broadcasting sdp/1 **and** whose `PDID` matches a bond — no IPs are stored
as dial targets, so a DHCP-renumbered phone re-links on its next announce
round; idle phones go SDP-quiet until their accessory service wakes;
`AUTO_CONNECT=0` to disable, `AUTO_CONNECT_INTERVAL` seconds for cadence),
presence NDJSON bridge
(`LPLUS_EVENTS_PORT=14752`), the contract server (:1421), SCP_*/LINK_*
quickstart table (all values compiled in as config defaults; export any
documented key to override at launch, e.g. `ODMF_RTP_PORT=15550` for the
mirror lane). If a foreign process holds any of those ports, startup fails
loudly naming port + holder (`ss -ltnp`), so exactly one `lplus` owns the
network stack. Presence follows external bridges only via
`LPLUS_EVENTS_PORT=port[,port…]` (dev aid). Persistent state —
`paired.json`, `unpaired.json`, `settings.json` (host name, pinned
beacon `name`, pairing material `scpKsc`/`linkKpd` — read directly by the
config loader) — lives in the
platform config dir (`~/.config/lplus` on XDG; `directories` crate),
override with `LPLUS_STATE_DIR`; files left in the capture out dir are
copied over once on first use.

## 6. Next steps

1. Connect flow: the Connect/Disconnect actions and `connect_device` /
   `disconnect_device` channels are wired to
   `svc::epi::Command::{Connect,Disconnect}` — the PC-dialed EPI client
   establishes the session on a paired-idle phone (PROTOCOL.md §7.11);
   remaining: flip the phone UI without a phone-side tap (sealed DbsMessage
   routing, §7.11 open) and drive `KmsBootstrap` / `SendFrame` from UI
   actions as the lanes mature.
2. Work the audit ring (`ipc_registry`) list above as lanes land; every
   implemented channel = one `route_invoke`/`route_bus` arm.
3. Typed daemon config: landed — nested per-service config structs
   (`Arc`-shared, loaded once, owned by `Sdp`/clients/services); env keys
   remain compat overrides; `settings.json` supplies pairing material.
4. Bundle step (deb/appimage), icons/branding.


## 7. Vendor parity (measured, not guessed)

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

## 8. Route coverage

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

## 9. Known gaps / honest stubs

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

## 10. Control-client contract (gRPC)

The API surface is `service Lplusd` in `ipc/protos/lplus.proto`
(`lplus.backend.v1`) — one rpc per capability, each with its own
request/response message, served by tonic as standard gRPC (HTTP/2) on
`127.0.0.1:1421`: any gRPC client (or `grpcurl`) reaches the identical
contract the window uses. The server's dispatch table is test-enforced
complete against the descriptor-extracted `pb::SERVICE_METHODS`, so the
`service` block is the single source of truth; handler failures surface
as gRPC `internal` statuses with the message intact.

Rpcs: `Ping`, `ListDevices`, `Connect`/`Disconnect`/`RemoveDevice`,
`GetHostName`/`SetHostName`, `GetPairedDevices`, `GetLocalDeviceId`,
`EnsureRunning`, `GetCloudBind`, `SidecarStatus`, `PollEvents` (drains the
ring: `sdpd::emit_device` presence today; `bus`/`log` variants return with
the renderer), `Status`, `CastPush`, `OdmfStart`, `KmsBootstrap`,
`SinkList`/`InjectFrame` (raw frames onto live EPI/KMS sessions, no
re-handshake), `RequestLive`/`TakeFrame` (JPEG screencast). Nothing speaks
JSON: handlers project the internal `api` shapes onto protobuf at the
boundary, and an rpc missing from the table is a compile-time schema bug,
not a runtime `{ok:false,__unhandled}`.

```sh
# plain-text gRPC, no reflection — schema comes from the proto
grpcurl -plaintext -import-path ipc/protos -proto lplus.proto \
  -d '{}' 127.0.0.1:1421 lplus.backend.v1.Lplusd/Ping
grpcurl -plaintext -import-path ipc/protos -proto lplus.proto \
  -d '{"sinceSeq":0}' 127.0.0.1:1421 lplus.backend.v1.Lplusd/PollEvents
```

