# GF-server

Resources and tools for a self-hosted Girls' Frontline (CN) 3.0600_506 server.

| Part | Where |
|---|---|
| Game resources — 11.03 GiB | release [`res-v1`](#res-v1) |
| Two APKs — client + server | release [`apk-v1`](#apk-v1) |
| Save export tool | [`save-export/`](save-export/README.md) |

---

## apk-v1

Both APKs must be installed **on the same Android device** — the client only ever
talks to `127.0.0.1`.

| File | Package | Bytes | SHA-256 |
|---|---|---|---|
| `gf_cn_506_local.apk` | `com.sunborn.girlsfrontline.cn` | 318,403,335 | `c973de25ecd40a7b46b73784c3d9d04db84ecc982676985dc3ce04a1344ecfd5` |
| `app-debug.apk` | `com.gfserver.phone.debug` | 188,725,401 | `6dc3276683b632b1a6b1a10a0440ce858294c75e6eb393596cf3c7b5445c0ab1` |

### Client APK

The official 3.0600_506 client, **re-signed with a local key**. Exactly two things
differ from the official package:

1. `res/xml/network_security_config.xml` also trusts the CA that is bundled inside
   the APK (referenced as an existing resource), so **no certificate needs to be
   installed** on the device.
2. Every server URL in the IL2CPP metadata points at `127.0.0.1`. The port is part
   of the URL (`:8080` / `:8443`) because Android refuses to bind ports below 1024
   for non-root apps. The replacement is length-preserving; overflow is padded with
   a `/moltxxxxxx/` path prefix that the server strips.

Game logic, assets, and the anti-cheat libraries (`libtersafe2.so` / `libtprt.so`)
are byte-for-byte untouched.

Re-signing means a different signature than the official package, so installing it
over an official install requires an uninstall first (which wipes
`Android/data/<pkg>`, i.e. the multi-GB resource cache).

### Server APK

Chaquopy CPython 3.11. Listens on `127.0.0.1:8080` (HTTP) and `127.0.0.1:8443`
(TLS), binds nothing else. `assets/server.zip` is extracted once into the app's
external files directory (`Android/data/com.gfserver.phone.debug/files/gfserver/`).

The bundled player data is a **demo save** — `uid 1000001`, name `指挥官`. Replace
it with your own by importing a `save-<uid>-<yyyymmdd>.gfsave.zip` from the server
app's 「导入存档」 button.

> There is no "new account" bootstrap in the server: `content/player/l1.json` must
> exist, otherwise `Index/index` answers `error:0` and the client cannot get past
> the title screen. That is why a demo save ships inside the APK.

The APK also carries the self-signed CA (certificate + key) used for TLS on
`127.0.0.1:8443`. It is a throwaway, localhost-only anchor that the client APK
above trusts — do not reuse it for anything else.

### Install

```sh
adb install gf_cn_506_local.apk
adb install app-debug.apk
```

Then open **GF 私服** → 启动, and start the game.

### Resources

The APK does **not** contain the 11 GB resource tree. Two ways to get it:

- The server app's resource page can fetch the `res-v1` volumes from GitHub
  (see below) and extract them automatically;
- or push an `android3060/` tree manually into
  `Android/data/com.gfserver.phone.debug/files/gfserver/data/cdn/android3060/`.

---

## save-export

Windows tool that exports a PC inherit-edition account's current progress into a
`save-<uid>-<yyyymmdd>.gfsave.zip` the server app can import. Captures the login
traffic with the built-in `pktmon` and reads the `Index/getUidPC` response — no
request replay, no third-party packages.

See [`save-export/README.md`](save-export/README.md).

---

## res-v1

`android3060` full resource set — **11.03 GiB**, split into 6 tar volumes:

```
res-android3060-part-aa .. res-android3060-part-af
SHA256SUMS.txt
```

Each volume is under 1.9 GB (GitHub caps a release asset at 2 GB).

### How to reassemble

Concatenate `aa` .. `af` **in that order** — the result is a single tar stream:

```sh
cat res-android3060-part-a{a,b,c,d,e,f} | tar -xf -
```

Archive member paths carry **no directory prefix**, so extract into an
`android3060/` directory:

```sh
mkdir -p android3060
tar -xf - -C android3060
```

### Verify

```sh
sha256sum -c SHA256SUMS.txt
```

Each line is `<sha256> *<volume name>`.

### How the server uses it

The server APK (resource page -> "fetch from GitHub") downloads the volumes to a
`<dest>.dl/` cache, verifies each SHA-256, concatenates them into one read-only
stream, and streams the tar into:

```
Android/data/com.gfserver.phone.debug/files/gfserver/data/cdn/android3060/
```

Volumes are deleted after a successful extraction.

---

## Scope

Local research / preservation only. Everything here talks to `127.0.0.1`; it does
not touch, proxy, or impersonate the official service.
