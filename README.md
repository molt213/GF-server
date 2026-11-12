# GF-server resources

Storage for the Android server APK's game resource volumes.

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
/data/data/<pkg>/files/gfserver/data/cdn/android3060/
```

Volumes are deleted after a successful extraction.
