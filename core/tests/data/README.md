# tests/data — QCOW2 Real-Image Corpus

Integration test fixtures and fuzz seed corpus.
`fuzz/corpus/fuzz_open/` symlinks here; files are not duplicated.

## Files

### cirros-0.6.3-x86_64-disk.img

| Field       | Value |
|-------------|-------|
| Format      | QCOW2 v3 (compat 1.1), zlib compression |
| Virtual size | 112 MiB |
| On-disk size | 20.7 MiB |
| Source      | https://download.cirros-cloud.net/0.6.3/cirros-0.6.3-x86_64-disk.img |
| License     | Apache 2.0 (CirrOS project) |
| SHA-256     | run `shasum -a 256 cirros-0.6.3-x86_64-disk.img` to verify |

CirrOS is a minimal Linux distribution purpose-built for cloud/QEMU testing.
This is the official 0.6.3 release image, unmodified.

## Regenerating

```sh
curl -L -o tests/data/cirros-0.6.3-x86_64-disk.img \
  https://download.cirros-cloud.net/0.6.3/cirros-0.6.3-x86_64-disk.img
```
