# QCOW2 Implementation Notes

Developer notes capturing format quirks, spec contradictions, and empirically verified
behaviour. Intended for future contributors and as a basis for upstream spec clarifications.

---

## 1. Compressed cluster bit-field layout (spec vs. QEMU source)

**The most dangerous pitfall in QCOW2 implementation.**

### What the spec says

From `docs/interop/qcow2.txt` in the QEMU source tree:

> For compressed clusters:  
> Bits (62 – cluster_bits) .. 0 : Host cluster offset (byte offset)  
> Bits 61 .. (63 – cluster_bits + 1) : Additional 512-byte sectors, minus 1

For cluster_bits = 16 (64 KiB clusters, the default):

| Field | Bit range | Width | Notes |
|-------|-----------|-------|-------|
| Compressed flag | 62 | 1 bit | Must be 1 |
| Compressed sectors − 1 | 61 .. 47 | 15 bits | `nb_sectors - 1` |
| File byte offset | 46 .. 0 | 47 bits | Direct byte offset, **no ×512** |

### What QEMU's C source says (block/qcow2.c)

```c
s->csize_shift = (8 * (sizeof(uint64_t) - sizeof(uint32_t)))
               - (s->cluster_bits - 8);
// = 32 - (cluster_bits - 8) = 40 - cluster_bits
// For cluster_bits=16 → csize_shift = 24

s->cluster_offset_mask = (1LL << s->csize_shift) - 1;
// For cluster_bits=16 → 0xFFFFFF (24-bit mask)

nb_csectors = ((l2_entry >> s->csize_shift) & s->csize_mask) + 1;
coffset     =   l2_entry & s->cluster_offset_mask;
```

This yields `split = 24` for 64 KiB clusters — **contradicting the spec's split = 47**.

### What empirical testing reveals

With a real CirrOS 0.6.3 image (qemu-img, compression type: zlib):

```
L2[0] = 0x4040_0000_0005_0000
```

| Formula | file_offset | nb_sectors | compressed_bytes | Works? |
|---------|-------------|------------|------------------|--------|
| split=47, no ×512 (**spec**) | 327 680 ✓ | 129 (66 048 B) | Yes — deflate stream ends at byte 679 of 66 048 |
| split=24, no ×512 (QEMU C code) | 327 680 ✓ | 1 (512 B) | **No** — stream needs 679 B, 512 too short |
| split=47, ×512 (broken intuition) | 167 772 160 ✗ | — | **No** — past EOF |

**Conclusion:** The spec is correct. The QEMU C formula (`csize_shift = 40 - cluster_bits`)
produces wrong `nb_sectors` for real images, though it may be correct in a different code
path we have not traced. Our implementation uses the spec formula.

### Implementation

```rust
let cluster_bits = self.cluster_size.trailing_zeros(); // u32, in [9, 20]
let split        = 63u32 - cluster_bits;               // = 47 for 64 KiB
let count_mask   = (1u64 << (cluster_bits - 1)) - 1;  // = 0x7FFF for 64 KiB
let file_offset  = l2_entry & ((1u64 << split) - 1);  // byte offset — NO ×512
let nb_sectors   = ((l2_entry >> split) & count_mask) + 1;
let compressed_bytes = (nb_sectors * 512) as usize;
```

### Silent corruption trap

If `file_offset` is past EOF (as with the `×512` bug), `File::read` returns 0 bytes.
`flate2::read::DeflateDecoder::new(&[]).read_to_end(&mut out)` returns `Ok(0)` without
error on empty input, yielding an empty buffer. The `if out.len() < cluster_size` guard
then zero-pads to `cluster_size`. Result: **silent wrong data** — no panic, no error.

Always validate that the decompressed length equals `cluster_size` or return an error.

### Upstream PR opportunity

`docs/interop/qcow2.txt` in QEMU would benefit from an explicit note:

> The host cluster offset is a **byte** offset. Do not multiply by 512.
> The `csize_shift` formula in `block/qcow2.c` partitions the bits differently
> from this spec; readers should verify against real images.

---

## 2. L1/L2 entry bit masking

### L1 table entries

| Bit | Meaning | Must mask? |
|-----|---------|-----------|
| 63 | DIRTY (v3 only) | Yes — mask before using as offset |
| 62..9 | L2 table byte offset | Used directly |
| 8..0 | Reserved (must be 0) | Ignored |

Mask: `l1_entry & 0x7FFF_FFFF_FFFF_FE00` or simply `l1_entry & 0x7FFF_FFFF_FFFF_FFFF`
(the lower 9 bits are always zero because L2 tables are cluster-aligned).

### L2 table entries (uncompressed)

| Bit | Meaning |
|-----|---------|
| 63 | COPIED (cluster owned by this image) |
| 62 | 0 (not compressed) |
| 61..56 | Reserved |
| 55..0 | Host cluster byte offset |

Mask: `l2_entry & 0x3FFF_FFFF_FFFF_FFFF`

If the masked offset is 0, the cluster is unallocated → return zeros.

---

## 3. Backing-file images

This implementation rejects images with a non-zero `backing_file_offset`. Implementing
backing files correctly requires:

- Resolving a relative path against the image's own location
- Handling a chain of backing files (depth can be arbitrary)
- Knowing the virtual size of the overlay vs. the backing image

Unallocated clusters in the overlay must be read from the backing file, not returned as
zeros. Returning zeros for unallocated clusters in a backed image is **silently wrong**.

---

## 4. Extended L2 entries (v3, incompat bit 4)

When `INCOMPAT_EXTL2` (bit 4 of incompatible features) is set, each L2 entry is 128 bits
instead of 64 bits. The extra 64 bits encode per-subcluster allocation and zeroing flags
(32 subclusters per cluster). This implementation rejects such images.

---

## 5. Compression type (v3, incompat bit 3)

`INCOMPAT_COMPRESSION_TYPE` (bit 3) signals that a **non-default** compression algorithm
is in use (currently: zstd). **It is not set for the default zlib/deflate compression.**
Images using default zlib compression have `incompat = 0` for this bit.

This is a common misreading of the spec: the bit does not mean "this image is compressed";
it means "this image uses a non-zlib compressor".

---

## 6. Raw DEFLATE, not zlib

QCOW2 uses raw DEFLATE streams (no zlib header/trailer, `windowBits = -15`). Use
`flate2::read::DeflateDecoder`, not `ZlibDecoder` or `GzDecoder`.

---

## Upstream PR candidates

| Project | File | Suggested change |
|---------|------|-----------------|
| QEMU | `docs/interop/qcow2.txt` | Clarify that compressed cluster host offset is bytes, not sectors; add example for `cluster_bits=16` showing exact bit ranges |
| QEMU | `block/qcow2.c` | Add comment to `csize_shift` explaining the relationship (or discrepancy) with the spec bit layout |
