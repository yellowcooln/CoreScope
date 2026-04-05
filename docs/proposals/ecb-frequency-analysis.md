# Security Analysis: AES-128-ECB in MeshCore Channel Encryption

## Scope

This analysis covers GRP_TXT (channel/group messages) as the primary subject. Section 7 extends the analysis to TXT_MSG (direct messages). All claims are derived from firmware source (`BaseChatMesh.cpp`, `Utils.cpp`, `Mesh.cpp`, `MeshCore.h`) unless explicitly marked as conjecture.

## 1. How Encryption Works

### Constants (from `MeshCore.h`)
- `CIPHER_KEY_SIZE = 16` (AES-128)
- `PUB_KEY_SIZE = 32`
- `CIPHER_MAC_SIZE` = HMAC-SHA256 truncated output size

### encrypt() (from `Utils.cpp`)
AES-128-ECB, block-by-block. No IV, no counter, no chaining:
```cpp
aes.setKey(shared_secret, CIPHER_KEY_SIZE);  // first 16 bytes of shared_secret
while (src_len >= 16) {
    aes.encryptBlock(dp, src);  // each 16-byte block independently
    dp += 16; src += 16; src_len -= 16;
}
if (src_len > 0) {  // partial final block
    uint8_t tmp[16];
    memset(tmp, 0, 16);   // zero-fill
    memcpy(tmp, src, src_len);  // copy remaining bytes
    aes.encryptBlock(dp, tmp);
}
```

### encryptThenMAC() (from `Utils.cpp`)
```cpp
int enc_len = encrypt(shared_secret, dest + CIPHER_MAC_SIZE, src, src_len);
SHA256 sha;
sha.resetHMAC(shared_secret, PUB_KEY_SIZE);   // HMAC uses full 32 bytes
sha.update(dest + CIPHER_MAC_SIZE, enc_len);
sha.finalizeHMAC(shared_secret, PUB_KEY_SIZE, dest, CIPHER_MAC_SIZE);
```

**Key reuse flaw:** The same `shared_secret` buffer serves both AES and HMAC. AES uses `shared_secret[0..15]` (first 16 bytes). HMAC uses `shared_secret[0..31]` (full 32 bytes). The AES key is a prefix of the HMAC key. See §6 for implications.

### GRP_TXT Plaintext Construction (from `BaseChatMesh::sendGroupMessage()`)

```cpp
memcpy(temp, &timestamp, 4);          // bytes 0-3: Unix timestamp (seconds)
temp[4] = 0;                           // byte 4: TXT_TYPE_PLAIN
sprintf((char *)&temp[5], "%s: ", sender_name);  // bytes 5+: "SenderName: "
char *ep = strchr((char *)&temp[5], 0);
int prefix_len = ep - (char *)&temp[5];           // length of "SenderName: "
memcpy(ep, text, text_len);            // message text (no null terminator)
ep[text_len] = 0;                      // null written AFTER data boundary
// data_len passed to encrypt = 5 + prefix_len + text_len
```

**The null terminator is NOT part of the encrypted data length.** The call to `createGroupDatagram` passes length `5 + prefix_len + text_len`. The null at `ep[text_len]` is written to the buffer but is beyond `data_len`. In the final partial block, `encrypt()` zero-fills with `memset(tmp, 0, 16)` before copying the remaining bytes — so a zero byte appears at the position where the null would be, but this is an artifact of zero-padding, not an explicit null in the plaintext.

On the receiving side, this is confirmed:
```cpp
data[len] = 0; // need to make a C string again, with null terminator
```
The receiver must re-add the null after decryption.

## 2. Block Layout Analysis

### Notation

Let `N` = length of sender name. Then:
- `prefix_len` = N + 2 (for ": " suffix from `sprintf("%s: ", sender_name)`)
- Header overhead = 4 (timestamp) + 1 (type) + prefix_len = N + 7 bytes
- Message text begins at byte offset N + 7

### Block 0

Block 0 = bytes 0–15 of plaintext:
```
[TS₀][TS₁][TS₂][TS₃][0x00][sender_name: ][...message start...]
```

The first 9 − N bytes of message text fit in block 0 (when N < 9). For N ≥ 9, no message text fits in block 0.

### Boundary Condition: Sender Name ≥ 12 Characters

When N ≥ 12, the header overhead (N + 7 ≥ 19) exceeds 16 bytes. The header itself spills into block 1:

**Example: sender name "LongUserName1" (N = 13), message "hi":**
```
Header = 13 + 7 = 20 bytes. Total plaintext = 20 + 2 = 22 bytes.

Block 0 (bytes 0-15):  [TS₀][TS₁][TS₂][TS₃][0x00][L][o][n][g][U][s][e][r][N][a][m]
Block 1 (bytes 16-31): [e][1][:][space][h][i][0x00 ×10]  ← zero-padded partial block
```

Block 1 here contains the tail of the sender name, the ": " separator, message text, AND zero-padding. For sender names of length 12–15, block 1 is a mix of header and message — **it is NOT "pure message text."**

For sender names ≥ 16, blocks 0 and 1 are both pure header, and message text doesn't begin until block 1 or later.

### General Block Content Table

| Sender name length N | Header bytes | Message starts at byte | Block 0 content | Block 1+ content |
|---|---|---|---|---|
| 1–8 | 8–15 | 8–15 | timestamp + header + message start | message text + zero-pad |
| 9–11 | 16–18 | 16–18 | timestamp + header (no message) | header tail + message + zero-pad |
| 12–15 | 19–22 | 19–22 | timestamp + partial header | header tail + message + zero-pad |
| ≥16 | ≥23 | ≥23 | timestamp + partial header | header continuation, then message |

### Typical Case (N = 5, e.g. "Alice")

Header = 12 bytes. Message starts at byte 12. Block 0 holds 4 bytes of message text.

```
Message "hello world" (11 chars). Total plaintext = 12 + 11 = 23 bytes.

Block 0 (bytes 0-15):  [TS₀][TS₁][TS₂][TS₃][0x00][A][l][i][c][e][:][space][h][e][l][l]
Block 1 (bytes 16-22): [o][space][w][o][r][l][d] → padded to: [o][space][w][o][r][l][d][0×9]
```

Block 1 contains 7 bytes of message text and 9 bytes of zero-padding.

## 3. Attack Surface by Block Position

### Block 0: Accidental Nonce from Timestamp

The 4-byte Unix timestamp in bytes 0–3 acts as an **accidental nonce** — it was included "mostly as an extra blob to help make packet_hash unique" (per firmware comment), not as a cryptographic countermeasure against ECB determinism. Nevertheless, it has the effect of making block 0's plaintext vary per message.

**Precision on uniqueness:** Block 0 is unique per (sender, timestamp-second) pair, not per message. Two messages from the same sender within the same second, on the same channel, with the same type byte, produce identical block 0 plaintext and therefore identical block 0 ciphertext. At typical mesh chat rates, same-second collisions are rare but not impossible for automated/scripted senders.

**Known-plaintext observation:** Bytes 4–15 of block 0 are largely predictable per sender (type byte is always 0x00 for plain text; sender name and ": " are static). The timestamp is predictable within a window (Unix seconds). An attacker who knows the sender name and approximate time can compute all 16 plaintext bytes of block 0. However, **AES-128 is resistant to known-plaintext attacks** — knowing plaintext-ciphertext pairs for block 0 does not help recover the key or decrypt other blocks.

### Blocks 1+: Deterministic ECB (for short sender names)

When the sender name is short enough that the header fits in block 0 (N ≤ 8), blocks 1+ contain **only message text and zero-padding.** No timestamp, no nonce, no per-message varying data. Identical message text at the same block offset produces identical ciphertext, always.

When N ≥ 9, block 1 contains header spillover, which includes static sender name bytes — these vary per sender but not per message, so block 1 is still deterministic for a given sender once the header portion is fixed.

**The fundamental ECB property:** For any block beyond the timestamp's reach, `E_K(P) = E_K(P)`. Same plaintext block → same ciphertext block, regardless of when or how many times it's sent.

### Partial Final Block: Strongest Attack Target

The final block of every message is zero-padded by `encrypt()` to 16 bytes. The padding bytes are deterministic and known (always 0x00). For a message whose final block contains `B` bytes of actual content:

- `B` bytes are unknown message text
- `16 - B` bytes are known zeros

When B is small (short final fragment), most of the block is known plaintext. For B = 1, the attacker knows 15 of 16 bytes — only 256 possible plaintext blocks exist. This means:

- **The final block has at most 2^(8B) possible plaintexts** (versus 2^128 for a full unknown block)
- For B ≤ 4, there are ≤ 2^32 possibilities — a small enough space for dictionary attacks given enough ciphertext samples
- The attacker can precompute all possible final-block plaintexts for small B values and match against observed ciphertext blocks

This makes the partial final block a **stronger frequency analysis target** than interior blocks, where all 16 bytes may be unknown text.

## 4. Feasible Attack Scenarios

### 4.1 Block Frequency Analysis on Blocks 1+

**Preconditions (all must hold):**
1. Attacker can observe encrypted GRP_TXT packets (passive radio capture)
2. Messages from the same sender (or senders with identical name lengths — same block alignment)
3. Messages long enough to produce blocks beyond block 0 (text > 9 − N chars)
4. Sufficient message volume with repeated content at the same block positions

**Method:**
1. Collect GRP_TXT packets, group by sender hash
2. Decompose encrypted payloads into 16-byte blocks (after stripping HMAC prefix)
3. Discard block 0 (timestamp-varying)
4. Build frequency tables for blocks 1, 2, 3, etc., per sender
5. Match high-frequency ciphertext blocks against expected plaintext distributions

**Practical constraints limiting this attack:**
- LoRa bandwidth severely limits message length. Most mesh chat messages are short — many fit entirely within block 0 (≤ 9 − N chars of text), yielding zero analyzable blocks.
- Messages that spill into block 1+ tend to be longer and more varied — fewer repeated patterns.
- The attack requires repeated identical 16-byte-aligned text fragments from the same sender over time.

**Conditions under which this attack succeeds:** Automated or scripted senders transmitting repetitive messages longer than block 0 capacity, on a channel with a static PSK, over an extended collection period. For human-typed conversational messages with typical length and variety, the number of repeated block 1+ patterns is likely too low for meaningful frequency analysis. (This is an empirical claim that depends on actual traffic patterns — no formal bound is established here.)

### 4.2 Partial Final Block Dictionary Attack

**Preconditions:**
1. Attacker knows (or can estimate) the message length modulo 16
2. Final block has few content bytes (B ≤ 4)

**Method:** Enumerate all 2^(8B) candidate plaintexts for the final block. Since AES-ECB is deterministic with a fixed key, the attacker can build a lookup table: if they ever observe a ciphertext block matching one of the candidates in a known-plaintext scenario (e.g., from a leaked or guessed message), they can identify which final-block value corresponds to which ciphertext.

**Limitation:** Without the key, the attacker cannot compute E_K(candidate) directly. The attack requires collecting enough ciphertext final blocks to perform frequency analysis within the reduced plaintext space. With only 256 possibilities (B=1), convergence is fast given sufficient samples.

### 4.3 Cross-Sender Correlation

Senders with identical name lengths produce identical block alignments. Messages from "Alice" (N=5) and "Bobby" (N=5) place message text at the same byte offsets. If both send the same message, their blocks 1+ are identical ciphertext — **but only if they share the same channel PSK** (same AES key). On the same channel, this enables cross-sender frequency analysis within same-name-length groups.

### 4.4 Message Length Leakage

Ciphertext length = ⌈(5 + prefix_len + text_len) / 16⌉ × 16 bytes. This reveals the message text length within a 16-byte window (not 15, because the block count is the observable quantity). Not ECB-specific — any block cipher without constant-length padding leaks this.

### 4.5 Replay Attacks

`encryptThenMAC()` authenticates the ciphertext, but if the mesh doesn't track previously-seen packet MACs, captured packets can be replayed. The embedded timestamp may be checked for staleness — this requires firmware verification beyond the scope of this analysis.

### 4.6 No Forward Secrecy

Channel PSKs are static and shared among all participants. ECDH shared secrets for direct messages are also static (no ephemeral key exchange). Compromise of any key decrypts all past and future traffic encrypted under that key.

## 5. What Known-Plaintext Does NOT Achieve

AES-128 is designed to resist known-plaintext attacks. An attacker who knows the full plaintext and ciphertext of block 0 (or any block) **cannot**:
- Recover the AES key
- Decrypt other blocks encrypted under the same key
- Derive any information about other plaintexts from their ciphertexts

The ECB weakness is **determinism** (identical plaintext → identical ciphertext), not key recovery. The attacks in §4 exploit pattern matching and frequency analysis, not cryptanalysis of AES itself.

## 6. HMAC Key Reuse: Cryptographic Design Flaw

From `encryptThenMAC()`:
- AES key: `shared_secret[0..15]` (CIPHER_KEY_SIZE = 16)
- HMAC key: `shared_secret[0..31]` (PUB_KEY_SIZE = 32)

The AES key is the first half of the HMAC key. Both are derived from the same `shared_secret` — for channels, this is the PSK; for direct messages, the ECDH shared secret.

**Why this matters:**
1. **Violated key separation principle.** Standard practice dictates that encryption and authentication keys must be independent. Using overlapping portions of the same secret means a weakness in one mechanism could leak information relevant to the other.
2. **HMAC key reveals AES key.** If an attacker recovers the 32-byte HMAC key (e.g., through a side-channel attack on the HMAC computation), they automatically obtain the 16-byte AES key as a prefix.
3. **No key derivation function.** The shared_secret is used directly — no HKDF or similar KDF is applied to derive independent subkeys. This is a departure from cryptographic best practice (cf. RFC 5869).

**Practical impact:** In the current threat model (passive radio capture of LoRa packets), this is unlikely to be directly exploitable — HMAC-SHA256 does not leak its key through normal operation. However, it represents a structural weakness that compounds with any future vulnerability in either the AES or HMAC implementation.

## 7. TXT_MSG (Direct Message) Block Layout

Direct messages use a different plaintext structure (from `BaseChatMesh::composeMsgPacket()`):

```cpp
memcpy(temp, &timestamp, 4);          // bytes 0-3: timestamp
temp[4] = (attempt & 3);               // byte 4: attempt counter (0-3)
memcpy(&temp[5], text, text_len + 1);  // bytes 5+: message text
// data_len = 5 + text_len (null terminator copied but not counted in length)
```

**Block layout for TXT_MSG:**
```
Block 0: [TS₀][TS₁][TS₂][TS₃][attempt][text bytes 0-10]
Block 1: [text bytes 11-26] (if message long enough)
```

Key differences from GRP_TXT:
- **No sender name in plaintext** — the sender is identified by the source hash in the unencrypted packet header, not in the encrypted payload.
- **Header is exactly 5 bytes** (4 timestamp + 1 attempt), always. No variable-length field.
- **11 bytes of message text fit in block 0** (vs. 9 − N for GRP_TXT).
- **Encrypted with per-pair ECDH shared secret**, not a group PSK. Each sender-recipient pair has a unique key.

**ECB implications for TXT_MSG:**
- Block 0 is still protected by the timestamp accidental nonce.
- Blocks 1+ are deterministic, same as GRP_TXT — identical message text at the same offset produces identical ciphertext.
- However, frequency analysis is harder: each sender-recipient pair uses a different key, so the attacker can only correlate messages within a single pair. The message volume for any given pair is typically much lower than for a group channel.
- The fixed 5-byte header means block alignment is consistent across ALL direct messages (unlike GRP_TXT where alignment varies by sender name length). An attacker who compromises one ECDH key can build block frequency tables, but only for that specific pair.

## 8. Mitigations

### Priority 1: Switch to AES-128-CTR

Replace ECB with CTR mode. Use the existing 4-byte timestamp + a 4-byte per-message counter as the 8-byte nonce (padded to 16 bytes for the CTR block). Each byte of plaintext gets XORed with a unique keystream byte — eliminates all block-level determinism.

**Wire format change:** None if the nonce is derived from header fields already present. If an explicit counter is added, 4 bytes of overhead per message.

### Priority 2: Derive Independent Subkeys

Apply HKDF (or at minimum, two distinct SHA-256 hashes) to the shared_secret to produce independent AES and HMAC keys. This is a minimal code change:
```
aes_key = SHA256(shared_secret || "encrypt")[0..15]
hmac_key = SHA256(shared_secret || "authenticate")
```

### Priority 3: Constant-Length Padding

Pad all messages to a fixed block count (e.g., 4 blocks = 64 bytes) to eliminate length leakage. Expensive on LoRa — should be configurable per channel as a security-vs-bandwidth tradeoff.

### Priority 4: Replay Protection

Track seen packet HMACs within a time window. Reject messages with timestamps older than N minutes.

### Priority 5: Channel Key Rotation

Manual or automated periodic rotation of channel PSKs. Even monthly rotation limits the exposure window.

### Priority 6: Forward Secrecy

Ephemeral ECDH for direct messages. Significant protocol change but prevents retroactive decryption on key compromise.

## 9. Speculative: LLM-Assisted Analysis

> **This section is speculation, not formal analysis.** The claims below are plausible but unvalidated. They do not affect the formal findings in §1–8.

An LLM could reduce the sample size needed for block frequency analysis:

1. **Context-aware candidate generation:** Given a sender's known patterns (the sender name is recoverable from block 0's predictable prefix), an LLM could generate likely message continuations and predict which plaintext blocks to look for in the frequency tables.
2. **Conversational inference:** Timestamps + sender IDs + partially decoded messages could let an LLM reconstruct probable conversation flow, narrowing the search space for unknown blocks.
3. **Community-specific vocabulary:** Training on public mesh chat logs could yield common phrases and greeting patterns, further reducing the candidate plaintext space.

This does not change the fundamental requirement (blocks 1+ must repeat, or the final block must be in a small enough space for dictionary matching). It potentially reduces the number of captured messages needed for convergence, but no quantitative bound is established.

## 10. Conclusion

MeshCore's AES-128-ECB encryption has three structural weaknesses:

1. **Blocks beyond the timestamp's reach are deterministic.** Identical plaintext at the same block offset always produces identical ciphertext. For GRP_TXT messages longer than ~9 − N characters (where N is sender name length), this enables frequency analysis on blocks 1+. The partial final block, with its known zero-padding, is the strongest individual target.

2. **AES and HMAC share the same key material** without a key derivation function. The AES key is a prefix of the HMAC key. This violates key separation and creates a structural dependency between the encryption and authentication mechanisms.

3. **No forward secrecy, no key rotation, no replay protection.** These are independent of ECB but compound the risk: a single key compromise exposes all traffic, past and future.

**Severity assessment:**
- For short conversational messages that fit in block 0: **low risk** — the timestamp accidental nonce prevents block repetition
- For repetitive messages exceeding block 0 capacity from the same sender on a static-PSK channel: **medium risk** — frequency analysis on blocks 1+ and the partial final block is viable given sufficient traffic volume (order of magnitude: hundreds of messages with repeated content; precise threshold depends on traffic patterns and is not formally established)
- For automated/scripted senders with predictable content: **elevated risk** — the combination of known block alignment, predictable content, and high volume makes frequency analysis practical

The timestamp in block 0 was not designed as a nonce and should not be relied upon as one. Switch to CTR mode.
