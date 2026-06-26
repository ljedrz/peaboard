# peaboard

A private bulletin board you run from the terminal — built to
**demonstrate the pea\* stack** end to end.

> [!WARNING]
> **This is a demonstration, not a product.** It exists to show
> how the pea\* crates fit together in the smallest honest amount
> of code. It ships a **hard-coded encryption key** (so anyone
> with the source can read every message), keeps no history
> across restarts, and has had no security review. Do not use it
> for anything you actually want kept private. See
> [Just a demo](#just-a-demo) at the bottom.

```
┌─ peaboard ───────────────────────────────────────────────┐
│ a private bulletin board on the pea* stack — DEMO ONLY   │
└──────────────────────────────────────────────────────────┘
discovery : 127.0.0.1:9000   board : 127.0.0.1:9001
nick      : alice

Boards:
    rust
    privacy
    memes

> /join rust
— now on #rust (0 message(s)) —
[net] peers on the network: 2
[15:45 #b8de5d] bob: has anyone benchmarked locktick?
[15:45 #df4fb8] carol: yep, see message #b8de5d
```

## How the pea\* crates interact

The whole point of this example. Four crates stack up, and each
one does **only** its own job — the layer below never knows what
the layer above is for, and the layer above never re-implements
what the layer below already does:

| Layer | Crate | Job | What it does *not* do |
| --- | --- | --- | --- |
| transport | `pea2pea` | open TCP connections, run protocols | — |
| shaping | `peashape` | pad every frame to one size, emit at a constant rate, fill gaps with cover traffic | decide *what* to send |
| discovery | `peaveil` | gossip peer *addresses*, maintain a "view" of the network | open connections |
| gossip | `peasub` | spread *messages* to the whole overlay, de-dup what it has seen | open connections; encrypt |
| **the app** | **`peaboard`** | connection policy + payload encryption + UI | anything a lower layer already handles |

`peaveil` and `peasub` are siblings: each is an independent
protocol that sits on its *own* `peashape` node (and `peashape`
sits on its own `pea2pea` node). peaboard runs one of each and
bridges them.

### The life of a discovery

How a node that knows only one peer ends up connected to the
whole network:

1. peaboard hands `peaveil` a `bootstrap` address at startup.
   `peaveil` puts it in its view but **does not dial it** —
   opening connections isn't a discovery library's job.
2. peaboard's [reconcile loop](src/main.rs) reads
   `peaveil.known_peers()` and calls `peaveil.connect(addr)`.
   *The application owns the connection.*
3. Now connected, the two `peaveil` nodes gossip address samples
   (shaped by `peashape`, so the exchange is invisible). Each
   learns the peers the other knows.
4. Next reconcile tick, the newly-learned addresses are in
   `known_peers()`, so peaboard dials them too — and bridges each
   onto the board overlay at `addr.port() + 1`. Discovery is
   transitive: bootstrap to one node, reach them all.

### The life of a post

What happens when you type a line and press enter:

1. **peaboard** builds a `Post`, seals it with ChaCha20-Poly1305
   (`proto::seal`), and calls `peasub.publish(sealed)`. The board
   name is *inside* the ciphertext.
2. **peasub** assigns a random 32-byte id, and queues the frame.
3. **peashape** is already emitting a frame on every cover tick.
   On the next tick it sends *your* frame instead of a cover one
   — same size, same timing — to `fanout` connected peers.
4. **pea2pea** writes the bytes to the wire. To an observer they
   are indistinguishable from the cover frames flowing the rest
   of the time.
5. At each peer, **pea2pea** reads the frame, **peasub** de-dups
   it by id, delivers it to subscribers, and re-gossips it to
   *its* peers (so it fans out across the overlay).
6. **peaboard** receives it via `peasub.subscribe()`, calls
   `proto::open`; if it decrypts under the shared key it's a real
   post (cover frames just fail to open), and it's displayed.

```
        peaveil overlay (discovery)            peasub overlay (the board)
   alice:9000 ─ bob:9002 ─ carol:9004     alice:9001 ─ bob:9003 ─ carol:9005
        └────────────┬───────────┘             └────────────┬──────────┘
          "who is out there?"                     posts gossip hop-by-hop
                     │                                       ▲
                     └──── peaboard's reconcile loop dials ──┘
              (the app is the only thing that opens a socket)
```

## Connections and the peer count

A subtlety worth understanding, because the raw connection count
is *not* what you'd expect.

peaboard's reconcile loop dials **every** peer it discovers. TCP
connections are bidirectional, but each *dial* opens its own
connection — so when both ends dial each other (which they do,
since both discover each other), a pair of nodes ends up sharing
**two** connections, one opened from each side. In a 3-node
network every node therefore holds four board connections: two
it dialed, two dialed into it.

Why doesn't peaboard just collapse those into "one peer"? Because
it can't tell they're the same peer. An *outbound* connection
goes to the peer's known listener address (`bob:9003`), but the
matching *inbound* connection arrives from the peer's **ephemeral**
source port (`bob:51324`), and nothing in the frames says "I am
bob". The pea\* stack deliberately carries no peer identity —
that's an application concern, like encryption.

A real overlay closes this gap with a **handshake**: right after
connecting, each side announces its listener address (and usually
a public key), so the receiver can recognize the ephemeral
connection as "bob", find the connection it already has to bob,
and drop the redundant one. `pea2pea` supports exactly this via a
custom `Handshake` protocol — peaboard skips it to stay minimal.

So instead of counting connections, peaboard reports the number
of distinct peers **`peaveil` has discovered**. `peaveil` keys
peers by listener address, so each appears once regardless of how
many TCP connections back it — which is why a healthy 3-node
network reports **2** peers, not 4.

## Run it

Three terminals, one machine. Bob and Carol each know only
Alice; they find each other through her.

```sh
# terminal 1 — the entry point
cargo run -- --port 9000 --nick alice

# terminal 2
cargo run -- --port 9002 --bootstrap 127.0.0.1:9000 --nick bob

# terminal 3 — only knows alice, still sees bob's posts
cargo run -- --port 9004 --bootstrap 127.0.0.1:9000 --nick carol
```

In each window: `/join rust`, then type to post. A post from any
node reaches every node, even ones it never directly dialed.

## Commands

```
/join <board>   enter a board (replays its history)
/boards         list known boards and message counts
/peers          how many peers are on the network
/help           command list
/quit           leave
<text>          post to the current board
```

## The code

Two short files, kept deliberately small:

- [`src/main.rs`](src/main.rs) — CLI, the reconcile loop (the
  connection manager), and the incoming-post task.
- [`src/proto.rs`](src/proto.rs) — the `Post` wire format and the
  AEAD `seal` / `open` that make a real post indistinguishable
  from `peasub` cover.

## Just a demo

What a real application built on this stack would need, and
peaboard deliberately skips:

- **Real key management.** peaboard uses one hard-coded key
  (`proto::board_key`) shared by every node — that is what makes
  them one "private" board, but it means the encryption keeps out
  nobody who has the source. A real deployment does key agreement
  (a per-board key, or a `pea2pea` Noise handshake). The pea\*
  crates stay out of the crypto business by design; supplying it
  is the application's job, and here it's only a stub.
- **Connection de-duplication.** peaboard opens one connection
  per direction and runs no identity handshake to collapse them
  — see [Connections and the peer count](#connections-and-the-peer-count).
- **Persistence.** History lives in memory and is gone on exit.
- **Sanity limits.** No rate limiting, no message-size policy
  beyond the single-frame cap, no moderation, no abuse handling.
- **Identity & threads.** Nicknames are unauthenticated free
  text; there are no replies, attachments, or message ordering
  guarantees.
- **A serious threat-model review.** The metadata-privacy
  property is inherited from `peashape` (constant rate/size); the
  caveats in `peashape`'s and `peasub`'s own docs all apply, and
  peaboard adds no analysis of its own.

It is a readable map of how the pieces connect — start there, not
here, if you're building something real.

## License

MIT OR CC0-1.0.
