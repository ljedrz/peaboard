//! peaboard — a tiny, self-contained **demonstration** of the
//! pea* stack: a private bulletin board you run from a terminal.
//!
//! This is an example meant to be *read*, not deployed (see the
//! README for the long list of things a real app would add). The
//! point is to show how the four crates compose, each doing only
//! its own job:
//!
//! - **`pea2pea`** — the TCP transport (connections, listeners).
//! - **`peashape`** — pads every frame to a constant size and
//!   emits them at a constant rate, mixing real frames with
//!   cover traffic. An observer can't tell a busy node from an
//!   idle one. (Used indirectly, *through* the two crates below.)
//! - **`peaveil`** — peer discovery: it gossips peer *addresses*
//!   and maintains a "view" of who is out there.
//! - **`peasub`** — message gossip: it disseminates *posts* to
//!   the whole overlay and de-duplicates what it has seen.
//!
//! Each node therefore runs **two overlays**: a `peaveil` node
//! for discovery on `--port P`, and a `peasub` node for the
//! board on `P + 1`. peaboard itself is the glue — and, per the
//! pea* philosophy, it owns exactly the two things no library
//! below should decide for it:
//!
//! 1. **Who to connect to** — the [`reconcile`] loop reads
//!    `peaveil`'s view and dials both overlays. No library opens
//!    a socket on its own.
//! 2. **What the bytes say** — every post is sealed with
//!    authenticated encryption (see [`proto`]) before it is
//!    handed to `peasub`.

use std::collections::{BTreeSet, HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use chacha20poly1305::ChaCha20Poly1305;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::sync::broadcast::error::RecvError;

use peasub::{ID_SIZE, Node as Board, NodeConfig as BoardConfig};
use peaveil::{Node as Discovery, NodeConfig as DiscoveryConfig};

mod proto;
use proto::{Post, board_key, open, seal};

/// How many peers to keep connected on each overlay.
const PEER_CAP: usize = 8;
/// Boards shown on a fresh node, before any have been discovered
/// from incoming posts.
const SEED_BOARDS: [&str; 3] = ["rust", "privacy", "memes"];

/// One post as it is displayed in a board's history.
#[derive(Clone)]
struct Line {
    /// Short hex message id, e.g. `b8de5d`.
    id: String,
    /// Sender's wall-clock time, unix seconds.
    ts: u64,
    nick: String,
    text: String,
}

/// All the mutable UI state, shared between the input loop and
/// the background "incoming posts" task behind one mutex.
#[derive(Default)]
struct State {
    /// The board we are currently viewing, if any.
    current: Option<String>,
    /// Every board name we know about (seeded + discovered).
    boards: BTreeSet<String>,
    /// Per-board message history.
    log: HashMap<String, Vec<Line>>,
    /// Full message ids already filed. A post is shown once even
    /// though our own publish is echoed locally *and* may be
    /// relayed back to us by a peer (`peasub` de-dups per node,
    /// not against the original author).
    seen: HashSet<String>,
}

/// Parsed command-line arguments.
struct Args {
    port: u16,
    bootstrap: Vec<SocketAddr>,
    nick: String,
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = parse_args();

    let state = Arc::new(Mutex::new(State::default()));
    state
        .lock()
        .unwrap()
        .boards
        .extend(SEED_BOARDS.iter().map(|s| s.to_string()));

    // Discovery overlay (peaveil) on `port`. The `bootstrap`
    // addresses are seeded into peaveil's view; peaveil does not
    // dial them — that is the reconcile loop's job below.
    let disc = Discovery::new(DiscoveryConfig {
        name: Some(format!("peaboard-disc-{}", args.port)),
        listener_addr: Some(format!("127.0.0.1:{}", args.port).parse()?),
        bootstrap: args.bootstrap.clone(),
        cover: peaveil::CoverStrategy::Constant {
            interval: Duration::from_millis(200),
        },
        ..Default::default()
    });
    disc.spawn().await?;

    // Board overlay (peasub) on `port + 1`.
    let board = Board::new(BoardConfig {
        name: Some(format!("peaboard-board-{}", args.port)),
        listener_addr: Some(format!("127.0.0.1:{}", args.port + 1).parse()?),
        cover: peasub::CoverStrategy::Constant {
            interval: Duration::from_millis(200),
        },
        fanout: 4,
        message_size: proto::MESSAGE_SIZE,
        ..Default::default()
    });
    board.spawn().await?;
    let board_addr = board.local_addr().await?;

    // One cipher for the whole node (sealing outgoing posts and
    // opening incoming ones). See `proto::board_key`.
    let cipher = board_key();

    // Background task 1: keep both overlays connected.
    tokio::spawn(reconcile(disc.clone(), board.clone(), board_addr));
    // Background task 2: surface incoming posts.
    tokio::spawn(incoming(board.clone(), state.clone(), cipher.clone()));

    banner(&args, board_addr);
    run_repl(&state, &board, &disc, &cipher, &args.nick).await;

    board.shutdown().await;
    disc.shutdown().await;
    Ok(())
}

/// The read-eval-print loop: read a line from stdin, run a
/// `/command` or treat the line as a post to the current board.
async fn run_repl(
    state: &Mutex<State>,
    board: &Board,
    disc: &Discovery,
    cipher: &ChaCha20Poly1305,
    nick: &str,
) {
    let mut reader = BufReader::new(tokio::io::stdin()).lines();
    while let Ok(Some(raw)) = reader.next_line().await {
        let line = raw.trim();
        if line.is_empty() {
            continue;
        }
        let Some(cmd) = line.strip_prefix('/') else {
            post(state, board, cipher, nick, line);
            continue;
        };
        let (head, rest) = split_first_word(cmd);
        match head {
            "join" if !rest.is_empty() => join(state, rest),
            "join" => println!("usage: /join <board>"),
            "boards" => list_boards(state),
            "peers" => println!("peers on the network: {}", disc.known_peers().len()),
            "help" => help(),
            "quit" | "exit" => break,
            other => println!("unknown command: /{other} (try /help)"),
        }
    }
}

/// Seal a post and hand it to `peasub` to gossip, then echo it
/// locally (we never receive our own gossip back).
fn post(state: &Mutex<State>, board: &Board, cipher: &ChaCha20Poly1305, nick: &str, text: &str) {
    let Some(board_name) = state.lock().unwrap().current.clone() else {
        println!("join a board first: /join <board>");
        return;
    };
    let p = Post {
        board: board_name,
        nick: nick.to_string(),
        ts: now_secs(),
        text: text.to_string(),
    };
    let Some(sealed) = seal(cipher, &p) else {
        println!("message too long (max {} bytes)", proto::MAX_POST);
        return;
    };
    // `publish` pads/queues the sealed bytes and gossips them on
    // the next cover tick; it returns the random message id.
    match board.publish(&sealed) {
        Ok(id) => deliver(state, p, hexid(&id)),
        Err(e) => println!("could not publish: {e}"),
    }
}

/// File a post into its board's history and print it if we are
/// currently viewing that board. Idempotent per message id.
fn deliver(state: &Mutex<State>, p: Post, id: String) {
    let mut s = state.lock().unwrap();
    if !s.seen.insert(id.clone()) {
        return; // already filed (our own echo, or a relayed copy)
    }
    let line = Line {
        id: id[..6].to_string(),
        ts: p.ts,
        nick: p.nick,
        text: p.text,
    };
    s.boards.insert(p.board.clone());
    let showing = s.current.as_deref() == Some(p.board.as_str());
    s.log.entry(p.board).or_default().push(line.clone());
    if showing {
        print_line(&line);
    }
}

/// Switch to a board and replay its history.
fn join(state: &Mutex<State>, board: &str) {
    let backlog = {
        let mut s = state.lock().unwrap();
        s.current = Some(board.to_string());
        s.boards.insert(board.to_string());
        s.log.get(board).cloned().unwrap_or_default()
    };
    println!("— now on #{board} ({} message(s)) —", backlog.len());
    for line in &backlog {
        print_line(line);
    }
}

/// List known boards with their message counts; mark the current.
fn list_boards(state: &Mutex<State>) {
    let s = state.lock().unwrap();
    println!("Boards:");
    for b in &s.boards {
        let count = s.log.get(b).map_or(0, Vec::len);
        let marker = if s.current.as_deref() == Some(b.as_str()) {
            " *"
        } else {
            ""
        };
        println!("    {b}  ({count}){marker}");
    }
}

/// peaboard's connection manager — the *only* place connections
/// are opened. Once a second it asks `peaveil` who it has
/// discovered and dials both overlays toward them (capped at
/// [`PEER_CAP`]). A `peasub` peer lives at its `peaveil` port + 1.
async fn reconcile(disc: Discovery, board: Board, board_addr: SocketAddr) {
    let mut last_peers = 0;
    loop {
        tokio::time::sleep(Duration::from_secs(1)).await;
        let known = disc.known_peers();

        // 1. Keep the discovery overlay connected, so peer
        //    addresses keep flowing in.
        for addr in &known {
            if disc.connected_peers().len() >= PEER_CAP {
                break;
            }
            if !disc.connected_peers().contains(addr) {
                let _ = disc.connect(*addr).await;
            }
        }

        // 2. Bridge each discovered peer onto the board overlay.
        for addr in &known {
            if board.connected_peers().len() >= PEER_CAP {
                break;
            }
            let peer_board = SocketAddr::new(addr.ip(), addr.port().wrapping_add(1));
            if peer_board != board_addr && !board.connected_peers().contains(&peer_board) {
                let _ = board.connect(peer_board).await;
            }
        }

        // Report the count of distinct *discovered* peers, which
        // peaveil de-dups by listener identity. (We don't report
        // raw board-overlay connections: peaboard opens one per
        // direction, so two nodes share two connections — see the
        // README. De-duping those would need an identity
        // handshake, which a minimal demo skips.)
        let n = disc.known_peers().len();
        if n != last_peers {
            last_peers = n;
            println!("[net] peers on the network: {n}");
        }
    }
}

/// Drain frames `peasub` delivers, open the ones that decrypt
/// (cover frames and posts for other keys simply fail to open),
/// and hand them to [`deliver`].
async fn incoming(board: Board, state: Arc<Mutex<State>>, cipher: ChaCha20Poly1305) {
    let mut rx = board.subscribe();
    loop {
        match rx.recv().await {
            Ok(frame) => {
                if let Some(p) = open(&cipher, &frame) {
                    deliver(&state, p, hexid(&frame[..ID_SIZE]));
                }
            }
            Err(RecvError::Lagged(_)) => continue, // fell behind; keep going
            Err(RecvError::Closed) => break,       // node shut down
        }
    }
}

fn banner(args: &Args, board_addr: SocketAddr) {
    println!("┌─ peaboard ───────────────────────────────────────────────┐");
    println!("│ a private bulletin board on the pea* stack — DEMO ONLY   │");
    println!("└──────────────────────────────────────────────────────────┘");
    println!(
        "discovery : 127.0.0.1:{}   board : {}",
        args.port, board_addr
    );
    println!("nick      : {}", args.nick);
    println!("privacy   : constant cover traffic — an observer cannot tell");
    println!("            a busy board from an idle one, nor which board you");
    println!("            are reading (the board name is encrypted too).");
    println!();
    println!("Boards:");
    for b in SEED_BOARDS {
        println!("    {b}");
    }
    println!();
    println!("Type /join <board> to enter, then just type to post. /help for more.");
    println!();
}

fn help() {
    println!("commands:");
    println!("  /join <board>   enter a board (replays its history)");
    println!("  /boards         list known boards and message counts");
    println!("  /peers          how many peers are on the network");
    println!("  /help           this message");
    println!("  /quit           leave");
    println!("  <text>          post <text> to the current board");
}

/// Render a post as `[HH:MM #id] nick: text`.
fn print_line(l: &Line) {
    println!("[{} #{}] {}: {}", hhmm(l.ts), l.id, l.nick, l.text);
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// `HH:MM` in UTC, computed without pulling in a date library.
fn hhmm(ts: u64) -> String {
    let s = ts % 86_400;
    format!("{:02}:{:02}", s / 3600, (s % 3600) / 60)
}

/// Hex-encode a message id. Used in full as a de-dup key; the
/// first six chars are what users see (e.g. `#b8de5d`).
fn hexid(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Split `"join rust"` into `("join", "rust")`.
fn split_first_word(s: &str) -> (&str, &str) {
    match s.split_once(char::is_whitespace) {
        Some((head, rest)) => (head, rest.trim()),
        None => (s, ""),
    }
}

fn parse_args() -> Args {
    let mut port = 9000u16;
    let mut bootstrap = Vec::new();
    let mut nick = "anon".to_string();
    let mut it = std::env::args().skip(1);
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--port" | "-p" => {
                if let Some(v) = it.next().and_then(|s| s.parse().ok()) {
                    port = v;
                }
            }
            "--bootstrap" | "-b" => {
                if let Some(addr) = it.next().and_then(|s| s.parse().ok()) {
                    bootstrap.push(addr);
                }
            }
            "--nick" | "-n" => {
                if let Some(v) = it.next() {
                    nick = v;
                }
            }
            "--help" | "-h" => {
                println!("usage: peaboard [--port P] [--bootstrap IP:PORT]... [--nick NAME]");
                println!("  --port P          peaveil listens on P, peasub on P+1 (default 9000)");
                println!(
                    "  --bootstrap A     a peer's peaveil address to enter through (repeatable)"
                );
                println!("  --nick NAME       your display name (default: anon)");
                std::process::exit(0);
            }
            _ => {}
        }
    }
    Args {
        port,
        bootstrap,
        nick,
    }
}
