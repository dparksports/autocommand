# AutoCommand — see what your Windows PC is really doing

![AutoCommand](Assets/corp_banner.png?v=light1)

**Tired of antivirus software? Nagging popups, yearly subscriptions, scans that finish with "no threats found" — and still no answer when your computer acts weird?**

You don't need another guard dog. You need to *see what's going on*. AutoCommand is a free, open-source app that shows you every program on your PC that's talking to the internet, explains each one in plain English, and stops anything you don't want — one click, undo included. It sends nothing anywhere, costs nothing, and you can delete it when you're done.

[![License: Apache-2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)

## Try it in five minutes

![Try it in five minutes](Assets/first_five_minutes_infographic.png?v=oss3)

1. **Download** `AutoCommand-v…-win-x64.zip` from [Releases](../../releases) and unzip it anywhere. There's no installer.
2. **Right-click `AutoCommand.exe` → Run as administrator.** (That permission lets it watch the whole machine — the same reason Task Manager asks.) The first screen lists every program talking to the internet right now.
3. **Look around, ask something.** Click any row to see who started it. And if you use an AI assistant, the **Be My Guest** tab can invite it to read the same facts — but only while you keep the door open (more below).

That's the whole tutorial. Looking changes nothing; deleting the folder uninstalls it completely.

> **Windows may show a blue "protected your PC" screen** because the app isn't from a big company. Click **More info → Run anyway**. It's open source — anyone can read exactly what it does, and that's rather the point.

## What am I looking at?

![How to read one row](Assets/row_anatomy_infographic.png?v=oss2)

The main screen is a list of rows — one per connection. Every row tells you who's talking, to whom, how much, for how long, and gives you a Block button (with an undo, and a panic button that restores everything). When a row surprises you, *that's* the moment to click it or ask for a second opinion — not before. Most rows, you'll never need to think about.

One question the list can answer for itself: the **TX-only (no reply)** checkbox — off by default — narrows it to programs that have *sent* packets and never heard one word back. That's the shape of a blocked outbound call or a dead-end beacon, and the checkbox shows how many are out there before you switch it on. It's a lens, not a verdict: uncheck it and the full list is exactly where it was, nothing hidden while you weren't looking.

## Where everything lives

![Where everything lives](Assets/app_map_infographic.png?v=oss3)

The sidebar groups its tools by the question you're asking. **Watch** is everything that shows what's happening — including **Spawns**, one tab for "who launched this?": scheduled-task launches, Python programs and the svchost timeline sit side by side there, each with a dot that glows green while it records. For when rows of numbers aren't the mood, the Process Monitor's right panel replays the same live process traffic as a Matrix-style digital rain — one column per alive process (never ten or more), falling glyphs for transmits, red for a blocked process — and either pane folds from the thin rail between them: ‹ hides the list for rain-only, › hides the rain for list-only, with a right-click menu on the rain for font, colors, speed and movie-look vs data-only styles. When a site feels slow, **Why is this site slow?** runs a 60-second check — recorded traffic, a handful of handshakes, a comparison site — and says what it found in one plain sentence, with the math one click away. **Contain** holds the stopping tools (firewall, telemetry sinkholes, Defender). **System** is the rest: AI access, privacy, settings — and, behind the Advanced-investigation toggle, **Investigate**, which joins everything the app recorded about one process (who launched it, where it connected, whether anything was blocked) into a single verdict and a copyable report. And watching never stops just because you looked at another screen — a feed runs until you stop it, not until you click away.

## When something looks odd

![See it, ask, stop it](Assets/plain_english_infographic.png?v=oss3)

Real example, from this app's own development machine: *"svchost.exe is uploading packets"* sounds alarming — it turned out to be Chrome's updater downloading from Google's own servers, and AutoCommand proved it in one row. No panic, no reinstall, no forum archaeology at midnight.

## Why this instead of another antivirus?

![Why your antivirus can't help](Assets/oss_alternative_infographic.png?v=oss3)

Keep your antivirus if you like it — this isn't a replacement, and you don't have to uninstall anything. It's the piece antivirus never gives you: **visibility**. A scanner matches files against a list of known bad ones; it has nothing to say about a "clean" program phoning home more than it should. AutoCommand watches behavior, names it in plain words, remembers what it saw (so yesterday's mystery is still solvable tomorrow), and never asks for a subscription, an account, or your credit card.

## Common questions

| What you see | What to do |
|---|---|
| "A program I don't recognize is on the list" | Most are normal Windows parts. Double-click the row — it shows who started it and where it connects. Still unsure? Invite your AI assistant to take a look — see **Be My Guest** below. |
| "It asked for Administrator permission" | That's how it sees system processes, not just yours. It never uses that permission without asking you first. |
| "Should I remove my antivirus?" | Your call — they do different jobs. AutoCommand shows what's happening; antivirus scans files. Many people run both. |
| "What does it send about me?" | Nothing, by default. Everything happens on your computer. (The one optional extra — an anonymous usage count, no identifiers at all — is off unless you say yes.) |
| "I blocked something and the internet broke" | Breathe. The 🚑 **Restore Internet** button in the corner undoes every block AutoCommand made, in one click. |

## Be My Guest — your AI assistant, invited

Maybe you've already asked ChatGPT or Claude about a weird-sounding program — and had to describe your screen in words, because an assistant can't see your computer. The **Be My Guest** tab finishes that thought, carefully. It works like having a guest over:

- **Nobody comes in until you open the door.** AI access is off until you start it. Stop the session — or close the app — and the invitation is withdrawn on the spot.
- **A guest looks; a guest doesn't wander.** Your assistant can't run commands, open files, or rummage through your PC. It can only ask AutoCommand's own questions — the same ones the app already answers for you: *what is this program, who started it, where is it going, is that normal?*
- **Nothing is touched without your yes.** Looking is all it can do unless you also switch on actions — and even then, every block, stop, or change shows the same confirmation box you'd see if you'd clicked it yourself. It can suggest; you decide.
- **You see every question it asked.** The tab keeps a plain-English list of every request and answer, for as long as the visit lasts.

The door only opens for assistants that speak a standard connection language called **MCP** — Claude Desktop, ZCode, AutoClaw, Gemini Antigravity, Cursor, Windsurf and VS Code all qualify, and so does any other MCP-capable desktop client. The Be My Guest tab offers one-click registration for the clients it finds on your PC; for anything else, **Copy MCP config** gives you the entry to paste by hand. And if your assistant doesn't speak MCP at all, nothing happens and nothing is lost: AutoCommand works exactly the same with the door shut.

One honest line about privacy, because you'd wonder: AutoCommand itself still talks to no one. It hands facts to your assistant's own app on your own PC — and where that app sends them is the trust you already chose when you picked it. Prefer it saw nothing? Leave the door closed. You lose nothing.

## What else is inside

The same plain-English treatment across a few more windows: a **"phone bill"** view of who talks to whom and how much, **one-click firewall presets**, a tab showing **what Windows delivered and updated overnight**, and a **telemetry opt-out** section that proves apps actually honored your "stop sending data" setting. One rule everywhere: *nothing runs without you, nothing is guessed, and everything it remembers is a readable file on your own disk.* The complete, honest list — including every limitation — is in the [Technical Notes](docs/TECHNICAL_NOTES.md).

> **🔧 Setting up a new PC instead?** The first-hour ritual — debloat, firewall presets, privacy opt-outs — lives in its own app: [**Shields Up**](https://github.com/dparksports/shields-up/releases/latest) (same author, same undo-first design).

## Downloads

| File | For |
|---|---|
| `AutoCommand-v…-win-x64.zip` | Windows 10 and 11 — unzip anywhere, right-click `AutoCommand.exe` → **Run as administrator**. Nothing else to install. |

## Your privacy, in one sentence

Everything happens on your computer; the app talks to no one by default, and the only optional exception is an anonymous usage count with no identifier of any kind — off unless you say yes.

## For developers and tinkerers

![Architecture](docs/infographic-architecture.svg)

This is **AutoCommand III**: the same app you just read about, with its core
engine layer rebuilt in **F#** — the C# WPF shell and app services drive
app-agnostic F# engines (firewall with strong-typed COM, Sysmon watching,
DNS/geo/RDAP, TLS interception, forensics, site diagnosis, the MCP agent
bridge), injected with AutoCommand's identity. Same behavior, same
self-tests, all of them green. The full story — what moved, what was
ported forward from II, what the seams look like — is in
**[README-III.md](docs/history/README-III.md)** (the III-era readme, kept in `docs/history/`).

The family tree starts one generation further back: **SystemMonitor was the
original precursor** to all of this. Its complete source tree and commit
history are preserved in [`systemmonitor/`](systemmonitor/) — the classic
v3.x firmware-forensics dashboard, unchanged, with every commit that led
here. Its future is this repo; its past now lives here too.

![The migration](docs/infographic-migration.svg)

```powershell
# .NET 10 SDK required
git clone https://github.com/dparksports/autocommand.git
cd autocommand
dotnet build AutoCommand.csproj -c Release

# self-contained build (what the releases ship)
dotnet publish AutoCommand.csproj -c Release -r win-x64 --self-contained

# the offline self-test suites (synthetic inputs, run anywhere)
dotnet run --project ContainSelfTest      # firewall engine
dotnet run --project SiteDoctorSelfTest   # diagnosis engines
dotnet run --project NetWatchSelfTest     # watch engines
dotnet run --project ProxyInstallSelfTest # MCP bridge
```

How it actually works — the dual-family kernel connection table, the Sysmon archive, the svchost decoder, the AI-assistant consent model, every engine's offline self-test — is documented in **[TECHNICAL_NOTES.md](docs/TECHNICAL_NOTES.md)**. Apache 2.0.

## Credits & license

Made with ❤️ in California

Apache License 2.0 — free to use, share, and modify

© 2026 Dan Park, magicpoint.ai

Questions, stories, things you caught? [Say hello in Discussions](../../discussions).
