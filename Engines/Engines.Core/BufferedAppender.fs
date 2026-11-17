namespace AutoCommand.Engines.Core

open System
open System.Collections.Generic
open System.IO
open System.Text

/// <summary>
/// One managed write buffer for every periodic disk writer — the disk-write
/// counterpart of the Instrument Metronome. Two writer shapes:
///   • Append(path, line) — append-log buffering per path (event journals);
///     a buffer crossing the byte threshold flushes itself immediately.
///   • Rewrite(path, text) — last-write-wins with a content guard: identical
///     content never touches the disk at all (state files, small stores).
/// Nothing inside runs on a timer: the host flushes on its own cadence
/// (AutoCommand: the "disk-flush" metronome instrument, default 30 s) and on
/// exit. Crash window = one flush interval, safe by design for every routed
/// writer — the blocks store reconciles from the firewall rules (they are
/// the truth), and the Sysmon archive state may re-read a few already-kept
/// events, which its record-id tracking tolerates.
/// Per-path accounting powers the Settings ▸ Instrumentation readout.
/// </summary>
type BufferedAppender private () =

    static let gate = obj ()
    static let appends = Dictionary<string, StringBuilder>(StringComparer.OrdinalIgnoreCase)
    static let rewrites = Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
    static let lastWritten = Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
    static let writtenBytes = Dictionary<string, int64>(StringComparer.OrdinalIgnoreCase)
    static let mutable thresholdBytes = 256 * 1024

    static let account (path: string) (n: int) =
        let mutable v = 0L
        if writtenBytes.TryGetValue(path, &v) then writtenBytes.[path] <- v + int64 n
        else writtenBytes.[path] <- int64 n

    static let ensureDir (path: string) =
        let d = Path.GetDirectoryName(path)
        if not (String.IsNullOrEmpty(d)) then Directory.CreateDirectory(d) |> ignore

    /// <summary>Buffer size at which an append buffer flushes itself
    /// (default 256 KB; the thrifty preset raises it to 1 MB).</summary>
    static member ThresholdBytes
        with get () = thresholdBytes
        and set v = thresholdBytes <- Math.Max(4096, v)

    /// <summary>Buffer one journal line. Newline is added here — callers
    /// pass the bare line.</summary>
    static member Append(path: string, line: string) : unit =
        try
            let flushNow =
                lock gate (fun () ->
                    let mutable sb = Unchecked.defaultof<StringBuilder>
                    if not (appends.TryGetValue(path, &sb)) then
                        sb <- StringBuilder()
                        appends.[path] <- sb
                    sb.Append(line).Append('\n') |> ignore
                    sb.Length >= thresholdBytes)
            if flushNow then BufferedAppender.Flush(path)
        with _ -> () // best-effort, the same contract as the writers it replaces

    /// <summary>Stage a whole-file rewrite. Unchanged content is dropped;
    /// changed content is written once at the next flush, not per call.</summary>
    static member Rewrite(path: string, text: string) : unit =
        try
            lock gate (fun () ->
                let mutable current = null
                if lastWritten.TryGetValue(path, &current) && current = text then ()
                else rewrites.[path] <- text)
        with _ -> ()

    /// <summary>Flush one path (its append buffer and any pending rewrite).
    /// Failures are swallowed per path — one unreadable file must not stop
    /// the others — but failed data is RE-STAGED, not discarded: a transient
    /// lock (AV scan, a viewer holding the file) used to silently lose every
    /// line staged for that path, beyond the documented one-flush crash
    /// window.</summary>
    static member Flush(path: string) : unit =
        let struct (appendText, rewriteText) =
            lock gate (fun () ->
                let appendText =
                    let mutable sb = Unchecked.defaultof<StringBuilder>
                    if appends.TryGetValue(path, &sb) then
                        appends.Remove(path) |> ignore
                        sb.ToString()
                    else null
                let rewriteText =
                    let mutable r = null
                    if rewrites.TryGetValue(path, &r) then rewrites.Remove(path) |> ignore; r
                    else null
                struct (appendText, rewriteText))

        let mutable appendOk = true
        let mutable rewriteOk = true
        if appendText <> null then
            try
                ensureDir path
                File.AppendAllText(path, appendText)
                lock gate (fun () -> account path appendText.Length)
            with _ -> appendOk <- false
        if rewriteText <> null then
            try
                ensureDir path
                // Atomic rewrite: tmp + replace, not a plain truncate-then-
                // write — blocks.txt (the production deferred-save ledger)
                // once flowed through WriteAllText here, re-introducing the
                // truncate-on-crash its own atomic path was written against.
                let tmp = path + ".batmp"
                File.WriteAllText(tmp, rewriteText)
                if File.Exists path then File.Replace(tmp, path, null) else File.Move(tmp, path)
                lock gate (fun () ->
                    account path rewriteText.Length
                    lastWritten.[path] <- rewriteText)
            with _ -> rewriteOk <- false

        // Re-stage failures. Appends go back at the FRONT (older text before
        // whatever was staged meanwhile — journal order is oldest-first).
        // Rewrites re-stage only if no newer staging exists (last-write-wins).
        lock gate (fun () ->
            if not appendOk && appendText <> null then
                let mutable sb = Unchecked.defaultof<StringBuilder>
                if appends.TryGetValue(path, &sb) then
                    let merged = StringBuilder(appendText.Length + sb.Length)
                    merged.Append(appendText) |> ignore
                    merged.Append(sb) |> ignore
                    appends.[path] <- merged
                else
                    appends.[path] <- StringBuilder(appendText)
            if not rewriteOk && rewriteText <> null && not (rewrites.ContainsKey path) then
                rewrites.[path] <- rewriteText)

    static member FlushAll() : unit =
        let paths =
            lock gate (fun () ->
                [ for p in appends.Keys -> p
                  for p in rewrites.Keys -> p ]
                |> List.distinct)
        for p in paths do BufferedAppender.Flush(p)

    /// <summary>(path, pending bytes, written bytes) — the Settings readout
    /// and the self-audit of what this class actually saved.</summary>
    static member Stats() : struct (string * int * int64) list =
        lock gate (fun () ->
            [ for kv in appends -> struct (kv.Key, kv.Value.Length, 0L) ]
            @ [ for kv in rewrites -> struct (kv.Key, kv.Value.Length, 0L) ]
            @ [ for kv in writtenBytes -> struct (kv.Key, 0, kv.Value) ])
        |> fun raw ->
            [ for struct (p, pending, written) in raw ->
                p, pending, written ]
            |> List.fold (fun (acc: Map<string, int * int64>) (p, pend, wr) ->
                    let cp, cw = match acc.TryFind(p) with Some (a, b) -> a, b | None -> 0, 0L
                    acc.Add(p, (cp + pend, cw + wr))) Map.empty
            |> Map.toList
            |> List.map (fun (p, (pend, wr)) -> struct (p, pend, wr))

    /// <summary>Test seam: drop every buffer without writing.</summary>
    static member ResetForTest() : unit =
        lock gate (fun () ->
            appends.Clear()
            rewrites.Clear()
            lastWritten.Clear()
            writtenBytes.Clear())
