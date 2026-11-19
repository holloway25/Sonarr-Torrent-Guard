# Metadata timeout and retry

Metadata retry is separate from [file-policy cleanup](PUBLIC-WORKFLOW.md#live-file-policy-cleanup).
An explicitly authorized live worker can remove a verified public torrent still
retrieving metadata. It may request a replacement search during the same pass.
Each scheduled run starts from current Sonarr and qBittorrent evidence.

## When a torrent qualifies

- Sonarr ownership, torrent identity, bound downloader and public source are
  verified. Private, manual, unowned and ambiguous items are protected.
- At least 30 minutes have elapsed since qBittorrent added the torrent.
- Its current state is `metaDL` or `forcedMetaDL` with zero progress,
  unknown size (`-1` or `0`) and a successfully read empty file list.
- The owning Sonarr reports a supported 4.x version and both retry settings
  are enabled. The approved scope is still valid.

The elapsed age uses the torrent addition time because the active-time counter
can stall during metadata retrieval. Paused, stopped and inconsistent items
are held. Metadata that arrives before the final check cancels this action.
A later pass can evaluate the resulting file list normally.

## What Guard asks Sonarr to do

Guard rereads the target and its files immediately before this request:

```text
DELETE /api/v3/queue/{currentQueueId}
removeFromClient=true
blocklist=false
skipRedownload=true
changeCategory=false
```

Sonarr requests removal of the torrent and its data. This action leaves
blocklisting off because a metadata timeout gives no file-policy verdict.
Guard can ask the same Sonarr to search affected episodes only after it
confirms the original torrent is absent and checks for replacements that
already exist.

Before searching, Guard rereads the queue, grab history, relevant blocklist,
retry settings and authorization. Guard checks a bounded history for each affected
episode back to the original grab. A later grab by the owning Sonarr holds the
search even if a different downloader handled it or it has already been imported.
A replacement queue entry, ambiguous evidence or a matching new blocklist entry
also holds the search. Guard recognizes original stale queue rows by their exact row ID,
episode and hash. A response that omits relevant evidence leaves the decision
uncertain.

```text
POST /api/v3/command
```

```json
{"name":"EpisodeSearch","episodeIds":[123]}
```

A receipt records Sonarr's acceptance of the command. Sonarr chooses the
replacement using its normal scoring and source rules. It may select another
release, re-grab the same torrent or find no candidate. Guard checks the next
grab in an ordinary later pass.

## Logs and interruptions

The private live log records the removal or search outcome. A lost removal
response or missing removal evidence stops the follow-up search. A lost search
response is logged as uncertain. An interruption can leave a removed torrent
without a new search. Subsequent passes assess what is currently queued.

Guard holds evidence for the two requests in memory during one pass. Later
passes use current evidence from Sonarr and qBittorrent.

- [Sonarr queue removal](https://github.com/Sonarr/Sonarr/blob/v4.0.20.3014/src/Sonarr.Api.V3/Queue/QueueController.cs)
- [Sonarr command submission](https://github.com/Sonarr/Sonarr/blob/v4.0.20.3014/src/Sonarr.Api.V3/Commands/CommandController.cs)
