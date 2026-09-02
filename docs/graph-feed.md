# The live graph feed

Kin serves its graph to outside consumers two ways: one JSON export shaped for
drawing, and one event stream that says what changed. Both come off the daemon,
both are reachable from the CLI, and both carry a sequence number so a consumer
knows exactly which events its picture already contains.

Before this existed, a consumer that wanted to draw a repository started
`kin graph viz --port N` and scraped its `/api/graph.json` once. That was a
snapshot, it needed a subprocess and a port, and on Windows it wedged on pid
reuse. The other option was `GET /graph/bootstrap`, which is the whole binary
snapshot: on a 23,098-entity repository that is 119.6 MiB, against the 1.0 MiB a
renderer actually draws.

## The export

`GET /graph/export` on the daemon, or `kin graph export --json`.

```
kin graph export --json --limit 1400 --include line
curl "$KIN_DAEMON_URL/graph/export?limit=1400&include=line,signature"
```

Query parameters:

| Parameter | Meaning |
| --- | --- |
| `limit` | Node cap. Absent uses 1,400. `0` asks for every entity |
| `kinds` | Comma-separated entity kinds to keep. Any spelling matches: `TraitDef`, `trait_def` and `traitdef` are one filter |
| `path` | Repository path prefix a node's file must start with |
| `include` | Comma-separated optional node fields: `signature`, `line` |

The response is `graph-export.schema.json` in `packages/boundary-contracts`.
It carries `seq`, the position in the delta stream the payload was cut at, which
is what pairs it with `/graph/events`.
Nodes carry `id`, `name`, `kind`, `file` and `degree` always, plus `line` and
`signature` when asked for. Links carry `source`, `target` and `kind`, and both
endpoints are always ids present in `nodes`.

The envelope says how much of the graph you are looking at. `entity_count` and
`relation_count` are the population the sample was drawn from, not what came
back, so a client can report "1,400 of 23,098" rather than implying it drew
everything. Two counters describe withheld edges and they are deliberately not
one number: `unresolved_links` counts links whose endpoint is not an entity in
this graph at all, such as an import of an external crate, which is a property
of the graph; `filtered_links` counts links dropped because an endpoint was
excluded by `kinds`, `path` or the node cap, which is a property of your
request.

Every count is of distinct links. A link is an undirected
`(source, target, kind)` key, so two relations between the same pair in the same
kind are one link and draw one line, and an edge the graph reports from both of
its endpoints is counted once.

A session holding a temporal scope exports the graph that scope names, the same
resolution `/graph/bootstrap` uses.

## The sampling rule

A repository graph is bigger than any renderer wants. The cap is applied server
side so a client does not download 9 MiB in order to throw 94 percent of it
away, and so two consumers drawing the same repository draw the same picture.

Nodes are bucketed by module, each module gets a quota, and whatever the quotas
leave is filled globally by degree:

1. A node's module is the first segment of its file path. Under a container
   directory (`app`, `apps`, `cmd`, `crates`, `internal`, `lib`, `modules`,
   `packages`, `pkg`, `services`, `src`) with more than two segments, it is the
   first two. A file at the repository root is `(root)`; an entity the graph
   placed in no file is `(unknown)`.
2. Each module gets `max(1, (limit * 60 / 100) / module_count)` nodes, taken
   highest degree first.
3. The remaining budget is filled from everything not yet chosen, again highest
   degree first.
4. Ties break on name, then on entity id.

The module split is what keeps a small module visible. Ranking the whole graph
by degree hands the entire budget to whichever directory happens to be densest;
measured on redis, `utils` holds 97 of 23,098 entities and a reader looking for
it has to find something drawn. At a 1,400-node cap on that repository all eight
modules survive, and `utils` keeps all 97.

The id tiebreak is what makes the sample deterministic. Without it every
zero-degree node with the same name is tied, and which one survived would depend
on the order the store happened to enumerate entities in, so two exports of one
unchanged graph could disagree.

`degree` is the node's degree across the whole matched population, not
recomputed for the sampled subgraph. A node whose neighbours were sampled out
still reports how connected it really is.

## The event stream

`GET /graph/events` on the daemon, or `kin graph watch --json`.

```
kin graph watch --json --types EntityChanged,RelationChanged
```

Server-sent events, one JSON payload per `data:` line, a comment heartbeat every
30 seconds. The `types` parameter keeps only the named event types. Frames are
`graph-event.schema.json` in `packages/boundary-contracts`.

A filtered stream has gaps in `seq`, and that is expected: the sequence is
assigned when an event is emitted, not when it is delivered, so numbers are
missing for the frames the filter dropped. Measured on hiredis, `--types
RelationChanged` over an edit that produced 27 entity frames delivered two
relation frames at seq 62 and 63 behind a connected frame at seq 33. Never read
consecutive sequence numbers as proof that nothing was missed. What `seq` is for
is ordering against an export's cut, and it does that whether or not a filter is
on.

Every frame carries a monotonic `seq`. The first frame is always `connected`,
carrying `entity_count`, `root_hash` and the `seq` the stream has reached.
`EntityChanged` carries the entity id, the change type, the file, the session
that caused it when there was one, and a `node` summary of what the entity now
is, so a consumer can patch a drawn node without a second round trip.
`RelationChanged` carries both endpoint ids, the relation kind and the change
type. It is emitted after the entity frames of the same reconcile, so an edge
never names a node the consumer has not been told about yet. Both endpoints are
always entities: an edge to an artifact or an external symbol is not drawable
and produces no frame.

`GraphDeltaApplied` closes each reconcile pass, after the last entity and
relation frame of that pass, and says how much the pass did:
`nodes_added`, `nodes_modified`, `nodes_removed`, `relations_added`,
`relations_removed`. Buffer frames and lay out on this one. The reason is
measured: one appended function at the end of hiredis `net.c` emitted 26
`EntityChanged` frames, and 25 of them were for entities the edit never
touched, because a reconcile re-emits every entity in the file it reparsed. A
consumer laying out per frame would relayout 26 times for one keystroke. A pass
that changed nothing emits no boundary at all.

`/vfs/subscribe` is unchanged and still carries the same bus. Its frames have no
`seq` and its `connected` frame has no root hash, because the VFS daemon and the
spine depend on its exact frames.

## Resyncing

The protocol is:

1. `GET /graph/export`. Keep its `seq`.
2. Subscribe to `/graph/events`.
3. Discard every frame whose `seq` is at or below the export's `seq`. Those
   changes are already in the payload you hold.
4. Apply the rest, laying out on each `GraphDeltaApplied`.

Order does not matter between steps 1 and 2, which is the point of doing it this
way. The export reads its sequence before it starts building, so an event
emitted while the payload is being assembled falls above the cut and is
delivered. The cost is that a client may re-apply one change it already has, and
applying a node or edge upsert twice is a no-op. The alternative, reading the
sequence after the build, would drop that event on the floor instead.

`root_hash` is not the resync key, and cannot be. A working-tree edit changes
the graph without advancing the graph root: measured on hiredis, one appended
function produced 26 entity events and zero `GraphRootChanged`. A client
reconnecting between commits would compare two matching hashes and keep a stale
picture. Use `root_hash` to tell which committed state you are looking at, and
`seq` to tell what you have applied.

One signal still means throw the picture away and start at step 1:

- `lagged`. The subscriber fell behind the daemon's broadcast channel and events
  were dropped before it saw them. It carries no `seq`, because the frames it is
  telling you about were never delivered and there is no position to name. It is
  never removed by the `types` filter: it is not a graph event, it is the news
  that your view is now wrong.

`GraphRootChanged` is not that signal. It means a commit happened, which a
consumer may want to show, but the entity and relation frames that came with it
already describe the change.

## Adding an event type

New event types are added additively and older consumers are expected to keep
working. A consumer must ignore a `type` it does not recognize rather than fail
on it. Validating a frame against `graph-event.schema.json` answers "is this a
frame I know", not "is this stream well formed", so a validation failure on an
unknown type is a signal to skip that frame and nothing more.

## Consumers

`kin-demo` draws the export in its graph pane. `kinlab` mission control reads
the event stream, and its org graph explorer is the surface the export is shaped
for. Both import the payload shapes from `@kin/boundary-contracts` so the schema
is the one contract all three read.
