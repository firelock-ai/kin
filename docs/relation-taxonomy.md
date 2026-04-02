# Kin Relation Taxonomy — Complete Coverage Matrix

## Full RelationKind Enum (23 variants)

```rust
pub enum RelationKind {
    // Structural
    Contains,          // parent encloses child (class→method, enum→variant)
    Extends,           // inherits implementation (class inheritance)
    Implements,        // satisfies type contract (interface/trait/protocol)
    Overrides,         // NEW — method replaces parent method

    // Usage
    Calls,             // invokes at runtime
    Instantiates,      // NEW — constructs an instance (new Foo())
    References,        // non-call reference (field access, constant use)
    UsesType,          // NEW — type dependency in signature/body

    // Dependencies
    Imports,           // file-level import/use/require
    DependsOn,         // package/crate-level dependency

    // Behavioral
    EmitsEvent,        // publishes named event
    SubscribesTo,      // NEW — listens/subscribes to named event
    DefinesContract,   // defines API/schema contract
    ConsumesContract,  // consumes API/schema contract

    // Concurrency
    SendsMessage,      // NEW — sends on typed channel/queue/mailbox
    Spawns,            // NEW — creates concurrent execution context

    // Lifecycle
    Tests,             // test entity verifies target
    Covers,            // test provides runtime coverage
    CoChanges,         // entities change together in commits
    DerivedFrom,       // generated/derived from another entity

    // Metadata
    DocumentedBy,      // entity has documentation
    OwnedBy,           // entity has responsible owner/team
    OwnedByFile,       // entity associated with file
}
```

---

## Matrix 1: Theoretical Applicability

Does this relationship concept exist in this language? Y = yes, - = not applicable.

| Language    | Contains | Extends | Implements | Overrides | Calls | Instantiates | References | UsesType | Imports | DependsOn | EmitsEvent | SubscribesTo | DefinesContract | ConsumesContract | SendsMessage | Spawns | Tests | Covers | CoChanges | DerivedFrom | DocumentedBy | OwnedBy | OwnedByFile |
|:------------|:--------:|:-------:|:----------:|:---------:|:-----:|:------------:|:----------:|:--------:|:-------:|:---------:|:----------:|:------------:|:---------------:|:----------------:|:------------:|:------:|:-----:|:------:|:---------:|:-----------:|:------------:|:-------:|:-----------:|
| Rust        | Y        | -       | Y          | -         | Y     | Y            | Y          | Y        | Y       | Y         | Y          | Y            | Y               | Y                | Y            | Y      | Y     | Y      | Y         | Y           | Y            | Y       | Y           |
| Python      | Y        | Y       | -          | Y         | Y     | Y            | Y          | Y        | Y       | Y         | Y          | Y            | Y               | Y                | Y            | Y      | Y     | Y      | Y         | Y           | Y            | Y       | Y           |
| TypeScript  | Y        | Y       | Y          | Y         | Y     | Y            | Y          | Y        | Y       | Y         | Y          | Y            | Y               | Y                | Y            | Y      | Y     | Y      | Y         | Y           | Y            | Y       | Y           |
| JavaScript  | Y        | Y       | -          | Y         | Y     | Y            | Y          | -        | Y       | Y         | Y          | Y            | Y               | Y                | Y            | Y      | Y     | Y      | Y         | Y           | Y            | Y       | Y           |
| Go          | Y        | Y       | Y          | -         | Y     | Y            | Y          | Y        | Y       | Y         | Y          | Y            | Y               | Y                | Y            | Y      | Y     | Y      | Y         | Y           | Y            | Y       | Y           |
| Java        | Y        | Y       | Y          | Y         | Y     | Y            | Y          | Y        | Y       | Y         | Y          | Y            | Y               | Y                | Y            | Y      | Y     | Y      | Y         | Y           | Y            | Y       | Y           |
| C           | Y        | -       | -          | -         | Y     | -            | Y          | Y        | Y       | Y         | -          | -            | Y               | Y                | -            | Y      | Y     | Y      | Y         | Y           | Y            | Y       | Y           |
| C++         | Y        | Y       | Y          | Y         | Y     | Y            | Y          | Y        | Y       | Y         | Y          | Y            | Y               | Y                | Y            | Y      | Y     | Y      | Y         | Y           | Y            | Y       | Y           |
| PHP         | Y        | Y       | Y          | Y         | Y     | Y            | Y          | Y        | Y       | Y         | Y          | Y            | Y               | Y                | -            | -      | Y     | Y      | Y         | Y           | Y            | Y       | Y           |
| Swift       | Y        | Y       | Y          | Y         | Y     | Y            | Y          | Y        | Y       | Y         | Y          | Y            | Y               | Y                | Y            | Y      | Y     | Y      | Y         | Y           | Y            | Y       | Y           |
| Kotlin      | Y        | Y       | Y          | Y         | Y     | Y            | Y          | Y        | Y       | Y         | Y          | Y            | Y               | Y                | Y            | Y      | Y     | Y      | Y         | Y           | Y            | Y       | Y           |
| HCL         | -        | -       | -          | -         | -     | -            | Y          | -        | Y       | Y         | -          | -            | Y               | Y                | -            | -      | -     | -      | Y         | Y           | Y            | Y       | Y           |
| C#          | Y        | Y       | Y          | Y         | Y     | Y            | Y          | Y        | Y       | Y         | Y          | Y            | Y               | Y                | Y            | Y      | Y     | Y      | Y         | Y           | Y            | Y       | Y           |
| Ruby        | Y        | Y       | -          | Y         | Y     | Y            | Y          | -        | Y       | Y         | Y          | Y            | Y               | Y                | Y            | Y      | Y     | Y      | Y         | Y           | Y            | Y       | Y           |

### Why certain cells are "-"

| Language | Missing Relations | Reason |
|:---------|:------------------|:-------|
| Rust     | Extends, Overrides | No class inheritance. Traits use Implements. No super dispatch. |
| Python   | Implements | No interfaces. ABCs are opt-in. `typing.Protocol` enables static analysis but isn't enforced at runtime. LSP (pyright) can infer. |
| JavaScript | UsesType, Implements | No static type system. No interfaces. |
| Go       | Overrides | No inheritance hierarchy. Embedding delegates but doesn't override. |
| C        | Extends, Implements, Overrides, Instantiates, EmitsEvent, SubscribesTo, SendsMessage | Not OOP. No classes, constructors, interfaces, event system. pthreads exist (Spawns via library) but no typed channels. |
| C++      | (all applicable) | Templates, virtual, operator overloading, std::thread, std::future, channels via libraries — full coverage. |
| PHP      | SendsMessage, Spawns | PHP is traditionally single-threaded request-response. No native channels or spawn. (Fibers in PHP 8.1 are cooperative, not concurrent.) |
| HCL      | Most | Declarative config language. No functions, types, classes, concurrency, or tests. |
| Ruby     | UsesType, Implements | No static type system (Sorbet is external). Duck typing, no interfaces. Ruby has threads and Queue but they're library-level. SendsMessage/Spawns are applicable via library. |

### Concurrency relationship details

**SendsMessage** — Entity sends a value on a typed channel, queue, or actor mailbox. The *type* of the message is the contract that links sender and receiver.

| Language | Mechanism | Language-level? |
|:---------|:----------|:----------------|
| Go | `ch <- value` / `<-ch` on `chan T` | Yes — first-class language construct |
| Rust | `tx.send(val)` / `rx.recv()` on `mpsc::channel<T>`, tokio channels, crossbeam | Library — but pervasive and strongly typed |
| Kotlin | `channel.send(val)` / `channel.receive()` via `kotlinx.coroutines` | Library (coroutine channels) |
| Swift | Actor method calls across isolation boundaries; `AsyncStream` | Language-level (actors), library (streams) |
| Java | `BlockingQueue.put(val)` / `take()`, `CompletableFuture` | Library |
| C++ | `std::promise`/`std::future`, concurrent queues | Library |
| TypeScript | `Worker.postMessage()` / `onmessage`, `MessagePort` | Web API / Node API |
| JavaScript | Same as TypeScript | Web API / Node API |
| Python | `queue.Queue.put()` / `get()`, `asyncio.Queue` | Library |
| C# | `Channel<T>.Writer.WriteAsync()` / `Reader.ReadAsync()` | Library (System.Threading.Channels) |
| Ruby | `Queue.push()` / `pop()`, `Ractor` mailbox (Ruby 3+) | Library / Ractor is language-level |

**Spawns** — Entity creates a new concurrent execution context (thread, goroutine, task, coroutine, process).

| Language | Mechanism | Language-level? |
|:---------|:----------|:----------------|
| Go | `go func()` | Yes — keyword |
| Rust | `tokio::spawn()`, `std::thread::spawn()`, `rayon::par_iter()` | Library |
| Kotlin | `launch {}`, `async {}` (coroutine builders) | Library (kotlinx.coroutines) |
| Swift | `Task {}`, `TaskGroup.addTask {}`, `async let` | Language-level |
| Java | `new Thread()`, `executor.submit()`, virtual threads (`Thread.startVirtualThread`) | Library / language (virtual threads in Java 21) |
| C++ | `std::thread()`, `std::async()`, `std::jthread()` | Library (standard library) |
| TypeScript | `new Worker()`, `Promise` (creates async context) | Web API |
| JavaScript | Same as TypeScript | Web API |
| Python | `threading.Thread()`, `asyncio.create_task()`, `multiprocessing.Process()` | Library |
| C | `pthread_create()` | Library (POSIX) |
| C# | `Task.Run()`, `Thread()`, `Parallel.ForEach()` | Library (TPL) |
| Ruby | `Thread.new {}`, `Ractor.new {}` | Library / Ractor is language-level |

---

## Matrix 2: Implementation Status

How is each relation extracted? Key:

| Code | Meaning |
|:-----|:--------|
| **TS** | Tree-sitter extracts this today |
| **LSP** | Needs LSP to extract (Phase 2+) |
| **Pat** | Pattern/convention detection (e.g., test naming) |
| **Git** | Extracted from git commit history |
| **Man** | Manual/user-provided (CODEOWNERS, etc.) |
| **Cfg** | Extracted from config/manifest files |
| **Sem** | Semantic contract analysis layer |
| **RT** | Needs runtime/coverage data |
| **—** | Not applicable to this language |

| Language    | Contains | Extends | Implements | Overrides | Calls | Instantiates | References | UsesType | Imports | DependsOn | EmitsEvent | SubscribesTo | DefinesContract | ConsumesContract | SendsMessage | Spawns | Tests | Covers | CoChanges | DerivedFrom | DocumentedBy | OwnedBy | OwnedByFile |
|:------------|:--------:|:-------:|:----------:|:---------:|:-----:|:------------:|:----------:|:--------:|:-------:|:---------:|:----------:|:------------:|:---------------:|:----------------:|:------------:|:------:|:-----:|:------:|:---------:|:-----------:|:------------:|:-------:|:-----------:|
| Rust        | TS       | —       | TS         | —         | TS    | LSP          | TS         | LSP      | TS      | Cfg       | Sem        | Sem          | Sem             | Sem              | Sem          | Sem    | Pat   | RT     | Git       | TS          | TS           | Man     | TS          |
| Python      | TS       | TS      | LSP        | LSP       | TS    | LSP          | TS         | LSP      | TS      | Cfg       | Sem        | Sem          | Sem             | Sem              | Sem          | Sem    | Pat   | RT     | Git       | Sem         | TS           | Man     | TS          |
| TypeScript  | TS       | TS      | TS         | LSP       | TS    | LSP          | TS         | LSP      | TS      | Cfg       | Sem        | Sem          | Sem             | Sem              | Sem          | Sem    | Pat   | RT     | Git       | Sem         | TS           | Man     | TS          |
| JavaScript  | TS       | TS      | —          | LSP       | TS    | LSP          | TS         | —        | TS      | Cfg       | Sem        | Sem          | Sem             | Sem              | Sem          | Sem    | Pat   | RT     | Git       | Sem         | TS           | Man     | TS          |
| Go          | TS       | TS      | TS         | —         | TS    | LSP          | TS         | LSP      | TS      | Cfg       | Sem        | Sem          | Sem             | Sem              | TS           | TS     | Pat   | RT     | Git       | Sem         | TS           | Man     | TS          |
| Java        | TS       | TS      | TS         | LSP       | TS    | LSP          | TS         | LSP      | TS      | Cfg       | Sem        | Sem          | Sem             | Sem              | Sem          | Sem    | Pat   | RT     | Git       | Sem         | TS           | Man     | TS          |
| C           | —        | —       | —          | —         | TS    | —            | TS         | LSP      | TS      | Cfg       | —          | —            | Sem             | Sem              | —            | Sem    | —     | RT     | Git       | Sem         | TS           | Man     | TS          |
| C++         | TS       | TS      | LSP        | LSP       | TS    | LSP          | TS         | LSP      | TS      | Cfg       | Sem        | Sem          | Sem             | Sem              | Sem          | Sem    | Pat   | RT     | Git       | Sem         | TS           | Man     | TS          |
| PHP         | TS       | TS      | TS         | LSP       | TS    | LSP          | TS         | LSP      | TS      | Cfg       | Sem        | Sem          | Sem             | Sem              | —            | —      | Pat   | RT     | Git       | Sem         | —            | Man     | TS          |
| Swift       | TS       | LSP     | TS         | LSP       | TS    | LSP          | TS         | LSP      | TS      | Cfg       | Sem        | Sem          | Sem             | Sem              | Sem          | Sem    | Pat   | RT     | Git       | Sem         | TS           | Man     | TS          |
| Kotlin      | TS       | TS      | TS         | LSP       | TS    | LSP          | TS         | LSP      | TS      | Cfg       | Sem        | Sem          | Sem             | Sem              | Sem          | Sem    | Pat   | RT     | Git       | Sem         | TS           | Man     | TS          |
| HCL         | —        | —       | —          | —         | —     | —            | TS         | —        | TS      | Cfg       | —          | —            | Sem             | Sem              | —            | —      | —     | —      | Git       | Sem         | —            | Man     | TS          |
| C#          | TS       | TS      | LSP        | LSP       | TS    | LSP          | TS         | LSP      | TS      | Cfg       | Sem        | Sem          | Sem             | Sem              | Sem          | Sem    | —     | RT     | Git       | Sem         | —            | Man     | TS          |
| Ruby        | TS       | TS      | —          | LSP       | TS    | LSP          | TS         | —        | TS      | Cfg       | Sem        | Sem          | Sem             | Sem              | Sem          | Sem    | —     | RT     | Git       | Sem         | —            | Man     | TS          |

### Implementation Notes

**Structural:**
- **Swift Extends = LSP:** `extract_inheritance` currently emits all Swift inheritance as Implements because tree-sitter can't distinguish superclass from protocol. LSP type resolution fixes this.
- **C++ Implements = LSP:** C++ has no `interface` keyword. Distinguishing "extends concrete base" from "implements abstract interface" requires knowing whether the base has pure virtual methods.
- **C#/Ruby Implements = LSP/—:** C# tree-sitter is shallow-backed, so interface implementation isn't extracted yet. Ruby has no interfaces.
- **Python Implements = LSP:** `typing.Protocol` conformance and ABC satisfaction require type resolution.
- **Rust DerivedFrom = TS:** `#[derive(Clone)]` is detected today. General proc-macro derivation is harder.

**Concurrency:**
- **Go SendsMessage = TS:** Channel sends (`ch <- val`) and receives (`<-ch`) are distinct AST node types in tree-sitter-go (`send_statement`, `receive_expression`). The channel variable can be matched to its typed declaration. This is one of the few languages where concurrency primitives are visible in syntax.
- **Go Spawns = TS:** `go func()` is a `go_statement` AST node — trivially detectable.
- **Most other languages = Sem:** Concurrency in most languages uses library functions (`tokio::spawn`, `Thread()`, `channel.send()`). These show up as Calls in tree-sitter, but identifying *which* calls are concurrency-related requires pattern matching on known APIs (e.g., "calls to `tokio::spawn` are Spawns, calls to `tx.send()` are SendsMessage"). This is semantic-layer work — matching known framework patterns.
- **C SendsMessage = —:** C has no typed channels. `pipe()`, shared memory, and `pthread_mutex` exist but are untyped byte streams, not typed message passing.
- **PHP = —:** PHP is fundamentally single-threaded per-request. PHP 8.1 Fibers are cooperative (not concurrent). No meaningful Spawns or SendsMessage.

---

## Gap Summary by Extraction Source

| Source | Cells done | Cells needed | What it unlocks |
|:-------|:-----------|:-------------|:----------------|
| Tree-sitter (TS) | ~112 | ~2 (Go channels, Go goroutines) | Fully exploited for what syntax can provide |
| LSP | 0 | ~35 | Overrides, UsesType, Instantiates, Swift Extends, C++ Implements, Python Implements |
| Pattern (Pat) | ~10 | ~3 (C#, Ruby test detection) | Test discovery by naming/annotation |
| Git | ~14 | 0 | CoChanges fully implemented |
| Config (Cfg) | 0 | ~14 | DependsOn from package manifests |
| Semantic (Sem) | Partial | ~60 | Contracts, events, concurrency patterns, derivation — framework-specific |
| Runtime (RT) | 0 | ~13 | Covers — needs actual test execution data |
| Manual (Man) | 0 | ~14 | OwnedBy — CODEOWNERS, user assignment |
