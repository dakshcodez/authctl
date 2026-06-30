# Phase 5 — CLI

The CLI layer renders output, reads user input, and dispatches commands to the service. It makes no authentication decisions and contains no SQL. Its only job is to be a correct, pleasant interface to the service layer.

## Files

```
internal/cli/
  banner.go        — PrintBanner(), PrintReady()
  handler.go       — Handler, Prompter interface, command dispatch
  shell.go         — Shell (readline loop), readlinePrompter, ErrInterrupted
  style.go         — ANSI color helpers, success/warn/fail printers
  userinfo.go      — renderLoginPanel(), renderWhoamiPanel()
  handler_test.go  — unit tests with fake prompter and fake service
```

## Architecture

```
shell.Run()
  └─ readline loop
       └─ handler.Dispatch(line)
            ├─ register()
            ├─ login()  → loginMFAStep() if ErrMFARequired
            ├─ logout()
            ├─ whoami()
            ├─ mfa() → mfaSetup / mfaEnable / mfaDisable
            ├─ clear
            └─ help
```

The `Shell` owns the readline loop. The `Handler` owns dispatch and all command logic. They are separate types so tests can call `Handler.Dispatch` directly without a TTY.

## Prompter interface

```go
type Prompter interface {
    ReadPassword(prompt string) (string, error)
    ReadLine(prompt string) (string, error)
    SetPrompt(prompt string)
}
```

All terminal I/O goes through this interface. The production implementation wraps `*readline.Instance`. Tests inject a `fakePrompter` backed by slices of prepared responses. This means handler tests run without a TTY.

## Shell and readline

`shell.go` wires `github.com/chzyer/readline` into the `Prompter` interface.

### Tab completion

```go
readline.NewPrefixCompleter(
    readline.PcItem("register"),
    readline.PcItem("login"),
    readline.PcItem("mfa",
        readline.PcItem("setup"),
        readline.PcItem("enable"),
        readline.PcItem("disable"),
    ),
    // ...
)
```

Tab completes top-level commands and `mfa` subcommands. `history.txt` persists command history across sessions.

### `readlinePrompter.ReadPassword` and the prompt reset bug

`readline.ReadPassword` has an internal side effect: after returning, it resets the readline instance's active prompt back to the value set in `readline.Config.Prompt` (the startup default `"authctl> "`). Without a fix, pressing Enter after a password prompt would revert the prompt from `authctl(alice)>` back to `authctl>`.

The fix is unconditional:

```go
func (p *readlinePrompter) ReadPassword(prompt string) (string, error) {
    b, err := p.rl.ReadPassword(prompt)
    p.rl.SetPrompt(p.currentPrompt) // restore the dynamically set prompt
    if err == readline.ErrInterrupt {
        return "", ErrInterrupted
    }
    return string(b), err
}
```

`p.currentPrompt` is the value last set by `SetPrompt`. This restoration happens even on error, so `^C` during password input also leaves the prompt correct.

### `ErrInterrupted`

```go
var ErrInterrupted = errors.New("interrupted")
```

`readline.ErrInterrupt` (`^C` during any input) is translated to `ErrInterrupted` by both `ReadPassword` and `ReadLine`. `Dispatch` handles it at the top level:

```go
if errors.Is(err, ErrInterrupted) {
    fmt.Fprintln(h.out) // move to clean line
    return
}
```

The shell loop continues. The username displayed in the prompt is preserved. Without this, `^C` during password input would leave the shell on the wrong line and lose the prompt state.

### `ReadLine` and prompt isolation

```go
func (p *readlinePrompter) ReadLine(prompt string) (string, error) {
    saved := p.currentPrompt
    p.rl.SetPrompt(prompt)
    defer p.rl.SetPrompt(saved)
    line, err := p.rl.Readline()
    // ...
}
```

`ReadLine` saves the current shell prompt, replaces it with the inline prompt (e.g., `"Username: "`), reads a line, and restores the saved prompt via `defer`. This prevents the per-field prompt from leaking into the shell loop.

## Handler dispatch

```go
func (h *Handler) Dispatch(input string) {
    parts := strings.Fields(input)
    cmd, args := parts[0], parts[1:]

    switch cmd {
    case "register": err = h.register(args)
    case "login":    err = h.login(args)
    // ...
    case "clear":    fmt.Fprint(h.out, "\033[H\033[2J")
    }
    // ...
}
```

- Commands that accept an optional username as an argument (`register`, `login`) check `args[0]` first and fall back to prompting.
- `clear` is handled inline: ANSI escape `\033[H\033[2J` moves the cursor to the top and erases the screen.
- Unknown commands print a warning, not an error, so the shell continues.

## Guard patterns

**Login guard in `register`:**
```go
if stored, err := h.store.Load(); err == nil {
    warn(h.out, "You are logged in as %s. Please logout first.", stored.Username)
    return nil
}
```

**Double-login guard in `login`:**
```go
if stored, err := h.store.Load(); err == nil {
    warn(h.out, "You are already logged in as %s. Please logout first.", stored.Username)
    return nil
}
```

Both are warnings, not errors. The shell continues.

## MFA login flow

```go
result, err := h.auth.Login(ctx, username, password)
if errors.Is(err, service.ErrMFARequired) {
    result, err = h.loginMFAStep(username, password)
}
```

`ErrMFARequired` is a signal, not an error. The CLI uses it to branch into the MFA prompt path without storing any intermediate state. `loginMFAStep` prompts for the TOTP code and calls `LoginWithMFA`, which re-verifies both the password and the TOTP code together.

## Prompt styling

ANSI codes in prompts must be wrapped in `\001...\002` so readline can compute the visible width correctly:

```go
func UserPrompt(username string) string {
    return "\001\033[32m\002authctl(\001\033[1m\002" + username + "\001\033[0;32m\002)\001\033[0m\002> "
}
```

Without `\001\002`, readline counts ANSI escape characters as visible width. This causes the cursor to misalign when editing long input lines — characters appear to jump to the wrong position.

## Output conventions (`style.go`)

All output uses three helpers:
- `success(w, fmt, ...)` — green checkmark
- `warn(w, fmt, ...)` — yellow warning symbol
- `fail(w, fmt, ...)` — red X

`fail` is only for unexpected errors. Known service errors (wrong password, locked account) are mapped to human messages via `userMessage(err)` before being passed to `fail`.

## Testing

`handler_test.go` tests all commands via `Handler.Dispatch` with:
- `fakePrompter` — responds with prepared values from `nextLines` / `nextPasswords`; can inject `ErrInterrupted` via `nextPwErr`
- `fakeAuth` — implements `AuthService` with configurable return values
- `fakeStore` — in-memory implementation of `session.Store`

Tests verify the output written to a `bytes.Buffer` and the state of the fake store. No TTY required.
