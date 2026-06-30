package cli

import (
	"fmt"
	"io"
	"strings"

	"github.com/chzyer/readline"
)

// Shell wraps readline to provide history, tab completion, and masked input.
type Shell struct {
	rl      *readline.Instance
	handler *Handler
}

func NewShell(handler *Handler, historyFile string) (*Shell, error) {
	completer := readline.NewPrefixCompleter(
		readline.PcItem("register"),
		readline.PcItem("login"),
		readline.PcItem("logout"),
		readline.PcItem("whoami"),
		readline.PcItem("help"),
		readline.PcItem("exit"),
	)

	rl, err := readline.NewEx(&readline.Config{
		Prompt:          "authctl> ",
		HistoryFile:     historyFile,
		AutoComplete:    completer,
		InterruptPrompt: "^C",
		EOFPrompt:       "exit",
	})
	if err != nil {
		return nil, fmt.Errorf("init readline: %w", err)
	}

	return &Shell{rl: rl, handler: handler}, nil
}

func (s *Shell) Run() error {
	defer s.rl.Close()

	for {
		line, err := s.rl.Readline()
		if err == readline.ErrInterrupt {
			continue
		}
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}

		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if line == "exit" || line == "quit" {
			return nil
		}

		s.handler.Dispatch(line)
	}
}

// readlinePrompter adapts *readline.Instance to the Prompter interface.
type readlinePrompter struct {
	rl *readline.Instance
}

func NewReadlinePrompter(rl *readline.Instance) Prompter {
	return &readlinePrompter{rl: rl}
}

func (p *readlinePrompter) ReadPassword(prompt string) (string, error) {
	b, err := p.rl.ReadPassword(prompt)
	return string(b), err
}

func (p *readlinePrompter) ReadLine(prompt string) (string, error) {
	p.rl.SetPrompt(prompt)
	defer p.rl.SetPrompt("authctl> ")
	return p.rl.Readline()
}
