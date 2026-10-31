package cli

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/coder/websocket"
	"golang.org/x/term"
)

// readToken asks for the admin token without echoing it, or reads one line
// from a pipe without a prompt.
func readToken(in io.Reader, out io.Writer) (string, error) {
	if f, ok := in.(*os.File); ok && term.IsTerminal(int(f.Fd())) {
		fmt.Fprint(out, "Admin token: ")
		b, err := term.ReadPassword(int(f.Fd()))
		fmt.Fprintln(out)
		return strings.TrimSpace(string(b)), err
	}
	line, err := bufio.NewReader(in).ReadString('\n')
	if err == io.EOF && line != "" {
		err = nil
	}
	return strings.TrimSpace(line), err
}

// secretValue reads a secret from --value-file, a hidden prompt, or stdin.
// Trailing newlines are removed.
func (c *client) secretValue(name string) (string, error) {
	var b []byte
	var err error
	f, isFile := c.in.(*os.File)
	switch path := c.opts.values["value-file"]; {
	case path != "" && path != "-":
		b, err = os.ReadFile(path)
	case path == "" && isFile && term.IsTerminal(int(f.Fd())):
		fmt.Fprintf(c.errOut, "Value for %s: ", name)
		b, err = term.ReadPassword(int(f.Fd()))
		fmt.Fprintln(c.errOut)
	default:
		b, err = io.ReadAll(io.LimitReader(c.in, 64<<10+1))
	}
	if err != nil {
		return "", err
	}
	value := strings.TrimRight(string(b), "\r\n")
	switch {
	case value == "":
		return "", fmt.Errorf("the value for %s is empty", name)
	case len(value) > 64<<10:
		return "", fmt.Errorf("a secret must be at most 64 KiB")
	}
	return value, nil
}

// console attaches the terminal to an SSH session on the instance. Terminal
// bytes travel as binary frames, resizes and notices as JSON text frames.
func (c *client) console(ctx context.Context, path string) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	u, _ := url.Parse(c.base + path)
	if u.Scheme == "https" {
		u.Scheme = "wss"
	} else {
		u.Scheme = "ws"
	}
	cols, rows := 80, 24
	f, isFile := c.in.(*os.File)
	interactive := isFile && term.IsTerminal(int(f.Fd()))
	if interactive {
		if w, h, err := term.GetSize(int(f.Fd())); err == nil {
			cols, rows = w, h
		}
	}
	q := u.Query()
	q.Set("cols", fmt.Sprint(cols))
	q.Set("rows", fmt.Sprint(rows))
	u.RawQuery = q.Encode()
	header := http.Header{}
	header.Set("Authorization", "Bearer "+c.token)
	ws, resp, err := websocket.Dial(ctx, u.String(), &websocket.DialOptions{HTTPClient: c.http, HTTPHeader: header})
	if err != nil {
		if resp != nil {
			return fmt.Errorf("console HTTP %d: %w", resp.StatusCode, err)
		}
		return err
	}
	defer ws.CloseNow()
	restore := func() {}
	if interactive {
		state, err := term.MakeRaw(int(f.Fd()))
		if err != nil {
			return err
		}
		var once sync.Once
		restore = func() { once.Do(func() { _ = term.Restore(int(f.Fd()), state) }) }
	}
	defer restore()
	go func() {
		buf := make([]byte, 4096)
		for {
			n, err := c.in.Read(buf)
			if n > 0 {
				if e := ws.Write(ctx, websocket.MessageBinary, buf[:n]); e != nil {
					return
				}
			}
			if err != nil {
				_ = ws.Close(websocket.StatusNormalClosure, "")
				return
			}
		}
	}()
	// Poll dimensions to support resizing on all platforms without platform-specific signals.
	if interactive {
		go func() {
			ticker := time.NewTicker(250 * time.Millisecond)
			defer ticker.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
					w, h, e := term.GetSize(int(f.Fd()))
					if e == nil && (w != cols || h != rows) {
						cols, rows = w, h
						b, _ := json.Marshal(map[string]any{"type": "resize", "cols": w, "rows": h})
						if ws.Write(ctx, websocket.MessageText, b) != nil {
							return
						}
					}
				}
			}
		}()
	}
	for {
		kind, b, err := ws.Read(ctx)
		if err != nil {
			restore()
			if websocket.CloseStatus(err) == websocket.StatusNormalClosure {
				return nil
			}
			return fmt.Errorf("console disconnected: %w", err)
		}
		if kind == websocket.MessageBinary {
			if _, err = c.out.Write(b); err != nil {
				return err
			}
			continue
		}
		var msg struct{ Type, Message string }
		if json.Unmarshal(b, &msg) == nil {
			switch msg.Type {
			case "error":
				restore()
				return fmt.Errorf("console: %s", clean(msg.Message))
			case "closed":
				// Print after leaving raw mode, or the line breaks oddly.
				restore()
				fmt.Fprintln(c.errOut, clean(msg.Message))
				return nil
			}
		}
	}
}
