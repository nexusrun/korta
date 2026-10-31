package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"time"
)

type operation struct {
	ID     string `json:"id"`
	Title  string `json:"title"`
	Status string `json:"status"`
	Detail string `json:"detail"`
	Steps  []struct {
		Name   string `json:"name"`
		Status string `json:"status"`
		Detail string `json:"detail"`
	} `json:"steps"`
}

// operationID finds the operation a response started, if any.
func operationID(b []byte) string {
	var v struct {
		ID        string `json:"id"`
		Operation *struct {
			ID string `json:"id"`
		} `json:"operation"`
	}
	_ = json.Unmarshal(b, &v)
	if v.Operation != nil {
		return v.Operation.ID
	}
	if strings.HasPrefix(v.ID, "op_") {
		return v.ID
	}
	return ""
}

// wait polls an operation until it finishes, reporting each step on stderr
// so standard output stays clean for --json.
func (c *client) wait(ctx context.Context, id string) (json.RawMessage, error) {
	reported := 0 // steps already reported as finished
	announced := ""
	for {
		b, err := c.request(ctx, "GET", "/api/operations/"+url.PathEscape(id), nil)
		if err != nil {
			return nil, err
		}
		var op operation
		if err = json.Unmarshal(b, &op); err != nil {
			return nil, err
		}
		if announced == "" {
			fmt.Fprintf(c.errOut, "%s (%s)\n", clean(op.Title), op.ID)
			announced = op.ID
		}
		for ; reported < len(op.Steps) && op.Steps[reported].Status != "running"; reported++ {
			s := op.Steps[reported]
			mark := "ok"
			if s.Status == "failed" {
				mark = "FAILED"
			}
			line := fmt.Sprintf("  %-6s %s", mark, clean(s.Name))
			if s.Status == "failed" && s.Detail != "" {
				line += ": " + firstLine(clean(s.Detail))
			}
			fmt.Fprintln(c.errOut, line)
		}
		c.waited = true
		switch op.Status {
		case "succeeded":
			return b, nil
		case "failed", "cancelled", "canceled":
			return b, fmt.Errorf("%s %s: %s", firstOf(op.Title, id), op.Status, firstLine(op.Detail))
		}
		select {
		case <-ctx.Done():
			return b, fmt.Errorf("stopped waiting for %s: %w; it keeps running on the manager (korta operations wait %s)", id, ctx.Err(), id)
		case <-time.After(time.Second):
		}
	}
}

func firstLine(s string) string {
	line, _, _ := strings.Cut(strings.TrimSpace(s), "\n")
	return line
}
