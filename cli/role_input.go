package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
	"unicode/utf8"

	"github.com/nexusrun/korta/roles"
)

// Role files are Markdown by default; JSON request objects remain supported.
func (c *client) rolePayload(b []byte, explicitMarkdown bool, dir string) ([]byte, error) {
	trimmed := bytes.TrimSpace(b)
	markdown := explicitMarkdown || (c.opts.values["data"] == "" && !bytes.HasPrefix(trimmed, []byte("{")) && !bytes.HasPrefix(trimmed, []byte("[")))
	var obj map[string]any
	if markdown {
		if !utf8.Valid(b) || len(trimmed) == 0 {
			return nil, fmt.Errorf("role Markdown must be nonempty UTF-8 text")
		}
		// Template files travel with the role, read from next to it.
		files, err := roleFiles(string(b), dir)
		if err != nil {
			return nil, err
		}
		obj = map[string]any{"markdown": string(b), "files": files}
		c.roleMarkdown = true
	} else {
		if err := json.Unmarshal(b, &obj); err != nil || obj == nil {
			return nil, fmt.Errorf("role input must be a JSON object or a Markdown file")
		}
	}
	if c.opts.args[1] == "preview" {
		return marshalRoleInput(obj)
	}
	o := c.opts
	for flag, key := range map[string]string{"name": "name", "description": "description"} {
		if v, ok := o.values[flag]; ok {
			obj[key] = v
		}
	}
	if markdown && o.args[1] == "create" && o.values["name"] == "" {
		return nil, fmt.Errorf("creating a role from Markdown requires --name ROLE_NAME")
	}
	if o.set("instance") || o.set("label") {
		targets := map[string]any{}
		if ids := o.list("instance"); len(ids) > 0 {
			targets["instanceIDs"] = ids
		} else if o.set("instance") {
			return nil, fmt.Errorf("--instance needs instance IDs")
		}
		labels, err := o.labels("label")
		if err != nil {
			return nil, err
		}
		if len(labels) > 0 {
			targets["labels"] = labels
		}
		obj["targets"] = targets
	}
	if v, ok := o.values["batch-size"]; ok {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > 100 {
			return nil, fmt.Errorf("--batch-size must be 1-100")
		}
		rollout, _ := obj["rollout"].(map[string]any)
		if rollout == nil {
			rollout = map[string]any{}
		}
		rollout["batchSize"] = n
		obj["rollout"] = rollout
	}
	if _, ok := o.values["continue-on-failure"]; ok {
		rollout, _ := obj["rollout"].(map[string]any)
		if rollout == nil {
			rollout = map[string]any{}
		}
		rollout["continueOnFailure"] = o.yes("continue-on-failure")
		obj["rollout"] = rollout
	}
	if markdown && o.args[1] == "create" && obj["targets"] == nil {
		aws, err := roles.ProvisionsAWS(string(b))
		if err != nil {
			return nil, err
		}
		gcp, err := roles.ParseGCP(string(b))
		if err != nil {
			return nil, err
		}
		if !aws && gcp == nil {
			return nil, fmt.Errorf("choose role targets with --instance INSTANCE_ID or --label KEY=VALUE")
		}
	}
	return marshalRoleInput(obj)
}

func marshalRoleInput(obj map[string]any) ([]byte, error) {
	b, err := json.Marshal(obj)
	if len(b) > 1<<20 {
		return nil, fmt.Errorf("encoded role request exceeds 1 MiB")
	}
	return b, err
}

// Replacing a role's Markdown preserves its name, description, targets and rollout.
func (c *client) mergeRoleUpdate(ctx context.Context, path string, body []byte) ([]byte, error) {
	current, err := c.request(ctx, "GET", path, nil)
	if err != nil {
		return nil, err
	}
	var role roles.Role
	if err = json.Unmarshal(current, &role); err != nil {
		return nil, err
	}
	clean, _ := json.Marshal(role)
	var base, patch map[string]any
	if err = json.Unmarshal(clean, &base); err != nil {
		return nil, err
	}
	if err = json.Unmarshal(body, &patch); err != nil {
		return nil, err
	}
	for k, v := range patch {
		if k == "rollout" {
			old, _ := base[k].(map[string]any)
			if old == nil {
				old = map[string]any{}
			}
			for key, value := range v.(map[string]any) {
				old[key] = value
			}
			base[k] = old
		} else {
			base[k] = v
		}
	}
	return marshalRoleInput(base)
}

// currentPlan fills in the role's newest valid plan when apply is given no
// --plan, and says on stderr which plan and risks are being approved.
func (c *client) currentPlan(ctx context.Context, id string, body []byte) ([]byte, error) {
	b, err := c.request(ctx, "GET", "/api/roles/"+url.PathEscape(id), nil)
	if err != nil {
		return nil, err
	}
	var r struct {
		Name    string   `json:"name"`
		Version int      `json:"version"`
		Risks   []string `json:"risks"`
		Plan    *struct {
			OperationID string   `json:"operationID"`
			InstanceIDs []string `json:"instanceIDs"`
			Changes     int      `json:"changes"`
		} `json:"plan"`
	}
	if err = json.Unmarshal(b, &r); err != nil {
		return nil, err
	}
	if r.Plan == nil {
		return nil, fmt.Errorf("role %s v%d has no valid plan; run korta roles plan %s and review it first", r.Name, r.Version, id)
	}
	fmt.Fprintf(c.errOut, "Approving plan %s for %s v%d: %s on %s.\n", r.Plan.OperationID, r.Name, r.Version, count(strconv.Itoa(r.Plan.Changes), "change"), count(strconv.Itoa(len(r.Plan.InstanceIDs)), "instance"))
	for _, risk := range r.Risks {
		fmt.Fprintf(c.errOut, "  review: %s\n", clean(risk))
	}
	var req map[string]any
	if err = json.Unmarshal(body, &req); err != nil {
		return nil, err
	}
	req["planID"] = r.Plan.OperationID
	return json.Marshal(req)
}

// previewResult prints the compiled steps, or fails with the first mistake
// in the Markdown so scripts and CI can rely on the exit status.
func (c *client) previewResult(res []byte) error {
	var p struct {
		Error string           `json:"error"`
		Steps []map[string]any `json:"steps"`
		Risks []string         `json:"risks"`
	}
	if err := json.Unmarshal(res, &p); err != nil {
		return err
	}
	if c.format() == "json" {
		if err := c.print(res); err != nil {
			return err
		}
	} else if p.Error == "" {
		for i, s := range p.Steps {
			fmt.Fprintf(c.out, "%2d. %-10s %s\n", i+1, clean(str(s, "type")), clean(str(s, "name")))
		}
		for _, r := range p.Risks {
			fmt.Fprintf(c.out, "review: %s\n", clean(r))
		}
	}
	if p.Error != "" {
		return fmt.Errorf("%s", p.Error)
	}
	return nil
}
