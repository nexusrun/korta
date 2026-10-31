package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
)

// runRole finishes korta roles run (and destroy) once its plan succeeded:
// it shows the plan, asks for approval unless --approve is given, applies
// exactly that plan and waits. When the manager requires a second
// approver, the plan is left for them.
func (c *client) runRole(ctx context.Context, id string, plan json.RawMessage) error {
	if err := c.print(plan); err != nil {
		return err
	}
	planID := operationID(plan)
	if planID == "" {
		return fmt.Errorf("the manager returned no plan; run korta roles plan %s", id)
	}
	if !c.opts.yes("approve") {
		if err := c.confirm("Approve and apply this plan?"); err != nil {
			return err
		}
	}
	body, err := json.Marshal(map[string]any{"planID": planID, "approve": true, "confirmCommands": c.opts.yes("confirm-commands"), "confirm": c.opts.values["confirm"]})
	if err != nil {
		return err
	}
	res, err := c.request(ctx, "POST", "/api/roles/"+url.PathEscape(id)+"/apply", body)
	if err != nil {
		if strings.Contains(err.Error(), "someone else must approve") {
			again := ""
			if c.opts.values["confirm"] != "" {
				again = " --confirm " + c.opts.values["confirm"]
			}
			return fmt.Errorf("planned and waiting for approval: you changed or planned this role, so someone with approver access applies it with: korta roles apply %s --approve%s", id, again)
		}
		return err
	}
	if op := operationID(res); op != "" {
		if res, err = c.wait(ctx, op); err != nil {
			_ = c.print(res)
			return err
		}
	}
	return c.print(res)
}
