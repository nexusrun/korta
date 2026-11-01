package roles

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestScheduledJob(t *testing.T) {
	md := "# Scheduled jobs\n- cleanup\n  - schedule: 0 2 * * 0\n  - user: app\n\n  ```sh\n  /usr/local/bin/cleanup\n  ```\n"
	r := Role{Name: "jobs", Markdown: md, Targets: Targets{InstanceIDs: []string{"host"}}}
	if err := r.Normalize(); err != nil {
		t.Fatal(err)
	}
	if len(r.Steps) != 1 || r.Steps[0].Schedule != "0 2 * * 0" || r.Steps[0].User != "app" || !r.HasCommand() {
		t.Fatalf("%+v", r)
	}
	round := Role{Name: "jobs", Markdown: ToMarkdown(r.Steps), Targets: r.Targets}
	if err := round.Normalize(); err != nil {
		t.Fatalf("%s: %v", round.Markdown, err)
	}
	if round.Steps[0].Run != r.Steps[0].Run || round.Steps[0].Schedule != r.Steps[0].Schedule {
		t.Fatal("round trip changed job")
	}
	for _, bad := range []string{
		"# Scheduled jobs\n- job\n  - schedule: 60 * * * *\n\n  ```\n  echo hi\n  ```\n",
		"# Scheduled jobs\n- job\n  - schedule: * * * * *;id\n\n  ```\n  echo hi\n  ```\n",
		"# Scheduled jobs\n- job\n  - schedule: * * * * *\n  - user: root;id\n\n  ```\n  echo hi\n  ```\n",
		"# Scheduled jobs\n- job\n  - schedule: * * * * *\n\n  ```\n  echo {{ secret.password }}\n  ```\n",
	} {
		role := Role{Name: "jobs", Markdown: bad, Targets: r.Targets}
		if err := role.Normalize(); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
	step := r.Steps[0]
	for _, apply := range []bool{false, true} {
		script, err := Script("jobs", step, Host{}, apply, false)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(script, "/etc/cron.d/xela-") || (!apply && strings.Contains(script, "mktemp")) {
			t.Fatal(script)
		}
	}
}

func TestScheduleFields(t *testing.T) {
	for _, schedule := range []string{"*/5 0-23/2 1,15 * 1-5", "0 0 1 1 0"} {
		if err := validateSchedule(schedule); err != nil {
			t.Errorf("%s: %v", schedule, err)
		}
	}
	for _, schedule := range []string{"* * * *", "*/0 * * * *", "* * 0 * *", "* * * 13 *", "* * * * 8", "1/2 * * * *", "*  * * * *"} {
		if err := validateSchedule(schedule); err == nil {
			t.Errorf("accepted %s", schedule)
		}
	}
}

func TestScheduledJobPlanApplyRemove(t *testing.T) {
	dir := t.TempDir()
	for name, body := range map[string]string{
		"getent": "#!/bin/sh\nexit 0\n", "chown": "#!/bin/sh\nexit 0\n", "stat": "#!/bin/sh\nprintf '644:0:0\\n'\n", "restorecon": "#!/bin/sh\nexit 0\n",
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0700); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	s := Step{Type: "scheduled-job", Job: "cleanup", Schedule: "0 2 * * 0", User: "root", State: "present", Run: "echo hello\n"}
	run := func(apply bool) string {
		t.Helper()
		script, err := Script("jobs", s, Host{}, apply, false)
		if err != nil {
			t.Fatal(err)
		}
		script = strings.ReplaceAll(script, "/etc/cron.d", dir)
		out, err := exec.Command("sh", "-c", script).CombinedOutput()
		if err != nil {
			t.Fatalf("%s: %v", out, err)
		}
		return string(out)
	}
	if !strings.Contains(run(false), "KORTA_RESULT changed") {
		t.Fatal("plan missed change")
	}
	files, _ := filepath.Glob(filepath.Join(dir, "xela-*"))
	if len(files) != 0 {
		t.Fatal("plan wrote cron file")
	}
	if !strings.Contains(run(true), "KORTA_RESULT changed") || !strings.Contains(run(false), "KORTA_RESULT ok") {
		t.Fatal("job did not converge")
	}
	s = Step{Type: "scheduled-job", Job: "cleanup", State: "absent"}
	if !strings.Contains(run(false), "KORTA_RESULT changed") {
		t.Fatal("plan missed removal")
	}
	files, _ = filepath.Glob(filepath.Join(dir, "xela-*"))
	if len(files) != 1 {
		t.Fatal("plan removed cron file")
	}
	if !strings.Contains(run(true), "KORTA_RESULT changed") || !strings.Contains(run(false), "KORTA_RESULT ok") {
		t.Fatal("job did not remove")
	}
}
