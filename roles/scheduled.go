package roles

import (
	"fmt"
	"strconv"
	"strings"
)

// validateSchedule accepts portable, numeric five-field cron expressions.
func validateSchedule(schedule string) error {
	fields := strings.Fields(schedule)
	if len(fields) != 5 || strings.Join(fields, " ") != schedule {
		return fmt.Errorf("schedule must be five cron fields separated by single spaces")
	}
	limits := [][2]int{{0, 59}, {0, 23}, {1, 31}, {1, 12}, {0, 7}}
	for i, field := range fields {
		for _, part := range strings.Split(field, ",") {
			base, step, stepped := strings.Cut(part, "/")
			if stepped {
				n, err := strconv.Atoi(step)
				if err != nil || n < 1 || n > limits[i][1] || strings.Contains(step, "+") || strings.Contains(step, "-") {
					return fmt.Errorf("invalid cron schedule field %q", field)
				}
			}
			if base == "*" {
				continue
			}
			a, b, ranged := strings.Cut(base, "-")
			start, err := strconv.Atoi(a)
			if err != nil || start < limits[i][0] || start > limits[i][1] || !digits(a) {
				return fmt.Errorf("invalid cron schedule field %q", field)
			}
			if ranged {
				end, err := strconv.Atoi(b)
				if err != nil || !digits(b) || end < start || end > limits[i][1] {
					return fmt.Errorf("invalid cron schedule field %q", field)
				}
			} else if stepped {
				return fmt.Errorf("cron steps need * or a range in %q", field)
			}
		}
	}
	return nil
}

func digits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

func parseScheduledJob(it mdItem) ([]Step, error) {
	s := Step{Type: "scheduled-job", Job: strings.TrimSpace(it.text)}
	seen := map[string]bool{}
	for _, line := range it.extra {
		key, value, ok := strings.Cut(line, ":")
		key, value = strings.TrimSpace(key), strings.TrimSpace(value)
		if !ok || value == "" || seen[key] {
			return nil, it.errorf("use unique schedule, user and state fields")
		}
		seen[key] = true
		switch key {
		case "schedule":
			s.Schedule = value
		case "user":
			s.User = value
		case "state":
			s.State = value
		default:
			return nil, it.errorf("unknown scheduled job field %q", key)
		}
	}
	if it.code != nil {
		s.Run = *it.code
	}
	if err := s.normalize(); err != nil {
		return nil, it.errorf("%v", err)
	}
	return []Step{s}, nil
}
