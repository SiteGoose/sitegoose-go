package sitegoose

// Feature flags module: turn features of your app on or off from the
// dashboard (Site settings -> Server), for everyone, a share of users, or
// listed user IDs. IsEnabled answers from memory; the flags come with the
// module switches (core), about once a minute.

import (
	"encoding/json"
	"fmt"
	"math"
)

type flagRule struct {
	on      bool
	users   []string
	rollout int64
}

func parseFlag(raw json.RawMessage) (flagRule, bool) {
	var data map[string]any
	if json.Unmarshal(raw, &data) != nil || data == nil {
		return flagRule{}, false
	}
	rule := flagRule{on: data["on"] == true, rollout: 100}
	if _, given := data["rollout"]; given {
		switch v := data["rollout"].(type) {
		case float64:
			rule.rollout = int64(math.Trunc(v))
		default:
			rule.rollout = num(v)
		}
	}
	for _, u := range stringList(data["users"]) {
		rule.users = append(rule.users, u)
	}
	return rule, true
}

// flagBucket is FNV-1a over "key:user", 0-99: the same as the Node, PHP and
// Python packages, so a user is in or out of a rollout on every server.
func flagBucket(key, user string) uint32 {
	h := uint32(0x811C9DC5)
	for _, b := range []byte(fmt.Sprintf("%s:%s", key, user)) {
		h ^= uint32(b)
		h *= 0x01000193
	}
	return h % 100
}

func (f flagRule) evaluate(key, user string) bool {
	if !f.on {
		return false
	}
	if user != "" && containsString(f.users, user) {
		return true
	}
	if f.rollout >= 100 {
		return true
	}
	if f.rollout <= 0 || user == "" {
		return false
	}
	return int64(flagBucket(key, user)) < f.rollout
}
