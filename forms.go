package sitegoose

// Form protection module: checks a form your server received before you
// accept it (POST /collectanalytics/shield/verify, the same check as spam
// protection's). It reads the hidden "analytics-shield" answer the tracker
// puts in protected forms, and checks the email, name and text for fake
// sign-ups. Spam lands in the site's spam folder (Leads -> Spam). Passwords,
// card numbers and tokens are never sent. Fails open: when the check can't be
// made, the form is accepted (Checked false).

import (
	"context"
	"net/http"
	"regexp"
	"sort"
	"strings"
)

var privateField = regexp.MustCompile(`(?i)pass|card|cvc|cvv|secret|token|ssn|iban|csrf|analytics-shield`)

const (
	maxFormFields = 50
	shieldAnswer  = "analytics-shield"
)

// FormOptions say what the form is; Fields default to the request's form.
type FormOptions struct {
	Fields map[string][]string
	Email  string
	Name   string
	Form   string
}

// FormResult is the check's answer. OK is false only for spam.
type FormResult struct {
	OK      bool     `json:"ok"`
	Spam    bool     `json:"spam"`
	Reasons []string `json:"reasons"`
	Checked bool     `json:"checked"`
}

func plainFields(fields map[string][]string) map[string]string {
	names := make([]string, 0, len(fields))
	for name := range fields {
		names = append(names, name)
	}
	sort.Strings(names)
	out := map[string]string{}
	for i, name := range names {
		if i == maxFormFields {
			break
		}
		if privateField.MatchString(name) {
			continue
		}
		out[truncate(name, 100)] = truncate(strings.Join(fields[name], ", "), 2000)
	}
	return out
}

func checkForm(ctx context.Context, c *core, fields map[string][]string, ip string, o FormOptions) FormResult {
	unchecked := FormResult{OK: true, Reasons: []string{"unchecked"}}
	if !c.isOn(ModuleForms) {
		return FormResult{OK: true, Reasons: []string{}}
	}
	token := ""
	if v := fields[shieldAnswer]; len(v) > 0 {
		token = v[0]
	}
	body := map[string]any{"token": token, "fields": plainFields(fields), "ip": ip}
	if o.Email != "" {
		body["email"] = o.Email
	}
	if o.Name != "" {
		body["name"] = o.Name
	}
	if o.Form != "" {
		body["form"] = o.Form
	}
	res := c.send(ctx, "forms", "/collectanalytics/shield/verify", http.MethodPost, body, authBody, nil)
	if res == nil || res.status >= 500 || res.status == 403 || res.status == 429 {
		if res != nil && res.status == 403 {
			c.log("forms", "the site secret was refused; forms aren't checked")
		}
		return unchecked
	}
	var data struct {
		Success *bool    `json:"success"`
		Reasons []string `json:"reasons"`
	}
	res.json(&data)
	spam := data.Success != nil && !*data.Success
	reasons := data.Reasons
	if reasons == nil {
		reasons = []string{}
	}
	return FormResult{OK: !spam, Spam: spam, Reasons: reasons, Checked: true}
}
