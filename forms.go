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

// privateField: fields never sent, by name. ProtectForm hands over the whole
// request, so whoever adds it to a sign-up or a checkout route relies on this
// list: keep it wide, and the same in every package (cc-number and cc-csc
// are the browser's own autocomplete names). ("pass" also covers passwd
// and passport.)
var privateField = regexp.MustCompile(`(?i)pass|pwd|card|cc[-_]?(num|no|number|csc|exp)|cvc|cvv|cvn|expiry|exp[-_]?(month|year|date)|secret|token|\bauth\b|authoriz|api[-_]?key|otp|mfa|2fa|\bpin\b|security[-_]?code|signature|private|ssn|sin\b|nino|tax[-_]?id|iban|bic|swift|routing|account[-_]?(no|num|number)|dob|birth|licen[cs]e|csrf|nonce|analytics-shield`)

// cardDigits: a card number in a field nobody thought to name "card" still
// must not be sent, so values are checked too: 13-19 digits that pass Luhn
// are taken out of the text and the rest of the message is kept, so spam is
// still judged.
var cardDigits = regexp.MustCompile(`\b(?:\d[ -]?){12,18}\d\b`)

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
		out[truncate(name, 100)] = withoutCardNumbers(truncate(strings.Join(fields[name], ", "), 2000))
	}
	return out
}

// withoutCardNumbers replaces anything shaped like a card number, and
// passing Luhn, with [removed]. Luhn is what keeps order numbers and phone
// numbers readable.
func withoutCardNumbers(text string) string {
	return cardDigits.ReplaceAllStringFunc(text, func(match string) string {
		sum, alt := 0, false
		for i := len(match) - 1; i >= 0; i-- {
			c := match[i]
			if c < '0' || c > '9' {
				continue
			}
			n := int(c - '0')
			if alt {
				n *= 2
				if n > 9 {
					n -= 9
				}
			}
			sum += n
			alt = !alt
		}
		if sum%10 == 0 {
			return "[removed]"
		}
		return match
	})
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
	// A verdict, spam or not, is always a 200 with `success`. Anything else
	// judged nothing, and must not look like protection that works.
	if res.status != http.StatusOK || !res.json(&data) || data.Success == nil {
		return unchecked
	}
	spam := !*data.Success
	reasons := data.Reasons
	if reasons == nil {
		reasons = []string{}
	}
	return FormResult{OK: !spam, Spam: spam, Reasons: reasons, Checked: true}
}
