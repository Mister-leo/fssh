package i18n

import (
	"regexp"
	"testing"
)

// withDetection stubs every detection source and resets the cached language.
func withDetection(t *testing.T, env map[string]string, cfgLang, appleLang string) {
	t.Helper()
	for _, k := range []string{"FSSH_LANG", "LC_ALL", "LC_MESSAGES", "LANG"} {
		t.Setenv(k, env[k])
	}
	origCfg, origApple := configLanguage, appleLanguages
	configLanguage = func() string { return cfgLang }
	appleLanguages = func() string { return appleLang }
	Set("")
	t.Cleanup(func() {
		configLanguage, appleLanguages = origCfg, origApple
		Set("")
	})
}

func TestDetectOrder(t *testing.T) {
	cases := []struct {
		name  string
		env   map[string]string
		cfg   string
		apple string
		want  Lang
	}{
		{"FSSH_LANG wins", map[string]string{"FSSH_LANG": "en", "LANG": "zh_CN.UTF-8"}, "zh", "zh-Hans", EN},
		{"config before LANG", map[string]string{"LANG": "en_US.UTF-8"}, "zh", "", ZH},
		{"LC_ALL before LANG", map[string]string{"LC_ALL": "zh_CN.UTF-8", "LANG": "en_US.UTF-8"}, "", "", ZH},
		{"LANG", map[string]string{"LANG": "zh_TW.UTF-8"}, "", "en", ZH},
		{"POSIX locale falls through to Apple", map[string]string{"LANG": "C.UTF-8"}, "", "zh-Hans-CN", ZH},
		{"launchd: only Apple languages", nil, "", "zh-Hans-CN", ZH},
		{"nothing set defaults to English", nil, "", "", EN},
		{"non-Chinese locale is English", map[string]string{"LANG": "ja_JP.UTF-8"}, "", "zh-Hans", EN},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			withDetection(t, c.env, c.cfg, c.apple)
			if got := Current(); got != c.want {
				t.Errorf("Current() = %q, want %q", got, c.want)
			}
		})
	}
}

func TestFirstAppleLanguage(t *testing.T) {
	out := "(\n    \"zh-Hans-CN\",\n    \"en-CN\"\n)\n"
	if got := firstAppleLanguage(out); got != "zh-Hans-CN" {
		t.Errorf("got %q", got)
	}
	if got := firstAppleLanguage(""); got != "" {
		t.Errorf("empty output: got %q", got)
	}
}

func TestTFallbacks(t *testing.T) {
	withDetection(t, map[string]string{"FSSH_LANG": "zh"}, "", "")
	if got := T("cli.unknown_command", "foo"); got != "未知命令: foo" {
		t.Errorf("zh: got %q", got)
	}
	Set(EN)
	if got := T("cli.unknown_command", "foo"); got != "unknown command: foo" {
		t.Errorf("en: got %q", got)
	}
	if got := T("no.such.key"); got != "no.such.key" {
		t.Errorf("unknown key: got %q", got)
	}
}

var verbRe = regexp.MustCompile(`%[-+# 0]*[0-9]*(\.[0-9]+)?[a-zA-Z%]`)

func verbs(s string) []string { return verbRe.FindAllString(s, -1) }

// Every message must have both languages with the same format verbs in the
// same order, so a missing translation or a mismatched argument never reaches users.
func TestMessagesComplete(t *testing.T) {
	for key, m := range messages {
		en, zh := m[EN], m[ZH]
		if en == "" || zh == "" {
			t.Errorf("%s: missing translation (en=%q zh=%q)", key, en, zh)
			continue
		}
		ve, vz := verbs(en), verbs(zh)
		if len(ve) != len(vz) {
			t.Errorf("%s: format verbs differ: en=%v zh=%v", key, ve, vz)
			continue
		}
		for i := range ve {
			if ve[i] != vz[i] {
				t.Errorf("%s: format verbs differ: en=%v zh=%v", key, ve, vz)
				break
			}
		}
	}
}
