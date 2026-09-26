package search

import (
	"fmt"
	"sort"
	"strings"
)

type Query struct {
	Keywords   []string
	Kind       string
	Limit      int
	Page       int
	Qualifiers Qualifiers
}

type Qualifiers struct {
	Author   string
	Label    []string
	Language string
	State    string
}

func (q Query) String() string {
	all := append(formatKeywords(q.Keywords), formatQualifiers(q.Qualifiers)...)
	return strings.TrimSpace(strings.Join(all, " "))
}

func (qs Qualifiers) Map() map[string][]string {
	m := map[string][]string{}
	if qs.Author != "" {
		m["author"] = []string{qs.Author}
	}
	if len(qs.Label) > 0 {
		m["label"] = qs.Label
	}
	if qs.Language != "" {
		m["language"] = []string{qs.Language}
	}
	if qs.State != "" {
		m["state"] = []string{qs.State}
	}
	return m
}

func quote(s string) string {
	if strings.ContainsAny(s, " \"\t") {
		return fmt.Sprintf("%q", s)
	}
	return s
}

func formatQualifiers(qs Qualifiers) []string {
	var all []string
	for k, vs := range qs.Map() {
		for _, v := range vs {
			all = append(all, fmt.Sprintf("%s:%s", k, quote(v)))
		}
	}
	sort.Strings(all)
	return all
}

func formatKeywords(ks []string) []string {
	for i, k := range ks {
		ks[i] = quote(k)
	}
	return ks
}
