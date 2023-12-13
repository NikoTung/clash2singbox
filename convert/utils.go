package convert

import (
	"bytes"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"github.com/xmdhs/clash2singbox/model/clash"
	"github.com/xmdhs/clash2singbox/model/singbox"
)

func filter(isinclude bool, reg string, sl []string) ([]string, error) {
	r, err := regexp.Compile(reg)
	if err != nil {
		return sl, fmt.Errorf("filter: %w", err)
	}
	return getForList(sl, func(v string) (string, bool) {
		has := r.MatchString(v)
		if has && isinclude {
			return v, true
		}
		if !isinclude && !has {
			return v, true
		}
		return "", false
	}), nil
}

func getForList[K, V any](l []K, check func(K) (V, bool)) []V {
	sl := make([]V, 0, len(l))
	for _, v := range l {
		s, ok := check(v)
		if !ok {
			continue
		}
		sl = append(sl, s)
	}
	return sl
}

func filterOut(s []string, flag string) []string {

	return getForList(s, func(v string) (string, bool) {
		f, has := flags[flag]
		if has {
			for _, keyword := range f {
				c := strings.Contains(v, keyword)
				if c {
					return v, true
				}
			}
			return v, false
		}
		return v, false
	})
}

func filterExlude(s []string, flag []string) []string {

	return getForList(s, func(v string) (string, bool) {
		for _, c := range flag {
			f, has := flags[c]
			if has {
				for _, keyword := range f {
					c := strings.Contains(v, keyword)
					if c {
						return "", false
					}
				}
			}
		}

		return v, true
	})
}

// func getServers(s []singbox.SingBoxOut) []string {
// 	m := map[string]struct{}{}
// 	return getForList(s, func(v singbox.SingBoxOut) (string, bool) {
// 		server := v.Server
// 		_, has := m[server]
// 		if server == "" || has {
// 			return "", false
// 		}
// 		m[server] = struct{}{}
// 		return server, true
// 	})
// }

func getTags(s []singbox.SingBoxOut) []string {
	return getForList(s, func(v singbox.SingBoxOut) (string, bool) {
		tag := v.Tag
		if tag == "" || v.Type == "shadowtls" {
			return "", false
		}
		return tag, true
	})
}

func Patch(b []byte, s []singbox.SingBoxOut, include, exclude string, extOut []interface{}, extags ...string) ([]byte, error) {
	d, err := PatchMap(b, s, include, exclude, extOut, extags, true)
	if err != nil {
		return nil, fmt.Errorf("Patch: %w", err)
	}
	bw := &bytes.Buffer{}
	jw := json.NewEncoder(bw)
	jw.SetIndent("", "    ")
	err = jw.Encode(d)
	if err != nil {
		return nil, fmt.Errorf("Patch: %w", err)
	}
	return bw.Bytes(), nil
}

func ToInsecure(c *clash.Clash) {
	for i := range c.Proxies {
		p := c.Proxies[i]
		p.SkipCertVerify = true
		c.Proxies[i] = p
	}
}

func PatchMap(
	tpl []byte,
	s []singbox.SingBoxOut,
	include, exclude string,
	extOut []interface{},
	extags []string,
	urltestOut bool,
) (map[string]any, error) {
	d := map[string]interface{}{}
	err := json.Unmarshal(tpl, &d)
	if err != nil {
		return nil, fmt.Errorf("PatchMap: %w", err)
	}
	tags := getTags(s)

	tags = append(tags, extags...)

	ftags := tags
	if include != "" {
		ftags, err = filter(true, include, ftags)
		if err != nil {
			return nil, fmt.Errorf("PatchMap: %w", err)
		}
	}
	if exclude != "" {
		ftags, err = filter(false, exclude, ftags)
		if err != nil {
			return nil, fmt.Errorf("PatchMap: %w", err)
		}
	}

	group := []singbox.SingBoxOut{}

	//auto
	group = append(group, singbox.SingBoxOut{
		Type:      "urltest",
		Tag:       "auto",
		Interval:  "10m",
		Tolerance: 100,
		Outbounds: append([]string{}, tags...),
	})
	//proxy
	group = append(group, singbox.SingBoxOut{
		Type:      "selector",
		Tag:       "proxy",
		Outbounds: append([]string{"auto", "direct"}, tags...),
	})

	hk := filterOut(tags, "🇭🇰")
	us := filterOut(tags, "🇺🇸")
	sg := filterOut(tags, "🇸🇬")
	jp := filterOut(tags, "🇯🇵")
	tw := filterOut(tags, "tw")
	others := filterExlude(tags, []string{"🇭🇰", "🇺🇸", "🇸🇬", "🇯🇵", "tw"})

	group = append(group, singbox.SingBoxOut{
		Type:      "selector",
		Tag:       "🇭🇰 HongKong",
		Outbounds: hk,
	})

	group = append(group, singbox.SingBoxOut{
		Type:      "selector",
		Tag:       "🇺🇸 USA",
		Outbounds: us,
	})

	group = append(group, singbox.SingBoxOut{
		Type:      "selector",
		Tag:       "🇸🇬 Singapore",
		Outbounds: sg,
	})

	group = append(group, singbox.SingBoxOut{
		Type:      "selector",
		Tag:       "🇯🇵 Japan",
		Outbounds: jp,
	})

	group = append(group, singbox.SingBoxOut{
		Type:      "selector",
		Tag:       "🇹🇼 Taiwan",
		Outbounds: tw,
	})

	group = append(group, singbox.SingBoxOut{
		Type:      "selector",
		Tag:       "✈️ Others",
		Outbounds: others,
	})

	x := d["outbounds"]

	finalList := []any{}
	for _, v := range group {
		finalList = append(finalList, v)
	}

	if xList, ok := x.([]any); ok {
		finalList = append(finalList, xList...)
	} else {
		// Handle the case when x is not of type []any
		// You can choose to skip or handle the error accordingly
	}

	for _, v := range s {
		finalList = append(finalList, v)
	}

	d["outbounds"] = finalList

	return d, nil
}
