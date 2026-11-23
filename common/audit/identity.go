package audit

import (
	"fmt"
	"strings"

	"github.com/sagernet/sing-box/option"
)

// The two audited server profiles require stable names. Other inbound types
// still emit their original runtime identity, including the empty value.
func ValidateIdentities(inbounds []option.Inbound) error {
	for _, in := range inbounds {
		var names []string
		switch opts := in.Options.(type) {
		case *option.Hysteria2InboundOptions:
			for _, u := range opts.Users {
				names = append(names, u.Name)
			}
		case *option.VLESSInboundOptions:
			for _, u := range opts.Users {
				names = append(names, u.Name)
			}
		default:
			continue
		}
		if in.Tag == "" {
			return fmt.Errorf("audited %s inbound needs a tag", in.Type)
		}
		seen := make(map[string]bool, len(names))
		for _, name := range names {
			if strings.TrimSpace(name) == "" || seen[name] {
				return fmt.Errorf("audited inbound %q needs nonempty, unique user names", in.Tag)
			}
			seen[name] = true
		}
	}
	return nil
}
