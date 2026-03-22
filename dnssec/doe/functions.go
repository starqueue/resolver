package doe

import (
	"github.com/miekg/dns"
	"strconv"
	"strings"
)

// wildcardName replaces the first label with `*`
func wildcardName(name string) string {
	labelIndexes := dns.Split(name)
	if len(labelIndexes) < 2 {
		return "*."
	}
	return "*." + name[labelIndexes[1]:]
}

func canonicalCmp(a, b string) int {
	labelsA := dns.SplitDomainName(dns.CanonicalName(a))
	labelsB := dns.SplitDomainName(dns.CanonicalName(b))

	minLength := min(len(labelsA), len(labelsB))

	for i := 1; i <= minLength; i++ {
		labelA := labelsA[len(labelsA)-i]
		labelB := labelsB[len(labelsB)-i]

		// Convert labels to lowercase and decode escaped characters
		if strings.Contains(labelA, `\`) {
			labelA = canonicalDecodeEscaped(labelA)
		}
		if strings.Contains(labelB, `\`) {
			labelB = canonicalDecodeEscaped(labelB)
		}

		// Compare lexicographically
		if labelA != labelB {
			if labelA < labelB {
				return -1
			}
			return 1
		}
	}

	// If labels are identical so far, the shorter one sorts first
	if len(labelsA) < len(labelsB) {
		return -1
	} else if len(labelsA) > len(labelsB) {
		return 1
	}
	return 0
}

// canonicalDecodeEscaped converts escaped octets (e.g., \001) to their raw byte values
// for DNS canonical ordering per RFC 4034 Section 6.1. We use raw byte values rather than
// UTF-8 rune encoding to ensure correct ordering for octet values > 127.
func canonicalDecodeEscaped(label string) string {
	var decoded []byte
	for i := 0; i < len(label); i++ {
		if label[i] == '\\' && i+3 < len(label) && canonicalIsDigit(label[i+1]) && canonicalIsDigit(label[i+2]) && canonicalIsDigit(label[i+3]) {
			// Decode escaped octet as a raw byte value, not a UTF-8 rune.
			octetValue, err := strconv.Atoi(label[i+1 : i+4])
			if err == nil && octetValue >= 0 && octetValue <= 255 {
				decoded = append(decoded, byte(octetValue))
			}
			i += 3 // Skip the escaped characters
		} else {
			decoded = append(decoded, label[i])
		}
	}
	return string(decoded)
}

// Check if a character is a digit
func canonicalIsDigit(b byte) bool {
	return b >= '0' && b <= '9'
}
