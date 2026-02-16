package mongo

import "strconv"

// Pre-allocated tag prefixes
const (
	tagPrefixAddress = "address:"
	tagPrefixSuccess = "success:"
)

// Pre-allocated common tag values
var (
	tagSuccessTrue  = tagPrefixSuccess + "true"
	tagSuccessFalse = tagPrefixSuccess + "false"
)

func successTag(success bool) string {
	if success {
		return tagSuccessTrue
	}
	return tagSuccessFalse
}

func addressTag(addr string) string {
	return tagPrefixAddress + addr
}

func int64Tag(prefix string, val int64) string {
	return prefix + strconv.FormatInt(val, 10)
}
