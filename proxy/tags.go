package proxy

import "strconv"

// Pre-allocated tag prefixes to avoid string concatenation in hot path
const (
	tagPrefixRequestOpCode  = "request_op_code:"
	tagPrefixIsMaster       = "is_master:"
	tagPrefixCommand        = "command:"
	tagPrefixCollection     = "collection:"
	tagPrefixUnacknowledged = "unacknowledged:"
	tagPrefixResponseOpCode = "response_op_code:"
	tagPrefixSuccess        = "success:"
	tagPrefixAddress        = "address:"
)

// Pre-allocated common tag values
var (
	tagIsMasterTrue        = tagPrefixIsMaster + "true"
	tagIsMasterFalse       = tagPrefixIsMaster + "false"
	tagUnacknowledgedTrue  = tagPrefixUnacknowledged + "true"
	tagUnacknowledgedFalse = tagPrefixUnacknowledged + "false"
	tagSuccessTrue         = tagPrefixSuccess + "true"
	tagSuccessFalse        = tagPrefixSuccess + "false"
)

func boolTag(trueVal, falseVal string, value bool) string {
	if value {
		return trueVal
	}
	return falseVal
}

func opCodeTag(prefix string, opCode int32) string {
	return prefix + strconv.FormatInt(int64(opCode), 10)
}
