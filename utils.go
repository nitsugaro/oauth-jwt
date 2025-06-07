package oauthjwt

func ToStr(val interface{}) string {
	if strVal, ok := val.(string); ok {
		return strVal
	}
	return ""
}

func ToInt(val interface{}) int {
	switch v := val.(type) {
	case int:
		return v
	case float64:
		return int(v)
	default:
		return 0
	}
}

func ToInt64(val interface{}) int64 {
	switch v := val.(type) {
	case int64:
		return v
	case float64:
		return int64(v)
	case int:
		return int64(v)
	default:
		return 0
	}
}

func ToFloat32(val interface{}) float32 {
	switch v := val.(type) {
	case float32:
		return v
	case float64:
		return float32(v)
	default:
		return 0
	}
}

func ToFloat64(val interface{}) float64 {
	if v, ok := val.(float64); ok {
		return v
	}
	if v, ok := val.(float32); ok {
		return float64(v)
	}
	return 0
}

func Filter[T any](slice []T, keep func(T) bool) []T {
	var result []T
	for _, item := range slice {
		if keep(item) {
			result = append(result, item)
		}
	}
	return result
}
