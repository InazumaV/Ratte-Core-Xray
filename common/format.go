package common

import "fmt"

func FormatDefaultOutboundName(name string) string {
	return fmt.Sprintf("%s_out", name)
}

func FormatUserEmail(nodeName, username string) string {
	return fmt.Sprintf("[%s](%s)", username, nodeName)
}
