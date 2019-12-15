package service

import "fmt"

func FullName(namespace, name string) string {
	return fmt.Sprintf("%s.%s", namespace, name)
}
