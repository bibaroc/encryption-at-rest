package main

import "fmt"

var (
	version   string
	gitCommit string
)

func main() {
	fmt.Printf("Starting application version=%s, commit=%s\n", version, gitCommit)
}
