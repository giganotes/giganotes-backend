package main

import (
	"fmt"
	"giganotes"
)

func main() {
	fmt.Println("Starting Giganotes backend. Version: " + giganotes.GIGANOTES_SERVER_VERSION)
	giganotes.RunServer()
}
