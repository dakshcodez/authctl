package main

import (
	"fmt"
	"log"

	"github.com/dakshcodez/authctl/internal/config"
)

func main() {

	cfg, err := config.Load()
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("%+v\n", cfg)
}