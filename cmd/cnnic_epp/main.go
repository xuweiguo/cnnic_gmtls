package main

import (
	"errors"
	"flag"
	"log"
	"os"

	"github.com/xuweiguo/cnnic_gmtls/cmd/internal/eppclient"
)

func main() {
	if err := eppclient.Execute(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return
		}
		log.Fatal(err)
	}
}
