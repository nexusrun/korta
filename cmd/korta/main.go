// korta is the command-line client for the Korta manager.
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"

	"github.com/nexusrun/korta/cli"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	if err := cli.Run(ctx, os.Args[1:], os.Stdin, os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, "korta:", err)
		os.Exit(1)
	}
}
