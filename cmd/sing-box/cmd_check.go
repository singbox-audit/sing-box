package main

import (
	"context"

	"github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing/service"

	"github.com/spf13/cobra"
)

var commandCheck = &cobra.Command{
	Use:   "check",
	Short: "Check configuration",
	Run: func(cmd *cobra.Command, args []string) {
		err := check()
		if err != nil {
			log.Fatal(err)
		}
	},
	Args: cobra.NoArgs,
}

func init() {
	commandCheck.Flags().StringVar(&auditDirectory, "audit-directory", "", "Check audited inbound identities for this directory")
	mainCommand.AddCommand(commandCheck)
}

func check() error {
	options, err := readConfigAndMerge()
	if err != nil {
		return err
	}
	ctx, cancel := context.WithCancel(service.ExtendContext(globalCtx))
	instance, err := box.New(box.Options{
		Context: ctx,
		Options: options, AuditDirectory: auditDirectory,
	})
	if err == nil {
		instance.Close()
	}
	cancel()
	return err
}
