package main

import (
	"os"

	cmd "github.com/desoivanov/ldbgrpc/pkg/cmd/server"

	"github.com/spf13/cobra"

	"github.com/davecgh/go-spew/spew"

	"github.com/spf13/viper"
)

var (
	CAPath string
	SCert  string
	SKey   string
	Cache  string
	v      *viper.Viper
)

var rootCmd = &cobra.Command{
	Use:   "server",
	Short: "starts the rest-grpc server.",
	Long:  "starts the rest-grpc server.",
	RunE: func(local *cobra.Command, args []string) error {
		return cmd.RunServer(v.GetString("cache"), v.GetString("cacert"), v.GetString("cert"), v.GetString("key"))
	},
}

func viperInit() {
	v = viper.New()
	v.BindPFlag("cacert", rootCmd.Flags().Lookup("cacert"))
	v.BindPFlag("cert", rootCmd.Flags().Lookup("cert"))
	v.BindPFlag("key", rootCmd.Flags().Lookup("key"))
	v.BindPFlag("cache", rootCmd.Flags().Lookup("cache"))
}

func init() {
	rootCmd.Flags().StringVarP(&CAPath, "cacert", "", "./certs/CA/CA.pem", "path to CA Certificate")
	rootCmd.Flags().StringVarP(&SCert, "cert", "", "./certs/SERVER/default/Server.pem", "path to server Certificate")
	rootCmd.Flags().StringVarP(&SKey, "key", "", "./certs/SERVER/default/Server.key", "path to server Certificate Key")
	rootCmd.Flags().StringVarP(&Cache, "cache", "", "cache/default", "path to cache storage")
	viperInit()
}

func main() {
	spew.Dump(v.AllSettings())
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
