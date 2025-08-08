package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"text/tabwriter"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	bolt "go.etcd.io/bbolt"

	"linknife/apikeygen"
	"linknife/jsonutil"
	"linknife/server"
)

/*──────────────────────── serve command ───────────────────────────*/
func newServeCmd() *cobra.Command {
	var cfgPath string

	cmd := &cobra.Command{
		Use:   "serve",
		Short: "Start the HTTP(S) server",
		PreRunE: func(_ *cobra.Command, _ []string) error {
			if cfgPath == "" {
				return fmt.Errorf("you must supply --config")
			}
			viper.SetConfigFile(cfgPath)
			viper.SetConfigType("json")
			if err := viper.ReadInConfig(); err != nil {
				return err
			}
			return viper.Unmarshal(&server.Cfg)
		},
		RunE: func(_ *cobra.Command, _ []string) error {
			ctx, stop := signal.NotifyContext(
				context.Background(), syscall.SIGINT, syscall.SIGTERM)
			defer stop()
			return server.Serve(ctx)
		},
	}

	cmd.Flags().StringVar(&cfgPath, "config", "",
		"Path to config.json (required)")
	return cmd
}

/*──────────────────────────── stats command ───────────────────────────*/
func newStatsCmd() *cobra.Command {
	var cfgPath string

	cmd := &cobra.Command{
		Use:   "stats",
		Short: "Print aggregate URL statistics",
		RunE: func(_ *cobra.Command, _ []string) error {
			if cfgPath == "" {
				return fmt.Errorf("--config is required")
			}

			// read db_path from the config file (no need to unmarshal whole struct)
			cfg, err := jsonutil.Load[map[string]any](cfgPath)
			if err != nil {
				return err
			}
			raw, ok := cfg["db_path"]
			if !ok {
				return fmt.Errorf("db_path missing in %s", cfgPath)
			}
			dbPath, ok := raw.(string)
			if !ok || dbPath == "" {
				return fmt.Errorf("db_path in %s is not a string", cfgPath)
			}

			// open Bolt in read-only mode
			db, err := bolt.Open(dbPath, 0o600, &bolt.Options{ReadOnly: true})
			if err != nil {
				return err
			}
			defer db.Close()

			// walk bucket and accumulate
			var totalLinks int
			var visits, redirects, cancels uint64

			err = db.View(func(tx *bolt.Tx) error {
				b := tx.Bucket([]byte("urls"))
				if b == nil {
					return fmt.Errorf("bucket \"urls\" not found in %s", dbPath)
				}
				return b.ForEach(func(_, v []byte) error {
					totalLinks++
					var meta struct {
						Visits    uint64 `json:"visits"`
						Redirects uint64 `json:"redirects"`
						Cancels   uint64 `json:"cancels"`
					}
					if err := json.Unmarshal(v, &meta); err == nil {
						visits += meta.Visits
						redirects += meta.Redirects
						cancels += meta.Cancels
					}
					return nil
				})
			})
			if err != nil {
				return err
			}

			// pretty output
			tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			fmt.Fprintln(tw, "TOTAL_LINKS\tVISITS\tREDIRECTS\tCANCELS")
			fmt.Fprintf(tw, "%d\t%d\t%d\t%d\n", totalLinks, visits, redirects, cancels)
			return tw.Flush()
		},
	}

	cmd.Flags().StringVar(&cfgPath, "config", "", "path to config.json (required)")
	return cmd
}

/*──────────────────── apikey admin sub-command ─────────────────────*/
func newAPIKeyAdminCmd() *cobra.Command {
	var cfgPath string

	cmd := &cobra.Command{
		Use:   "admin",
		Short: "Generate an admin key and write it into config.json",
		RunE: func(_ *cobra.Command, _ []string) error {
			if cfgPath == "" {
				logFatal("--config is required")
			}
			key, err := apikeygen.SetAdminKey(cfgPath)
			if err != nil {
				logFatal(err)
			}
			fmt.Printf("Admin API key written to %s:\n%s\n", cfgPath, key)
			return nil
		},
	}
	cmd.Flags().StringVar(&cfgPath, "config", "",
		"Path to config.json (required)")
	return cmd
}

/*──────────────────── apikey user sub-command ──────────────────────*/
/*──────────────────── apikey user sub-commands ───────────────────*/
func newAPIKeyUserCmd() *cobra.Command {
	/* shared --users flag for every leaf */
	var usersPath string
	addUsersFlag := func(c *cobra.Command) {
		c.Flags().StringVar(&usersPath, "users", "",
			"Path to users.json (required)")
	}

	/* helper that creates the RunE for generate / edit */
	makeRun := func(expectKey bool) func(cmd *cobra.Command, args []string) error {
		return func(cmd *cobra.Command, args []string) error {
			if usersPath == "" {
				return fmt.Errorf("--users is required")
			}
			var key string
			if expectKey {
				key = args[0] // cobra ensures arg count
			}

			create, _ := cmd.Flags().GetBool("create")
			update, _ := cmd.Flags().GetBool("update")
			delPerm, _ := cmd.Flags().GetBool("delete")

			perm := apikeygen.UserPerm{Create: create, Change: update, Delete: delPerm}

			switch cmd.Name() {
			case "generate":
				newKey, err := apikeygen.AddUserKey(usersPath, perm)
				if err != nil {
					return err
				}
				fmt.Printf("New user key written to %s:\n%s\n", usersPath, newKey)
			case "edit":
				if err := apikeygen.UpdateUserPerms(usersPath, key, perm); err != nil {
					return err
				}
				fmt.Printf("Updated permissions for key %s\n", key)
			}
			return nil
		}
	}

	/* helper to add the three perm flags */
	addPermFlags := func(c *cobra.Command) {
		c.Flags().Bool("create", false, "allow creating links")
		c.Flags().Bool("update", false, "allow updating links")
		c.Flags().Bool("delete", false, "allow deleting links")
	}

	/* ----- leaf commands ----- */
	genCmd := &cobra.Command{
		Use:   "generate",
		Short: "Create a new user key",
		RunE:  makeRun(false),
	}
	addPermFlags(genCmd)
	addUsersFlag(genCmd)

	editCmd := &cobra.Command{
		Use:   "edit <key>",
		Short: "Modify permissions of an existing key",
		Args:  cobra.ExactArgs(1),
		RunE:  makeRun(true),
	}
	addPermFlags(editCmd)
	addUsersFlag(editCmd)

	delCmd := &cobra.Command{
		Use:   "delete <key>",
		Short: "Remove a user key entirely",
		Args:  cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			if usersPath == "" {
				return fmt.Errorf("--users is required")
			}
			if err := apikeygen.RemoveUserKey(usersPath, args[0]); err != nil {
				return err
			}
			fmt.Printf("Deleted key %s from %s\n", args[0], usersPath)
			return nil
		},
	}
	addUsersFlag(delCmd)

	listCmd := &cobra.Command{
		Use:   "list",
		Short: "Show all user keys and their permissions",
		RunE: func(_ *cobra.Command, _ []string) error {
			if usersPath == "" {
				return fmt.Errorf("--users is required")
			}
			m, err := apikeygen.ListUsers(usersPath)
			if err != nil {
				return err
			}

			tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			fmt.Fprintln(tw, "KEY\tCREATE\tUPDATE\tDELETE")
			for k, p := range m {
				fmt.Fprintf(tw, "%s\t%v\t%v\t%v\n", k, p.Create, p.Change, p.Delete)
			}
			return tw.Flush()
		},
	}
	addUsersFlag(listCmd)

	/* assemble tree */
	userCmd := &cobra.Command{
		Use:   "user",
		Short: "Generate, edit, or delete user keys",
	}
	userCmd.AddCommand(genCmd, editCmd, delCmd, listCmd)
	return userCmd
}

/*──────────────────────── root CLI setup ───────────────────────────*/
func main() {
	root := &cobra.Command{
		Use:   "linknife",
		Short: "A tiny self-hosted URL shortener",
	}

	// serve
	root.AddCommand(newServeCmd())

	// stats
	root.AddCommand(newStatsCmd())

	// apikey (parent) → admin | user
	apikeyRoot := &cobra.Command{
		Use:   "apikey",
		Short: "Generate or manage API keys",
	}
	apikeyRoot.AddCommand(newAPIKeyAdminCmd())
	apikeyRoot.AddCommand(newAPIKeyUserCmd())
	root.AddCommand(apikeyRoot)

	if err := root.Execute(); err != nil {
		logFatal(err)
	}
}

/*───────────────────────── helpers ────────────────────────────────*/
func logFatal(v any) {
	log.Println(v)
	os.Exit(1)
}
