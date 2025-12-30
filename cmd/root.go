/*
Copyright © 2025 Matt Krueger <mkrueger@rstms.net>
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

 1. Redistributions of source code must retain the above copyright notice,
    this list of conditions and the following disclaimer.

 2. Redistributions in binary form must reproduce the above copyright notice,
    this list of conditions and the following disclaimer in the documentation
    and/or other materials provided with the distribution.

 3. Neither the name of the copyright holder nor the names of its contributors
    may be used to endorse or promote products derived from this software
    without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
POSSIBILITY OF SUCH DAMAGE.
*/
package cmd

import (
	"os"
	"strings"

	"github.com/rstms/filterbooks/scanner"
	"github.com/spf13/cobra"
)

var cfgFile string

var rootCmd = &cobra.Command{
	Version: "0.1.13",
	Use:     "filterbooks",
	Short:   "dovecot sieve filter implmenting filter-books header manipulation",
	Long: `
Scan email message from stdin and write message to stdout, modifying headers.
Read environment vars set by sieve filter: 
    HOME, USER, SENDER, RECIPIENT, ORIG_RECIPIENT
Perform filterbook lookup on SENDER and set header if a match is found:
    X-Filter-Book: <bookname>
Do not change messages matching these conditions:
    message has a header "X-Filterctl-Request-Id"
    SENDER matches MAILER-DAEMON.*
    SENDER matches SIEVE-DAEMON.*

Determine the filterbook lookup address as follows:
    username is $USER
    domain is the domain part of $HOST
`,
	Run: func(cmd *cobra.Command, args []string) {
		bookScanner, err := scanner.NewScanner(os.Stdout, os.Stdin)
		cobra.CheckErr(err)
		defer bookScanner.Close()
		bookScanner.Scan()
	},
}

func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func init() {
	CobraInit(rootCmd)
	keys := []string{
		"sender",
		"recipient",
		"host",
		"orig_recipient",
		"user",
	}
	for _, key := range keys {
		ViperSetDefault(key, os.Getenv(strings.ToUpper(key)))
	}
	OptionString(rootCmd, "filterctld-url", "", "https://127.0.0.1:2016", "filterctld URL")
	OptionString(rootCmd, "cert", "", "", "client certificate PEM file")
	OptionString(rootCmd, "key", "", "", "client certificate key PEM file")
	OptionString(rootCmd, "ca", "", "", "CA file")
}
