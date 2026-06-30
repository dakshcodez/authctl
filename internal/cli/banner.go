package cli

import (
	"fmt"
	"io"
)

const asciiArt = `
  ██████╗ ██╗   ██╗████████╗██╗  ██╗ ██████╗████████╗██╗
 ██╔══██╗██║   ██║╚══██╔══╝██║  ██║██╔════╝╚══██╔══╝██║
 ███████║██║   ██║   ██║   ███████║██║        ██║   ██║
 ██╔══██║██║   ██║   ██║   ██╔══██║██║        ██║   ██║
 ██║  ██║╚██████╔╝   ██║   ██║  ██║╚██████╗   ██║   ███████╗
 ╚═╝  ╚═╝ ╚═════╝    ╚═╝   ╚═╝  ╚═╝ ╚═════╝   ╚═╝   ╚══════╝`

// PrintBanner writes the startup banner to out.
func PrintBanner(out io.Writer) {
	colorBanner.Fprintln(out, asciiArt)
	fmt.Fprintln(out)
	colorHeader.Fprintln(out, "  Authentication Control Utility")
	colorDim.Fprintln(out, "  Version 1.0.0")
	fmt.Fprintln(out)
}

// PrintStartupStatus writes the database init messages that follow the banner.
func PrintStartupStatus(out io.Writer, msg string) {
	colorDim.Fprintln(out, "  "+msg)
}

// PrintReady writes the final "ready" line before the prompt appears.
func PrintReady(out io.Writer) {
	fmt.Fprintln(out)
	colorDim.Fprintln(out, "  Type 'help' to see available commands.")
	fmt.Fprintln(out)
}
