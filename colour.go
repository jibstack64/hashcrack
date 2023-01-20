package main

import (
	"os"

	colour "github.com/fatih/color"
)

type Printer struct {
	ErrorCol   *colour.Color
	SuccessCol *colour.Color
	WarningCol *colour.Color
	NeutralCol *colour.Color
}

func NewPrinter() *Printer {
	p := Printer{}
	p.ErrorCol = colour.New(colour.FgHiRed)
	p.SuccessCol = colour.New(colour.FgHiGreen)
	p.WarningCol = colour.New(colour.FgHiYellow)
	p.NeutralCol = colour.New(colour.FgHiWhite)
	return &p
}

// warningCol.Printf(...) but with os.Exit(1)
func (p *Printer) Fatal(format string, a ...interface{}) {
	p.ErrorCol.Printf(format, a...)
	os.Exit(1)
}

func (p *Printer) Success(format string, a ...interface{}) {
	p.SuccessCol.Printf(format, a...)
}

func (p *Printer) Warning(format string, a ...interface{}) {
	p.WarningCol.Printf(format, a...)
}

func (p *Printer) Neutral(format string, a ...interface{}) {
	p.NeutralCol.Printf(format, a...)
}
