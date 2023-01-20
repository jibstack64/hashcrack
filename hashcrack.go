package main

import (
	"crypto/md5"
	"crypto/sha256"
	"encoding"
	"encoding/hex"
	"flag"
	"os"
	"os/signal"
	"strings"

	combinations "github.com/mxschmitt/golang-combinations"
	"golang.org/x/exp/maps"
)

var (
	// args
	hashType    string
	keyTermsRaw string
	keyTerms    []string
	genFile     string
	useFile     string
	inputHash   string
	max         uint64

	// common num-char char-num replaces in passwords
	numChar = map[rune]rune{'a': '4', 'b': '8', 'e': '3', 'g': '9', 'i': '1', 'o': '0', 's': '5', 't': '7'}
	nums    = maps.Keys(numChar)
	chars   = maps.Values(numChar)

	specialStrings = []string{
		"@", "@@", "@@@", "@@@@", "@@@@@",
		"#", "##", "###", "####", "#####",
		"1", "12", "123", "1234", "12345",
	}

	hashFuncs = map[string]func(string) string{
		"sha256": hashSha256, "md5": hashMd5,
	}
	hashFunc func(string) string

	printer = NewPrinter()
)

// returns the (sha256) hashed version of text.
func hashSha256(text string) string {
	hs := sha256.New()
	hs.Write([]byte(text))
	marshaler, ok := hs.(encoding.BinaryMarshaler)
	if !ok {
		printer.Fatal("Hash does not implement encoding.BinaryMarshaler!")
	}
	_, err := marshaler.MarshalBinary()
	if err != nil {
		printer.Fatal("Unable to marshal hash:", err)
	}
	return hex.EncodeToString(hs.Sum(nil)[:])
}

// returns the (md5) hashed version of text.
func hashMd5(text string) string {
	hash := md5.Sum([]byte(text))
	return hex.EncodeToString(hash[:])
}

// generates all different combinations of capital letters within the provided string.
func capitals(st string) (capped []string) {
	if len(st) == 1 {
		return []string{strings.ToLower(st), strings.ToUpper(st)}
	} else {
		for _, i := range capitals(st[1:]) {
			for _, j := range capitals(string(st[0])) {
				capped = append(capped, j+i)
			}
		}
	}
	return capped
}

// generates all different combinations of number formatting (h3ll0).
func numbers(st string) (nummed []string) {
	conv := func(i rune) rune {
		for k, v := range numChar {
			if k == i {
				return v
			} else if v == i {
				return k
			}
		}
		return i
	}
	if len(st) == 1 {
		if conv(rune(st[0])) == rune(st[0]) {
			return []string{string(st[0])}
		} else {
			return []string{string(conv(rune(st[0]))), string(st[0])}
		}
	} else {
		for _, i := range numbers(st[1:]) {
			for _, j := range numbers(string(st[0])) {
				c := false
				for _, v := range nummed {
					if j+i == v {
						c = true
					}
				}
				if c {
					continue
				}
				nummed = append(nummed, j+i)
			}
		}
	}
	return nummed
}

// adds special characters and some nums.
func specials(st string) (specialed []string) {
	for _, s := range specialStrings {
		specialed = append(specialed, st+s)
	}
	for _, s := range specialed {
		for _, c := range specialStrings {
			specialed = append(specialed, s+c)
		}
	}
	return specialed
}

// save combos to gen-file.
func save(combos []string) {
	os.WriteFile(genFile, []byte(strings.Join(combos, "\n")), 0664)
}

func main() {
	// generate
	var combos []string
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	go func() {
		for range c {
			printer.Warning("ctrl+c received, saving...")
			save(combos)
			os.Exit(1)
		}
	}()
	if useFile == "" {
		// combos
		for _, cg := range combinations.All(keyTerms) {
			combos = append(combos, strings.Join(cg, ""))
		}
		// caps
		for _, cg := range combos {
			combos = append(combos, capitals(cg)...)
		}
		// nums
		for _, cg := range combos {
			combos = append(combos, numbers(cg)...)
		}
		// specials
		for _, cg := range combos {
			combos = append(combos, specials(cg)...)
		}
	} else {
		b, err := os.ReadFile(useFile)
		if err != nil {
			printer.Fatal("\nFailed to load input file.\n")
		} else {
			combos = strings.Split(string(b), "\n")
		}
	}

	if inputHash == "" {
		printer.Success("\nGenerated passwords.\n")
		// save
		save(combos)
	} else {
		for _, c := range combos {
			if hashFunc(c) == inputHash {
				printer.Success("\nPassword cracked: %s\n", c)
				return
			}
		}
		save(combos)
		printer.Fatal("\nFailed to crack password. Generated passwords.\n")
	}
}

func init() {
	// add and parse args
	flag.StringVar(&hashType, "type", "sha256", "The type of hash (sha256 or md5).")
	flag.StringVar(&keyTermsRaw, "terms", "", "The key terms to be used in the generated passwords (seperated by ',').")
	flag.StringVar(&genFile, "gen-file", "generated.txt", "Specifies a file where generated passwords are dumped.")
	flag.StringVar(&useFile, "use", "", "The file in which passwords can be pre-loaded from (e.g. an old gen-file).")
	flag.StringVar(&inputHash, "in", "", "The hash to attempt to crack. If none is provided, the program will generated <max> passwords.")
	flag.Uint64Var(&max, "max", 10^5, "Maximum number of passwords to generate.")
	flag.Parse()

	// make sure max is over 0
	if max < 1 {
		printer.Fatal("Maximum must be over 0.\n")
	}
	if keyTermsRaw == "" {
		printer.Fatal("No key terms provided.\n")
	} else {
		keyTerms = strings.Split(keyTermsRaw, ",")
	}

	// ensure hashtype is valid
	for k, v := range hashFuncs {
		if strings.ToLower(hashType) == k {
			hashFunc = v
		}
	}
	if hashFunc == nil {
		printer.Fatal("Hash type '%s' is invalid.\n", hashType)
	}

	// print options
	printer.Warning("> HashCrack v0.0.1\n")
	printer.Neutral("Hash type: %s\n", hashType)
	printer.Neutral("Key terms: '%s'\n", keyTermsRaw)
	printer.Neutral("Gen-file: '%s'\n", genFile)
	printer.Neutral("Use: '%s'\n", useFile)
	printer.Neutral("Input hash: %s\n", inputHash)
}
