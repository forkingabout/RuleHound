package core

import "fmt"

const (
	green        = "\033[38;5;82m"
	yellowOrange = "\033[38;5;214m"
	red          = "\033[38;5;196m"
	pinkPurple   = "\033[38;5;141m"
	electricBlue = "\033[38;5;39m" // Vivid, bright modern blue
	reset        = "\033[0m"
)

const banner = "\n888888ba           dP          dP     dP                                   dP \n 88    `8b          88          88     88                                   88 \na88aaaa8P' dP    dP 88 .d8888b. 88aaaaa88a .d8888b. dP    dP 88d888b. .d888b88 \n 88   `8b. 88    88 88 88ooood8 88     88  88'  `88 88    88 88'  `88 88'  `88 \n 88     88 88.  .88 88 88.  ... 88     88  88.  .88 88.  .88 88    88 88.  .88 \n dP     dP `88888P' dP `88888P' dP     dP  `88888P' `88888P' dP    dP `88888P8 \n\n"

func Success(msg string) {
	fmt.Printf("%s[+]%s %s\n", green, reset, msg)
}

func Warn(msg string) {
	fmt.Printf("%s[~]%s %s\n", yellowOrange, reset, msg)
}

func Error(msg string) {
	fmt.Printf("%s[!]%s %s\n", red, reset, msg)
}

func Debug(msg string) {
	fmt.Printf("%s{›}%s %s\n", pinkPurple, reset, msg)
}

func Help(msg string) {
	fmt.Printf("%s[?]%s %s\n", electricBlue, reset, msg)
}

func Banner() {
	fmt.Printf(banner)
}
