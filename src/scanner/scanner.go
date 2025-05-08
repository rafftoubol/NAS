// This file contains the declaration of the main Scanner. It include all our scanning methods.

package scanner

import "attack-surface/src/utils"

type Scanner struct {
	config *utils.Config
}

func NewScanner(config *utils.Config) *Scanner {
	return &Scanner{
		config: config,
	}
}

func (b *Scanner) Scan() {
	return
}

func (b *Scanner) Print() {
	return
}
