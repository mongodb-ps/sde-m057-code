package utils

import (
	"strings"
	"time"

	"github.com/goombaio/namegenerator"
)

func NameGenerator() (string, string) {
	seed := time.Now().UTC().UnixNano()
	nameGenerator := namegenerator.NewNameGenerator(seed)

	name := nameGenerator.Generate()

	firstName := strings.Split(name, "-")[0]
	lastName := strings.Split(name, "-")[1]

	return firstName, lastName
}
