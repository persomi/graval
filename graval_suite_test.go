package graval_test

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"testing"
)

func TestGraval(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Graval Suite")
}
