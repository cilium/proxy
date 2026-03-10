// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package proxylib

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestAdvanceInput(t *testing.T) {
	input := [][]byte{[]byte("ABCD"), []byte("1234567890"), []byte("abcdefghij")}

	require.Equal(t, byte('A'), input[0][0])
	require.Len(t, input, 3) // Three slices in input

	// Advance to one byte before the end of the first slice
	input = advanceInput(input, 3)
	require.Len(t, input, 3) // Still in the first slice
	require.Len(t, input[0], 1)
	require.Equal(t, byte('D'), input[0][0])

	// Advance to the beginning of the next slice
	input = advanceInput(input, 1)
	require.Len(t, input, 2) // Moved to the next slice
	require.Equal(t, byte('1'), input[0][0])

	// Advance 11 bytes, crossing to the next slice
	input = advanceInput(input, 11)
	require.Len(t, input, 1) // Moved to the 3rd slice
	require.Equal(t, byte('b'), input[0][0])

	// Try to advance 11 bytes when only 9 remmain
	input = advanceInput(input, 11)
	require.Len(t, input, 0) // All data exhausted

	// Try advance on an empty slice
	input = advanceInput(input, 1)
	require.Len(t, input, 0)
}
