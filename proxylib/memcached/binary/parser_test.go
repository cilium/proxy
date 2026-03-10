// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package binary

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestMemcacheGetKey(c *testing.T) {
	packet := []byte{
		0x80, 0, 0, 0x5,
		0, 0, 0, 0,
		0, 0, 0, 0x5,
		0, 0, 0, 0,
		0, 0, 0, 0,
		0, 0, 0, 0,
		'T', 'e', 's', 't',
		'1',
	}

	key := getMemcacheKey(packet, 0, 5)

	require.Equal(c, "Test1", string(key))

	packet = []byte{
		0x80, 0, 0, 0x5,
		0x4, 0, 0, 0,
		0, 0, 0, 0x5,
		0, 0, 0, 0,
		0, 0, 0, 0,
		0, 0, 0, 0,
		'e', 'x', 't', 'r',
		'T', 'e', 's', 't',
		'1',
	}

	key = getMemcacheKey(packet, 4, 5)

	require.Equal(c, "Test1", string(key))

	packet = []byte{
		0x80, 0x8, 0, 0x0,
		0x4, 0, 0, 0,
		0, 0, 0, 0x4,
		0, 0, 0, 0,
		0, 0, 0, 0,
		0, 0, 0, 0,
		0, 0, 0x1c, 0x20,
	}

	key = getMemcacheKey(packet, 4, 0)

	require.Equal(c, "", string(key))
}
