package common

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// BlockHashWhitelist is a map of block numbers to their expected Hash values
type BlockHashWhitelist map[uint64]Hash

func ParseBlockHashWhitelist(entries []string) (*BlockHashWhitelist, error) {
	whitelist := make(BlockHashWhitelist)

	for _, entry := range entries {
		split := strings.SplitN(entry, "=", 2)
		if len(split) != 2 {
			return nil, errors.New(fmt.Sprintf("invalid whitelist entry: %s", entry))
		}

		bn, err := strconv.ParseUint(split[0], 0, 64)
		if err != nil {
			return nil, errors.New(fmt.Sprintf("Invalid whitelist block number %s: %v", split[0], err))
		}

		hash := Hash{}
		err = hash.UnmarshalText([]byte(split[1]))
		if err != nil {
			return nil, errors.New(fmt.Sprintf("Invalid whitelist hash %s: %v", split[1], err))
		}

		whitelist[bn] = hash
	}

	return &whitelist, nil
}
