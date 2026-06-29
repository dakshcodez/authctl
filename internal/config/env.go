package config

import (
	"fmt"
	"os"
	"strconv"
	"time"
)

func getString(key, defaultValue string) string {
	if value, ok := os.LookupEnv(key); ok {
		return value
	}

	return defaultValue
}

func getInt(key string, defaultValue int) (int, error) {
	value := getString(key, "")

	if value == "" {
		return defaultValue, nil
	}

	i, err := strconv.Atoi(value)
	if err != nil {
		return 0, fmt.Errorf("%s must be an integer", key)
	}

	return i, nil
}

func getDuration(key string, defaultValue time.Duration) (time.Duration, error) {
	value := getString(key, "")

	if value == "" {
		return defaultValue, nil
	}

	d, err := time.ParseDuration(value)
	if err != nil {
		return 0, fmt.Errorf("%s has invalid duration", key)
	}

	return d, nil
}