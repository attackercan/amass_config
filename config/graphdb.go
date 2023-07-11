// Copyright © by Jeff Foley 2017-2023. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"fmt"
	"net/url"
	"strings"
)

// Database contains values required for connecting with graph databases.
type Database struct {
	System   string // Database system type (Postgres, MySQL, etc.)
	Primary  bool   // Whether this database is the primary store
	URI      string // Full URI to the database
	Username string // Username for authentication
	Password string // Password for authentication
	Host     string // Host of the database
	Port     string // Port of the database
	DBName   string // Name of the database
	Options  string // Extra options used while connecting to the database
}

func (c *Config) loadDatabaseSettings(cfg *Config) error {
	dbURIInterface, ok := c.Options["database"]
	if !ok {
		return nil
	}

	dbURI, ok := dbURIInterface.(string)
	if !ok {
		return fmt.Errorf("expected 'database' to be a string, got %T", dbURIInterface)
	}

	u, err := url.Parse(dbURI)
	if err != nil {
		return err
	}

	// Check for valid scheme (database type)
	if u.Scheme == "" {
		return fmt.Errorf("missing scheme in database URI")
	}

	// Check for non-empty username
	if u.User == nil || u.User.Username() == "" {
		return fmt.Errorf("missing username in database URI")
	}

	// Check for reachable hostname
	if u.Hostname() == "" {
		return fmt.Errorf("missing hostname in database URI")
	}

	dbName := ""
	// Only get the database name if it's not empty or a single slash
	if u.Path != "" && u.Path != "/" {
		dbName = strings.TrimPrefix(u.Path, "/")
	}

	c.GraphDB = &Database{
		URI:      dbURI,
		Username: u.User.Username(),
		System:   u.Scheme,
		DBName:   dbName,
		Host:     u.Hostname(), // Hostname without port
		Port:     u.Port(),     // Get port
	}

	password, isSet := u.User.Password()
	if isSet {
		c.GraphDB.Password = password
	}

	if u.RawQuery != "" {
		queryParams, err := url.ParseQuery(u.RawQuery)
		if err != nil {
			return fmt.Errorf("unable to parse database URI query parameters: %v", err)
		}
		c.GraphDB.Options = queryParams.Encode() // Encode url.Values to a string
	}

	return nil
}

// LocalDatabaseSettings returns the Database for the local bolt store.
func (c *Config) LocalDatabaseSettings() (string, error) {
	// Extract the database_uri from the Config options
	uriInterface, ok := c.Options["database"]
	if !ok {
		return "", fmt.Errorf("DatabaseSettings: No database found in the configuration options")
	}

	uri, ok := uriInterface.(string)
	if !ok {
		return "", fmt.Errorf("expected 'database' to be a string, got %T", uriInterface)
	}

	return uri, nil
}