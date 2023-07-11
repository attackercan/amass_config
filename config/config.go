// Copyright © by Jeff Foley 2017-2023. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"bufio"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/caffix/stringset"
	"github.com/google/uuid"
	"github.com/owasp-amass/amass/v3/resources"
)

const (
	outputDirName  = "amass"
	defaultCfgFile = "config.yaml"
	cfgEnvironVar  = "AMASS_CONFIG"
	systemCfgDir   = "/etc"
)

// Updater allows an object to implement a method that updates a configuration.
type Updater interface {
	OverrideConfig(*Config) error
}

// Config passes along Amass configuration settings and options.
type Config struct {
	sync.Mutex

	// A Universally Unique Identifier (UUID) for the enumeration
	UUID uuid.UUID

	// The pseudo-random number generator
	Rand *rand.Rand

	// Logger for error messages
	Log *log.Logger

	//Scope struct that contains ASN, CIDR, Domain, IP, and ports in scope
	Scope Scope `yaml:"scope"`

	//Assets in which the scripts will need identify its purpose, similar to nmap scripts
	Assets map[string]*Actions `yaml:"assets"`

	//Defines options like datasources config path and stuff like that
	Options map[string]interface{} `yaml:"options"`

	// Alternative directory for scripts provided by the user
	ScriptsDirectory string

	// The directory that stores the bolt db and other files created
	Dir string

	// The graph databases used by the system / enumerations
	GraphDB *Database

	// The maximum number of concurrent DNS queries
	MaxDNSQueries int

	// The list of words to use when generating names
	Wordlist []string

	// Will the enumeration including brute forcing techniques
	BruteForcing bool

	// Will recursive brute forcing be performed?
	Recursive bool

	// Minimum number of subdomain discoveries before performing recursive brute forcing
	MinForRecursive int

	// Maximum depth for bruteforcing
	MaxDepth int

	// Will discovered subdomain name alterations be generated?
	Alterations    bool
	FlipWords      bool
	FlipNumbers    bool
	AddWords       bool
	AddNumbers     bool
	MinForWordFlip int
	EditDistance   int
	AltWordlist    []string

	// Only access the data sources for names and return results?
	Passive bool

	// Determines if zone transfers will be attempted
	Active bool

	blacklistLock sync.Mutex

	// A list of data sources that should not be utilized
	SourceFilter struct {
		Include bool // true = include, false = exclude
		Sources []string
	}

	// The minimum number of minutes that data source responses will be reused
	MinimumTTL int

	// Type of DNS records to query for
	RecordTypes []string

	// Resolver settings
	Resolvers        []string
	ResolversQPS     int
	TrustedResolvers []string
	TrustedQPS       int

	// Option for verbose logging and output
	Verbose bool

	// The root domain names that the enumeration will target
	domains []string

	// The regular expressions for the root domains added to the enumeration
	regexps map[string]*regexp.Regexp

	// Mode should be determined based on scripts utilized
	Mode string

	// The data source configurations
	DatasrcConfigs *DataSourceConfig
}

type Actions struct {
	Actions []string            `yaml:"actions"`
	Options map[string][]string `yaml:"options"`
}

type Scope struct {
	// Names provided to seed the enumeration
	ProvidedNames []string `yaml:"domain"`

	// IP Net.IP
	IP []net.IP `yaml:"-"`

	// The IP addresses specified as in scope
	Addresses []string `yaml:"ip"`

	// ASNs specified as in scope
	ASNs []int `yaml:"ASN"`

	//CIDR IPNET
	CIDRs []*net.IPNet `yaml:"-"`

	//CIDR in scope
	CIDRStrings []string `yaml:"CIDR"`

	// The ports checked for certificates
	Ports []int `yaml:"ports"`

	// A blacklist of subdomain names that will not be investigated
	Blacklist []string `yaml:"blacklist"`
}

// NewConfig returns a default configuration object.
func NewConfig() *Config {
	return &Config{
		UUID:            uuid.New(),
		Rand:            rand.New(rand.NewSource(time.Now().UTC().UnixNano())),
		Log:             log.New(io.Discard, "", 0),
		MinForRecursive: 1,
		// The following is enum-only, but intel will just ignore them anyway
		FlipWords:      true,
		FlipNumbers:    true,
		AddWords:       true,
		AddNumbers:     true,
		MinForWordFlip: 2,
		EditDistance:   1,
		Recursive:      true,
		MinimumTTL:     1440,
		ResolversQPS:   DefaultQueriesPerPublicResolver,
		TrustedQPS:     DefaultQueriesPerBaselineResolver,
	}
}

// UpdateConfig allows the provided Updater to update the current configuration.
func (c *Config) UpdateConfig(update Updater) error {
	return update.OverrideConfig(c)
}

// CheckSettings runs some sanity checks on the configuration options selected.
func (c *Config) CheckSettings() error {
	var err error

	if c.BruteForcing {
		if c.Passive {
			return errors.New("brute forcing cannot be performed without DNS resolution")
		} else if len(c.Wordlist) == 0 {
			f, err := resources.GetResourceFile("namelist.txt")
			if err != nil {
				return err
			}

			c.Wordlist, err = getWordList(f)
			if err != nil {
				return err
			}
		}
	}
	if c.Passive && c.Active {
		return errors.New("active enumeration cannot be performed without DNS resolution")
	}
	if c.Alterations {
		if len(c.AltWordlist) == 0 {
			f, err := resources.GetResourceFile("alterations.txt")
			if err != nil {
				return err
			}

			c.AltWordlist, err = getWordList(f)
			if err != nil {
				return err
			}
		}
	}

	c.Wordlist, err = ExpandMaskWordlist(c.Wordlist)
	if err != nil {
		return err
	}

	c.AltWordlist, err = ExpandMaskWordlist(c.AltWordlist)
	if err != nil {
		return err
	}
	return err
}

// LoadSettings parses settings from an .yaml file and assigns them to the Config.
func (c *Config) LoadSettings(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("failed to load the main configuration file: %v", err)
	}

	err = yaml.Unmarshal(data, c)
	if err != nil {
		return fmt.Errorf("error mapping configuration settings to internal values: %v", err)
	}

	// Convert string CIDRs to net.IP and net.IPNet
	c.Scope.CIDRs = c.Scope.toCIDRs(c.Scope.CIDRStrings)

	parseIPs := ParseIPs{} // Create a new ParseIPs, which is a []net.IP under the hood
	// Validate IP ranges in c.Scope.IP
	for _, ipRange := range c.Scope.Addresses {
		if err := parseIPs.parseRange(ipRange); err != nil {
			return err
		}
	}

	// append parseIPs (which is a []net.IP) to c.Scope.IP
	c.Scope.IP = append(c.Scope.IP, parseIPs...)

	loads := []func(cfg *Config) error{
		c.loadAlterationSettings,
		c.loadBruteForceSettings,
		c.loadDatabaseSettings,
		c.loadDataSourceSettings,
		c.loadResolverSettings,
	}
	for _, load := range loads {
		if err := load(c); err != nil {
			return err
		}
	}

	return nil
}

func (s *Scope) toCIDRs(strings []string) []*net.IPNet {
	cidrs := make([]*net.IPNet, len(strings))
	for i, str := range strings {
		_, cidr, _ := net.ParseCIDR(str)
		cidrs[i] = cidr
	}
	return cidrs
}

func (s *Scope) toIPs(strings []string) []net.IP {
	ips := make([]net.IP, len(strings))
	for i, str := range strings {
		ips[i] = net.ParseIP(str)
	}
	return ips
}

// AcquireConfig populates the Config struct provided by the Config argument.
func AcquireConfig(dir, file string, cfg *Config) error {
	var path, dircfg, syscfg string

	d := OutputDirectory(dir)
	if finfo, err := os.Stat(d); d != "" && !os.IsNotExist(err) && finfo.IsDir() {
		dircfg = filepath.Join(d, defaultCfgFile)
	}

	if runtime.GOOS != "windows" {
		syscfg = filepath.Join(filepath.Join(systemCfgDir, outputDirName), defaultCfgFile)
	}

	if file != "" {
		path = file
	} else if f, set := os.LookupEnv(cfgEnvironVar); set {
		path = f
	} else if _, err := os.Stat(dircfg); err == nil {
		path = dircfg
	} else if _, err := os.Stat(syscfg); err == nil {
		path = syscfg
	}

	return cfg.LoadSettings(path)
}

// OutputDirectory returns the file path of the Amass output directory. A suitable
// path provided will be used as the output directory instead.
func OutputDirectory(dir ...string) string {
	if len(dir) > 0 && dir[0] != "" {
		return dir[0]
	}

	if path, err := os.UserConfigDir(); err == nil {
		return filepath.Join(path, outputDirName)
	}

	return ""
}

// GetListFromFile reads a wordlist text or gzip file and returns the slice of words.
func GetListFromFile(path string) ([]string, error) {
	var reader io.Reader

	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("error opening the file %s: %v", path, err)
	}
	defer file.Close()
	reader = file

	// We need to determine if this is a gzipped file or a plain text file, so we
	// first read the first 512 bytes to pass them down to http.DetectContentType
	// for mime detection. The file is rewinded before passing it along to the
	// next reader
	head := make([]byte, 512)
	if _, err = file.Read(head); err != nil {
		return nil, fmt.Errorf("error reading the first 512 bytes from %s: %s", path, err)
	}
	if _, err = file.Seek(0, 0); err != nil {
		return nil, fmt.Errorf("error rewinding the file %s: %s", path, err)
	}

	// Read the file as gzip if it's actually compressed
	if mt := http.DetectContentType(head); mt == "application/gzip" || mt == "application/x-gzip" {
		gzReader, err := gzip.NewReader(file)
		if err != nil {
			return nil, fmt.Errorf("error gz-reading the file %s: %v", path, err)
		}
		defer gzReader.Close()
		reader = gzReader
	}

	s, err := getWordList(reader)
	return s, err
}

func getWordList(reader io.Reader) ([]string, error) {
	var words []string

	scanner := bufio.NewScanner(reader)
	for scanner.Scan() {
		// Get the next word in the list
		w := strings.TrimSpace(scanner.Text())
		if err := scanner.Err(); err == nil && w != "" {
			words = append(words, w)
		}
	}
	return stringset.Deduplicate(words), nil
}