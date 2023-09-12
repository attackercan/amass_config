# Configuration Users' Guide
![Network graph](./images/network_06092018.png "Amass Network Mapping")

----

The configuration & data sources file that the AMASS framework uses, is in YAML format. 
Users can add assets in scope, options, and data sources in use to fine tune the users collection experience.

## Elements in the configuration file

The configuration file is fomratted with two root elements in the YAML format.

|Element|Description|
|-------|-----------|
|scope  | Assets that are deemed *in scope*|
|options| Options to fine tune the collection experience|

These elements can be used together in the configuration file, or a user may choose to only utilize one of the root elements in their configuration file.

The *Scope* root element contains the following nested elements that a user can use:

|Element|Description|Input|
|-------|-----------|-----|
|domains| Domain names to be in scope| The domain name(s) is needed, such as `example.com`| 
|ips    | IP addresses to be in scope| Multiple methods of inserting ip addresses can be used such as `192.168.0.1`, `192.168.0.3-8`, `192.168.0.10-192.168.0.20`|
|asns   | ASNs (Autonomous system numbers) that are to be in scope| The ASN number(s) can be inserted without the AS prefix, such as `1234`|
|cidrs  | CIDR ranges that are to be in scope| CIDR notation is needed as input, such as `192.168.233.0/24`|
|ports  | Ports to be used when actively reaching a service| The port number(s), such as `80`, `8080`, `443`, `8443`| 
|blacklist| subdomains to be blacklisted or *out of scope* when collecting| The FQDN is needed, such as `badname.example.com`|

The *Options* root element contains the following nested elements that a user can use:

|Element|Description|Input|
|-------|-----------|-----|
|resolvers| Resolvers to use when collecting| Either a file path containing the resolvers, or the ip(s) itself. Such as `../examples/resolvers.txt`, or `1.1.1.1`
|datasources| The file that contains the data source configuration | File path, such as `./datasources.yaml`|
|wordlist| The worldlist file(s) to use upon collection| File path(s), such as `./wordlists/deepmagic.com_top50kprefixes.txt`
|database| The database where the information will be stored | The URI of the database, it must follow the format of `scheme://username:password@host:port/database_name?options=works`, an example is `postgres://amass:iscool@192.168.54.23:5432/amass?sslmode=disable`
|bruteforce| To enable bruteforcing methods in collection and wordlists to use during bruteforcing | See [here](#bruteforcealterations-objects) for objects under bruteforcing |
|alterations| To enable alteration methods in collection and wordlists to use during alteration | See [here](#bruteforcealterations-objects) for objects under alterations |

### Bruteforce/Alterations objects
Under the `bruteforcing` and `alterations` objects, there are two child objects that users could use:

|Element|Description|Input|
|-------|-----------|-----|
|enabled| Determines whether the certain method is enabled or not | Boolean based on YAML standards, which is `true` or `false`|
|wordlists| Wordlist(s) to use | File path(s) such as `./wordlists/subdomains-top1mil-5000.txt`|

#### **Example of valid configurations:**

1. This is the example configuration file that you see in the [example directory](./examples).
```yaml
scope:
  domains: # domain names to be in scope
    - example.com
  ips: # IP addresses to be in scope, multiple methods of inserting ip addresses can be used
    - 192.0.2.1
    - 192.0.2.2
    - 192.168.0.3-8
    - 192.168.0.10-192.168.0.20
  asns: # ASNs that are to be in scope
    - 1234
    - 5678
  cidrs: # CIDR ranges that are to be in scope
    - 192.0.2.0/24
    - 192.0.2.128/25
  ports: # ports to be used when actively reaching a service
    - 80
    - 443
  blacklist: # subdomains to be blacklisted
    - example.example1.com
options:
  resolvers: 
    - "../examples/resolvers.txt" # array of 1 path or multiple IPs to use as a resolver
    - 76.76.19.19
  datasources: "./datasources.yaml" # the file path that will point to the data source configuration
  wordlist: # global wordlist(s) to uses 
    - "./wordlists/deepmagic.com_top50kprefixes.txt"
    - "./wordlists/deepmagic.com_top500prefixes.txt"
  database: "postgres://username:password@localhost:5432/database?testing=works" # databases URI to be used when adding entries
  bruteforce: # specific option to use when brute forcing is needed
    enabled: true
    wordlists: # wordlist(s) to use that are specific to brute forcing
      - "./wordlists/subdomains-top1mil-5000.txt"
  alterations: # specific option to use when brute forcing is needed
    enabled: true
    wordlists: # wordlist(s) to use that are specific to alterations
      - "./wordlists/subdomains-top1mil-110000.txt"
```

2. This example shows that users are not required to have the two root objects together if they do not wish to do so.
```yaml
scope:
  domains: # domain names to be in scope
    - example.com
  ips: # IP addresses to be in scope, multiple methods of inserting ip addresses can be used
    - 192.0.2.1
    - 192.0.2.2
    - 192.168.0.3-8
    - 192.168.0.10-192.168.0.20
  asns: # ASNs that are to be in scope
    - 1234
    - 5678
  cidrs: # CIDR ranges that are to be in scope
    - 192.0.2.0/24
    - 192.0.2.128/25
  ports: # ports to be used when actively reaching a service
    - 80
    - 443
  blacklist: # subdomains to be blacklisted
    - example.example1.com
```

3. On top of example #2, users do not need to include all the child elements inside the root object.
```yaml
scope:
  domains: # domain names to be in scope
    - example.com
  ports: # ports to be used when actively reaching a service
    - 80
    - 443
```

4. Same thing as example #3, but with the `options` root object.
```yaml
options:
  resolvers: 
    - "../examples/resolvers.txt" # array of 1 path or multiple IPs to use as a resolver
  datasources: "./datasources.yaml" # the file path that will point to the data source configuration
  database: "postgres://username:password@localhost:5432/database?testing=works" # databases URI to be used when adding entries
  bruteforce: # specific option to use when brute forcing is needed
    enabled: false
```
## Datasource configuration
The data source configuration is in a seperate file. There are two root elements in the data source configuration file.

|Element|Description|
|-------|-----------|
|datasources| Contains an array of datasource configuration (explained in this section)|
|[global_options](#the-global_options-object)| Options that are applied to all data sources|

The *datasources* root element contains the following:

|Element|Description|Input|
|-------|-----------|-----|
|name| The name of the datasource | String reperesenting the data source, such as `IPinfo` |
|ttl| The time to live per datsource | An integer representing the number of minutes, such as `1440` |
|creds| An object that contains nested elements for account access | See [below](#the-datasources-root-element-contains-an-array-of-multiple-objects-which-is-stated-above-the-following-format-for-a-datasource-is-shown-below) for objects under creds|

The *ttl* object does not have to be used if there is no need.

#### The datasources root element contains an array of multiple objects, which is stated [above](#datasource-configuration). The following format for a datasource is shown below.

```yaml
datasources:
  - name: Censys
    ttl: 10080
    creds:
      account: 
        apikey: null
        secret: null
  - name: CIRCL
    creds:
      account: 
        username: null
        password: null
```

 The *Creds* object contains the credentials used for account access to the specific data source. The *creds* object must have a nested element representing the account in question. The *account* object will have a variety of methods to obtain access:

|Element|Description|Input|
|-------|-----------|-----|
|username|The username of the datasource account|A string containing the username, such as `amass_user123`|
|password|The password of the datasource account|A string containing the password, such as `OAM4LIFE`|
|apikey|The API key of the datasource account|A string containing the API key, such as `OAMEXAMPLE498ftrg7gh4we978g`| 
|secret|The secret key of the datasource account|A string containing the secret key, such as `OAMEXAMPLE498ftrg7gh4we978g`|

### The global_options object

The *global_options* object allows users to fine tune options globally. As of now, there is only one object/option available under *global_options*. Expect more options soon.

|Element|Description|Input|
|-------|-----------|-----|
|minimum_ttl|Used to set the minimum ttl acceptable amongst all data sources| An integer representing the number of minutes, such as `1440`|

### Examples of valid data source configuration

1. This is example provides multiple ways a data source might need to authenticate.
```yaml
  - name: Censys
    ttl: 10080
    creds:
      account: 
        apikey: insert_creds_here
        secret: insert_creds_here
  - name: WhoisXMLAPI
    creds:
      account: 
        apikey: insert_creds_here
  - name: IPinfo
    creds:
      account: 
        apikey: insert_creds_here
  - name: CIRCL
    creds:
      account: 
        username: insert_creds_here
        password: insert_creds_here
global_options: 
  minimum_ttl: 1440 #one day
```
2. This example is just to show that all root elements do not have to be populated.
```yaml
global_options: 
  minimum_ttl: 1440 #one day
```
3. Same as example #2, but for the *datasources* object. 
```yaml
datasources:
  - name: 360PassiveDNS
    ttl: 3600
    creds:
      account: 
        apikey: insert_creds_here
  - name: ASNLookup
    creds:
      account: 
        apikey: insert_creds_here
  - name: Ahrefs
    ttl: 4320
    creds:
      account: 
        apikey: insert_creds_here
```