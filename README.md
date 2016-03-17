# wrossmann/whois - WHOIS Client object for PHP

## Features:

* Simplified resolution of domains names and IP addresses
* Does not rely on distributed lists of WHOIS servers, uses IANA/ARIN 'root' server referrals.
* Includes optional, simple, PDO-driven caching functionality to improve response times and mediate load on WHOIS roots.
* Requires only PHP >= 5.4, no external binaries or libraries.
* PHP7 compatible.

## Classes

All classes take an optional final parameter that is an array containing key => value pairs that can be used to override certain protected properties. Overrideable parameters set in each class' private `$overrides` parameter, and are detailed below.

### \wrossmann\whois\Whois - Base WHOIS class.

Public Methods:

* `void __construct(array $params = [])`
* `string query(string $domain)`
* `static string stripComments(string $input, bool $strip_blank = true, string $regex = '/^(?:#|%).*$/')`
    * Strips comments from WHOIS responses, generally formatted as lines beginning with either `#` or `%`.
    * Second parameter controls stripping of blank lines
    * Third parameted allows the comment matching regex to be overridden.

Overrideable Parameters:

* `max_response_size` - The maximum amount of data, in bytes, to accept from a WHOIS response. [Default: `20480`]
* `normalize_line_breaks` - If true replaces all instances of `\r\n` with `\n`. [Default: `true`]

### \wrossmann\whois\CachedWhois - WHOIS class with simple caching to a PDO database

Public Methods:

* Public methods inherited from parent class `Whois`.
* `void __construct(\PDO $dbh, array $params = [])`
* `static boolean initDB(\PDO $dbh)`
    * Issues `CREATE TABLE IF NOT EXISTS` statement to create table, see `src/CachedWhois.php`.
    
Overrideable Parameters:

* `cache_lifetime` - Length of time, is seconds, to cache a TLD WHOIS server referral. [Default `604800` aka 7 days]

### \wrossmann\whois\IPWhois - Class for performing IPWHOIS queries

Public Methods:

* Public methods inherited from parent class `Whois`.
* `void __construct(array $params=[])`
* `string function query(string $ipaddr)`
* `static bool validateIP(string $ipaddr)`

Overrideable Parameters: None

## Interfaces

### WhoisInterface

* `string query(string $domain)`
* `static string stripComments(string $input, bool $strip_blank = true, string $regex = '/^(?:#|%).*$/') `

## TODO

* `CachedIPWhois` Class
* Make `IPWhois::validate()` check for reserved addresses.