<?php
require('vendor/autoload.php');
use \wrossmann\whois\Whois,
	\wrossmann\whois\IPWhois,
	\wrossmann\whois\CachedWhois;

$domain = 'example.com';
$ipaddr = '1.2.3.4';
	
// Un-cached WHOIS
$w = new WHOIS();
var_dump($w->query($domain));

// Cached WHOIS
$dbh = new \PDO('sqlite:whois.sqlite3');
CachedWhois::initDB($dbh);

$cw = new CachedWhois($dbh);
var_dump($cw->query($domain));

// IPWHOIS
$i = new \wrossmann\whois\IPWhois();
var_dump($i->query($ipaddr));