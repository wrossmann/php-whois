<?php

namespace wrossmann\whois;

class IPWhois extends Whois {
	const ARIN_WHOIS = 'whois.arin.net';
	
	public function __construct() {}
	
	public function query($ipaddr) {
		$this->validateIP($ipaddr);
		$raw_result = $this->queryWhois(self::ARIN_WHOIS, sprintf("%s", $ipaddr));
		if( preg_match('#^ReferralServer:\s+whois://(.*)$#m', $raw_result, $matches) ) {
			echo "Referral to {$matches[1]}\n";
			$raw_result = $this->queryWhois($matches[1], sprintf("%s", $ipaddr));
		}
		return $raw_result;
	}
	
	public function validateIP($ipaddr) {
		// TODO: check for reserved ranges
		$nval = inet_pton($ipaddr);
		if( $nval === false ) {
			throw new InvalidIPException("Address $ipaddr invalid.");
		}
	}
}

class InvalidIPException extends \Exception {}