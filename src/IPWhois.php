<?php

namespace wrossmann\whois;

class IPWhois extends Whois {
	/**
	 * 
	 * @var string ARIN_WHOIS Server used as root for IPWHOIS queries.
	 */
	const ARIN_WHOIS = 'whois.arin.net';
	
	/**
	 * Constructor
	 */
	public function __construct($params=[]) {
		parent::__construct($params);
	}
	
	/**
	 * Query IPWHOIS info
	 * {@inheritDoc}
	 * @see \wrossmann\whois\Whois::query()
	 */
	public function query($ipaddr) {
		self::validateIP($ipaddr);
		// Use ARIN as the starting point
		$raw_result = $this->queryWhois(self::ARIN_WHOIS, sprintf("%s", $ipaddr));
		// Re-issue query to other RIR if referred
		if( preg_match('#^ReferralServer:\s+whois://(.*)$#m', $raw_result, $matches) ) {
			$raw_result = $this->queryWhois($matches[1], sprintf("%s", $ipaddr));
		}
		return $raw_result;
	}
	
	/**
	 * Check that the supplied IP address is a valid public IP
	 * @param string $ipaddr
	 * @throws InvalidIPException
	 */
	public static function validateIP($ipaddr) {
		// TODO: check for reserved ranges
		$nval = inet_pton($ipaddr);
		if( $nval === false ) {
			throw new InvalidIPException("Address $ipaddr invalid.");
		}
	}
}

class InvalidIPException extends \Exception {}