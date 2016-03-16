<?php

namespace wrossmann\whois;

interface WhoisInterface {
	/**
	 * Query WHOIS server
	 * @param string $domain
	 */
	function query($domain);
	
	/**
	 * Strip comments from a WHOIS response
	 * @param string $input
	 * @param bool $strip_blank
	 * @param string $regex
	 */
	static function stripComments($input, $strip_blank = true, $regex = '/^(?:#|%).*$/');
}