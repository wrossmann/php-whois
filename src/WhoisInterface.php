<?php

namespace wrossmann\whois;

interface WhoisInterface {
	function query($domain);
	static function stripComments($input, $strip_blank = true, $regex = '/^(?:#|%).*$/');
}