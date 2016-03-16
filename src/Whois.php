<?php

namespace wrossmann\whois;

class Whois implements WhoisInterface {
	/**
	 *
	 * @var string WHOIS_ROOT Root server for TLDs
	 * @var int WHOIS_PORT
	 * @var int $max_response_size
	 * @var bool $normalize_line_breaks
	 * @var array $allow_override Protected properties allowed to be overridden in constructor params.
	 */
	const WHOIS_ROOT = 'whois.iana.org';
	const WHOIS_PORT = 43;
	
	protected $max_response_size = 20480;
	protected $normalize_line_breaks = true;
	
	private $allow_override = [ 'max_response_size','normalize_line_breaks' ];
	
	/**
	 * Constructor
	 * @param array $params        	
	 */
	public function __construct($params = []) {
		foreach( $this->allow_override as $override ) {
			if( key_exists( $override, $params ) ) {
				$this->$override = $params[$override];
			}
		}
	}
	
	/**
	 * Issue WHOIS query
	 * {@inheritDoc}
	 *
	 * @see \wrossmann\whois\WhoisInterface::query()
	 */
	public function query($domain) {
		$parts = explode( '.', trim( strtolower( $domain ) ) );
		$tld_whois = $this->getTLDWhois( $parts[count( $parts ) - 1] );
		
		return $this->queryWhois( $tld_whois, $domain );
	}
	
	/**
	 * Strip comments from WHOIS replies
	 * @param string $input
	 * @param string $strip_blank
	 * @param string $regex
	 * @return string
	 */
	public static function stripComments($input, $strip_blank = true, $regex = '/^(?:#|%).*$/') {
		return implode( 
			"\n", 
			array_filter( 
				explode( "\n", $input ), 
				function ($a) use ($regex, $strip_blank) {
					return ! (preg_match( $regex, $a ) || preg_match( '/^\s*$/', $a ));
				} ) );
	}
	
	/**
	 * Get TLD's whois server from the root server.
	 * @param string $tld        	
	 * @throws EmptyWhoisListException
	 */
	protected function getTLDWhois($tld) {
		$raw_whois = $this->queryWhois( self::WHOIS_ROOT, ".$tld" );
		$whois_servers = array_values( 
			array_map( 
				function ($a) {
					return preg_split( '/\s+/', $a )[1];
				}, 
				array_filter( 
					explode( "\n", $raw_whois ), 
					function ($a) {
						return preg_match( '/^whois:/', $a );
					} ) ) );
		if( count( $whois_servers ) == 0 ) {
			throw new EmptyWhoisListException( 'Could not find WHOIS server for TLD ' . $tld );
		}
		return $whois_servers[0];
	}
	
	/**
	 * Query the specified WHOIS server for the given name.
	 * @param string $server        	
	 * @param string $name        	
	 * @throws WhoisConnectException
	 */
	protected function queryWhois($server, $name) {
		$result = '';
		$chunksize = 4096;
		$res_size = 0;
		
		if( ! $sock = fsockopen( $server, SELF::WHOIS_PORT, $errno, $errstr ) ) {
			throw new WhoisConnectException( 'Could not connect to %s: [%d] %s', $server, $errno, $errstr );
		}
		fwrite( $sock, sprintf( "%s\r\n", $name ) );
		while( ! feof( $sock ) ) {
			$result .= fread( $sock, $chunksize );
			$res_size += $chunksize;
			if( $res_size >= $this->max_response_size ) {
				$result .= "\n\nWHOIS response exceeded max size, may be truncated.\n";
				break;
			}
		}
		fclose( $sock );
		
		return $this->normalize_line_breaks ? str_replace( "\r\n", "\n", $result ) : $result;
	}
}

class WhoisConnectException extends \Exception {}
class EmptyWhoisListException extends \Exception {}