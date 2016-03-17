<?php

namespace wrossmann\whois;

class CachedWhois extends Whois {
	/**
	 *
	 * @var \PDO $dbh Cache DB object
	 * @var array $_stmt_cache Prepared statement cache
	 * @var int $cache_lifetime Cache entry lifetime, overrideable by 'params'
	 * @var array $allow_overrides Properties allowed to be overridden by constructor param-s
	 */
	protected $dbh;
	protected $_stmt_cache = [ ];
	
	protected $cache_lifetime = 604800;
	private $allow_override = [ 'cache_lifetime' ];
	
	/**
	 * Constructor
	 * @see \wrossmann\whois\Whois::__construct()
	 * @param \PDO $dbh        	
	 * @param array $params        	
	 */
	public function __construct(\PDO $dbh, $params = []) {
		$this->dbh = $dbh;
		$this->dbh->setAttribute( \PDO::ATTR_ERRMODE, \PDO::ERRMODE_EXCEPTION );
		$this->dbh->setAttribute( \PDO::ATTR_DEFAULT_FETCH_MODE, \PDO::FETCH_ASSOC );
		
		foreach( $this->allow_override as $override ) {
			if( key_exists( $override, $params ) ) {
				$this->$override = $params[$override];
			}
		}
		
		parent::__construct( $params );
	}
	
	/**
	 * Initialize cache DB
	 * @param \PDO $dbh        	
	 */
	public static function initDB(\PDO $dbh) {
		$query = <<<_E_
CREATE TABLE IF NOT EXISTS whois (
	tld VARCHAR(255) PRIMARY KEY,
	whois VARCHAR(255),
	updated INTEGER UNSIGNED
);
_E_;
		return $dbh->query( $query ) !== false;
	}
	
	/**
	 * Retrieve TLD whois server from cache, if available.
	 * Fallback to parent.
	 * {@inheritDoc}
	 *
	 * @see \wrossmann\whois\Whois::getTLDWhois()
	 */
	protected function getTLDWhois($tld) {
		if( ! isset( $this->_stmt_cache['tld_get'] ) ) {
			$this->_stmt_cache['tld_get'] = $this->dbh->prepare( 'SELECT * FROM whois WHERE tld = ? AND updated > ?;' );
		}
		$this->_stmt_cache['tld_get']->execute( [ $tld,time() - $this->cache_lifetime ] );
		$res = $this->_stmt_cache['tld_get']->fetchAll();
		
		if( count( $res ) == 0 ) {
			$server = parent::getTLDWhois( $tld );
			$this->updateTLDWhoisCache( $tld, $server );
			return $server;
		} else {
			return $res[0]['whois'];
		}
	}
	
	/**
	 * Update the cache with the TLD's whois server address.
	 * @param string $tld        	
	 * @param string $server        	
	 */
	protected function updateTLDWhoisCache($tld, $server) {
		if( ! isset( $this->_stmt_cache['tld_set'] ) ) {
			$this->_stmt_cache['tld_set'] = $this->dbh->prepare( 
				'INSERT OR REPLACE INTO whois (tld, whois, updated) VALUES (?,?,?)' );
		}
		$this->_stmt_cache['tld_set']->execute( [ $tld,$server,time() ] );
	}
}