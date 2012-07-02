<?php
App::uses('HttpSocket', 'Network/Http');

/**
 * OAuth Component
 * Uses OAuth library from http://oauth.googlecode.com/svn/code/php/
 * IMPORTANT: set security level in core.php to 'low'
 * 
 * @author segy
 * @package OAuth
 */
class OAuthComponent extends Component {
	/**
	 * OAuth consumer key
	 * 
	 * @var string
	 */
	protected $_consumerKey;
	
	/**
	 * OAuth consumer secret
	 * 
	 * @var string
	 */
	protected $_consumerSecret;
	
	/**
	 * Constructor
	 *
	 * @param ComponentCollection $collection
	 * @param array $settings
	 */
	public function __construct(ComponentCollection $collection, $settings = array()) {
		App::import('Vendor', 'OAuth.OAuth');
		parent::__construct($collection, $settings);
	}
	
	/**
	 * Set OAuth key
	 * 
	 * @param string $key
	 * @return OAuthComponent $this for method chaining
	 */
	public function setKey($key) {
		$this->_consumerKey = $key;
		return $this;
	}
	
	/**
	 * Set OAuth secret
	 * 
	 * @param string $secret
	 * @return OAuthComponent $this for method chaining
	 */
	public function setSecret($secret) {
		$this->_consumerSecret = $secret;
		return $this;
	}
	
	/**
     * Get request token
	 * 
	 * @param string $requestTokenUri
     * @param string $callback absolute URL to which the server will redirect back (if unable to receive callbacks MUST be set to 'oob')
     * @param string $httpMethod 'POST' or 'GET'
     * @param array $parameters
	 * @return OAuthToken
     */
    public function getRequestToken($requestTokenUri, $callback = 'oob', $httpMethod = 'POST', $parameters = array()) {
        $parameters['oauth_callback'] = $callback;
        $request = $this->_createRequest($httpMethod, $requestTokenUri, null, $parameters);
        return $this->_doRequest($request, $requestTokenUri);
    }
	
	/**
	 * Get access token after user authorized request token
	 * 
     * @param string $accessTokenUri
	 * @param string $tokenKey
	 * @param string $tokenSecret
     * @param string $httpMethod 'POST' or 'GET'
     * @param array $parameters
	 * @return OAuthToken
	 */
	public function getAccessToken($accessTokenUri, $tokenKey, $tokenSecret, $httpMethod = 'POST', $parameters = array()) {
        $requestToken = new OAuthToken($tokenKey, $tokenSecret);
        $queryStringParams = OAuthUtil::parse_parameters($_SERVER['QUERY_STRING']);
        $parameters['oauth_verifier'] = $queryStringParams['oauth_verifier'];
        $request = $this->_createRequest($httpMethod, $accessTokenUri, $requestToken, $parameters);
        return $this->_doRequest($request, $accessTokenUri);
    }
	
	/**
	 * Create consumer
	 * 
	 * @return OAuthConsumer
	 */
	protected function _createConsumer() {
        return new OAuthConsumer($this->_consumerKey, $this->_consumerSecret);
    }
	
	/**
	 * Create request
	 * 
	 * @param string $httpMethod 'POST' or 'GET'
	 * @param string $url
	 * @param OAuthToken $token
	 * @param array $parameters
	 * @return OAuthRequest
	 */
	protected function _createRequest($httpMethod, $url, $token, $parameters) {
        $consumer = $this->_createConsumer();
        $request = OAuthRequest::from_consumer_and_token($consumer, $token, $httpMethod, $url, $parameters);
        $request->sign_request(new OAuthSignatureMethod_HMAC_SHA1(), $consumer, $token);
        return $request;
    }
	
	/**
	 * Do get or post request for token
	 * 
	 * @param OAuthRequest $request
	 * @param strin $url
	 * @return OAuthToken
	 */
	protected function _doRequest($request, $url) {
        $socket = new HttpSocket();
        if ($request->get_normalized_http_method() == 'POST')
            $data = $socket->post($url, $request->to_postdata());
        else
            $data = $socket->get($request->to_url());
		
        $response = array();
        parse_str($data->body, $response);
        return $this->_createOAuthToken($response);
    }
	
	/**
	 * Create token
	 * 
	 * @param array $response
	 * @return OAuthToken
	 */
	protected function _createOAuthToken($response) {
        if (isset($response['oauth_token']) && isset($response['oauth_token_secret']))
            return new OAuthToken($response['oauth_token'], $response['oauth_token_secret']);
		
		return null;
    }
}
