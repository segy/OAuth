<?php
App::uses('OAuthComponent', 'OAuth.Controller/Component');
App::uses('SessionComponent', 'Controller/Component');
App::uses('Router', 'Routing');

/**
 * Consumer Component
 * Used for easy 3-legged OAuth authentication
 * 
 * @author segy
 * @package OAuth
 */
class OAuthConsumerComponent extends Component {
	/**
	 * Components
	 * 
	 * @var array
	 */
	public $components = array('OAuth.OAuth', 'Session');
	
	/**
	 * OAuth params
	 * 
	 * @var array
	 */
	protected $_params = array();
	
	/**
	 * Authorization URL
	 * 
	 * @var string
	 */
	protected $_authorizationLink;
	
	/**
	 * Access token
	 * 
	 * @var OAuthToken
	 */
	protected $_accessToken;
	
	/**
	 * Startup callback
	 * 
	 * @param Controller $controller
	 * @return void
	 */
	public function startup($controller) {
		// request parameters
		$r = $controller->request->params;
		// build authorization link
		$this->_authorizationLink = Router::url(array('plugin' => $r['plugin'], 'controller' => $r['controller'], 'action' => $r['action'], '?' => array('oauth_authorization_requested' => '1')));
		// search for authorization link in request
		if (array_key_exists('oauth_authorization_requested', $controller->request->query)) {
			$token = $this->OAuth->setKey($this->_params['key'])
				->setSecret($this->_params['secret'])
				->getRequestToken($this->_params['requestTokenUri'], Router::url(array('plugin' => $r['plugin'], 'controller' => $r['controller'], 'action' => $r['action']), true));
			
			$this->Session->write('OAuth.requestToken.key', $token->key);
			$this->Session->write('OAuth.requestToken.secret', $token->secret);
			$controller->redirect(sprintf($this->_params['authorizeUri'], $token->key));
		}
		// search for authorized token parameters
		if (array_key_exists('oauth_token', $controller->request->query) && array_key_exists('oauth_verifier', $controller->request->query)) {
        	$this->_accessToken = $this->OAuth->setKey($this->_params['key'])
				->setSecret($this->_params['secret'])
				->getAccessToken($this->_params['accessTokenUri'], $this->Session->read('OAuth.requestToken.key'), $this->Session->read('OAuth.requestToken.secret'));
			
			$this->Session->delete('OAuth.requestToken');
		}
		parent::startup($controller);
	}
	
	/**
	 * Set params
	 * 
	 * @param array $params expected keys - key, secret, requestTokenUri, authorizeUri, accessTokenUri
	 * @return void
	 */
	public function setParams($params) {
		$this->_params = $params;
	}
	
	/**
	 * Get authorization link
	 * 
	 * @return string
	 */
	public function getAuthorizationLink() {
		return $this->_authorizationLink;
	}
	
	/**
	 * Get successfully obtained access token
	 * 
	 * @return OAuthToken
	 */
	public function getAccessToken() {
		return is_object($this->_accessToken) && property_exists($this->_accessToken, 'key') ? $this->_accessToken->key : false;
	}
}
