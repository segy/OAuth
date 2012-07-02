# OAuth Plugin for CakePHP 2.x

Plugin for easy authorization via OAuth. 

### Usage

Create Component that extends _OAuthConsumerComponent_:  

	App::uses('OAuthConsumerComponent', 'OAuth.Controller/Component');
	
	class ServiceComponent extends OAuthConsumerComponent {
		/**
		 * Initialize callback
		 * 
		 * @param Controller $controller
		 * @return void
		 */
		public function initialize($controller) {
			$this->setParams(array(
				'key' => 'KLUC', 
				'secret' => 'SECRET', 
				'requestTokenUri' => 'URL', 
				'authorizeUri' => 'URL', 
				'accessTokenUri' => 'URL'
			));
		}
	}

Handle authorization in a controller this way:  

	class ServiceController extends AppController {
		public $components = array('Service');
	
		public function action() {
			// save token to database, session, etc.
			if ($this->Service->getAccessToken())
				$this->Session->write('accessToken', $this->Service->getAccessToken());
	
			// if we do not have token, give user authorization link
			if (!$this->Session->read('accessToken'))
				$this->set('link', $this->Service->getAuthorizationLink());
			else
				// access service
		}
	}
