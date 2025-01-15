<?php

/**
 * Authenticate using PAPI protocol.
 *
 * @author Jaime Perez, RedIRIS
 */
namespace SimpleSAML\Module\papi\Auth\Source;


use RedIRIS\PoA\PoA;
use SimpleSAML\Auth\Source;
use SimpleSAML\Auth\State;
use RedIRIS\PoA\Conf\Hook;

class PAPI extends Source
{
    /**
     * The string used to identify our states.
     */
    const STAGE_INIT = 'sspmod_papi_Auth_Source_PAPI.state';

    /**
     * The key of the AuthId field in the state.
     */
    const AUTHID = 'sspmod_papi_Auth_Source_PAPI.AuthId';

    /**
     * @var the poA to use
     */
    private $_poa;

    /**
     * @var the home locator interface to use
     */
    private $_hli;

    /**
     * @var the PAPIOPOA to use
     */
    private $_papiopoa;

    /**
     * @var the attributes of the user
     */
    private $_attrs;

    /**
     * @var the state ID to retrieve the original request later
     */
    private $_stateId;

    /**
     * Constructor for this authentication source.
     *
     * @param array $info information about this authentication source
     * @param array $config configuration
     */
    public function __construct($info, $config)
    {
        assert('is_array($info)');
        assert('is_array($config)');

        // Call the parent constructor first, as required by the interface
        parent::__construct($info, $config);

        if (!array_key_exists('site', $config)) {
            throw new Exception('PAPI authentication source is not properly configured: missing [site]');
        }
        $this->_poa = new PoA($config['site']);

        if (array_key_exists('hli', $config)) {
            $this->_hli = $config['hli'];
        }
        
    }

    /**
     * Hook that will set Home Locator Identifier, PAPIOPOA and/or State ID.
     *
     * @param the PAPI request parameters that will be modified/extended
     * @param mixed $params
     */
    public function modifyParams(&$params)
    {
        if (!empty($this->_hli)) {
            $params['PAPIHLI'] = $this->_hli;
        }
        if (!empty($this->_papiopoa)) {
            $params['PAPIOPOA'] = $this->_papiopoa;
        }
        $params['URL'] = $params['URL'] .'?'.urlencode('SSPStateID=' . $this->_stateId);
        return false;
    }

    /**
     * Log-in using PAPI.
     *
     * @param array &$state Information about the current authentication
     */
    public function authenticate(array &$state): void
    {
        assert('is_array($state)');
		if (isset($state['SPMetadata'])) {
			$this->_papiopoa = $state['SPMetadata']['entityid'];
			$relstate = '';
		}
        // if relayState is not set, generate an internal relayState value
        // (this shouldn't be addressed here, but not doing so, might result in problems at the IdP side for certain
        // implementations ...)
        if (!isset($state['saml:RelayState'])) {
            $state['saml:RelayState'] = '&RelayState=' . uniqid();
        }
        // If RelayState exists in state array, extract it... we don't want any additional params...
        preg_match('/((.*)&RelayState=([^&]*))/', $state['saml:RelayState'], $relstate, PREG_OFFSET_CAPTURE);
        // We only want the exact RelayState value
        if (!empty($relstate[3][0])) {
            $state['saml:RelayState'] = urldecode($relstate[3][0]);
        }
        // if request contains a providerId, load the state
        if (isset($_REQUEST['providerId'])) {
            $this->_stateId = (string)$_REQUEST['providerId'];
            $state = SimpleSAML\Auth\State::loadState($this->_stateId, self::STAGE_INIT);
        }
        // check if we are returning back from PAPI authentication
        if (isset($_REQUEST['SSPStateID'])) {
            // yes! restore original request
            $this->_stateId = (string)$_REQUEST['SSPStateID'];
            $state = State::loadState($this->_stateId, self::STAGE_INIT);
        } elseif (!$this->_poa->isAuthenticated()) {
            // no! we have to save the request
            // We are will need the authId in order to retrieve this authentication source later.
            $state[self::AUTHID] = $this->authId;
            $this->_stateId = State::saveState($state, self::STAGE_INIT);

            $this->_poa->addHook('PAPI_REDIRECT_URL_FINISH', new Hook([$this, 'modifyParams']));
        }
        $this->_poa->authenticate();
        $this->_attrs = $this->_poa->getAttributes();
        $state['Attributes'] = $this->parseAttributes($this->_attrs);
        self::completeAuth($state);
    }

    /**
     * Parse the attribute array in a format suitable for SSP.
     *
     * @param the original attribute array
     * @param mixed $attrs
     */
    protected function parseAttributes($attrs)
    {
        assert('is_array($attrs)');
		if (isset($attrs)) {
			foreach ($attrs as $name => $value) {
				if (!is_array($value)) {
					$attrs[$name] = [$value];
				}
			}
		}
        return $attrs;
    }

    /**
     * Log out from this authentication source.
     *
     * This function should be overridden if the authentication source requires special
     * steps to complete a logout operation.
     *
     * If the logout process requires a redirect, the state should be saved. Once the
     * logout operation is completed, the state should be restored, and completeLogout
     * should be called with the state. If this operation can be completed without
     * showing the user a page, or redirecting, this function should return.
     *
     * @param array &$state Information about the current logout operation
     */
    public function logout(array &$state): void
    {
        assert('is_array($state)');

        // check first if we have a valid session
        if ($this->_poa->isAuthenticated()) {
            // We are will need the authId in order to retrieve this authentication source later.
            $state[self::AUTHID] = $this->authId;
            $this->_stateId = SimpleSAML_Auth_State::saveState($state, self::STAGE_INIT);

            // TODO: pending on phpPoA adding PAPI_SLO_REDIRECT_URL_FINISH hook
            $this->_poa->addHook('PAPI_SLO_REDIRECT_URL_FINISH', new Hook([$this, 'modifyParams']));

            // perform single logout, this won't return
            $this->_poa->logout(true);
        } elseif (isset($_REQUEST['SSPStateID'])) {
            $this->_stateId = (string)$_REQUEST['SSPStateID'];
            $state = SimpleSAML\Auth\State::loadState($this->_stateId, self::STAGE_INIT);
        } else {
            return;
        }

        self::completeLogout($state);
    }
}
