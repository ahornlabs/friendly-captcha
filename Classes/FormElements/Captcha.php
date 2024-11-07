<?php

namespace Ahorn\FriendlyCaptcha\FormElements;

use Neos\Flow\Annotations as Flow;
use Neos\Error\Messages\Error;
use Neos\Form\Core\Model\AbstractFormElement;
use Neos\Form\Core\Runtime\FormRuntime;
use GuzzleHttp\Client;
use GuzzleHttp\Exception\RequestException;
use Composer\CaBundle\CaBundle;

class Captcha extends AbstractFormElement
{

    /**
     * @Flow\InjectConfiguration()
     * @var array
     */
    protected $settings = [];

    /**
     * Check the friendly captcha solution before submitting form.
     *
     * @param FormRuntime $formRuntime The current form runtime
     * @param mixed       $elementValue The transmitted value of the form field.
     *
     * @return void
     */

    public function onSubmit(FormRuntime $formRuntime, &$elementValue)
    {
        $properties = $this->getProperties();
        if($properties['overrideKeys'] && isset($properties['overrideSecretKey'])) {
          $apiKey = $properties['overrideSecretKey'];
        } else {
          $apiKey = $properties['apiKey'] ? $properties['apiKey'] : null;
        }

        if($properties['overrideKeys'] && isset($properties['overrideApiEndpoint'])) {
          $apiEndpoint = $properties['overrideApiEndpoint'];
        } else {
          $apiEndpoint = $properties['apiEndpoint'];
        }

        if (empty($apiKey) || $apiKey == 'add-your-api-key') {
            $processingRule = $this->getRootForm()->getProcessingRule($this->getIdentifier());
            $processingRule->getProcessingMessages()->addError(new Error('Error. Please try again later.', 17942348245));
            return;
        }

        if (empty($elementValue)) {
          $processingRule = $this->getRootForm()->getProcessingRule($this->getIdentifier());
          $processingRule->getProcessingMessages()->addError(new Error('You forgot to add the solution parameter.', 1515642243));
          return;
        }


        $verify = $this->verifyCaptchaSolutionV2('https://'.$apiEndpoint.'.frcapi.com/api/v2/captcha/siteverify', $elementValue, $apiKey);
        $response = $verify ? json_decode($verify, true) : [];

        if (empty($response)) {
            $processingRule = $this->getRootForm()->getProcessingRule($this->getIdentifier());
            $processingRule->getProcessingMessages()->addError(new Error('Validation server is not responding.', 1735489214));
            return;
        }


        if (!$response['success']) {

            if ($response['error']['error_code'] === 'auth_required') {
              $processingRule = $this->getRootForm()->getProcessingRule($this->getIdentifier());
              $processingRule->getProcessingMessages()->addError(new Error($response['error']['error_code'], 1732156724));
            } elseif($response['error']['error_code'] === 'auth_invalid') {
              $processingRule = $this->getRootForm()->getProcessingRule($this->getIdentifier());
              $processingRule->getProcessingMessages()->addError(new Error($response['error']['error_code'], 5786245981));
            } elseif($response['error']['error_code'] === 'sitekey_invalid') {
              $processingRule = $this->getRootForm()->getProcessingRule($this->getIdentifier());
              $processingRule->getProcessingMessages()->addError(new Error($response['error']['error_code'], 7956325875));
            } elseif($response['error']['error_code'] === 'response_missing') {
              $processingRule = $this->getRootForm()->getProcessingRule($this->getIdentifier());
              $processingRule->getProcessingMessages()->addError(new Error($response['error']['error_code'], 8876423767));
            } elseif($response['error']['error_code'] === 'response_invalid') {
              $processingRule = $this->getRootForm()->getProcessingRule($this->getIdentifier());
              $processingRule->getProcessingMessages()->addError(new Error($response['error']['error_code'], 1380742852));
            } elseif($response['error']['error_code'] === 'response_timeout') {
              $processingRule = $this->getRootForm()->getProcessingRule($this->getIdentifier());
              $processingRule->getProcessingMessages()->addError(new Error($response['error']['error_code'], 1380742853));
            } elseif($response['error']['error_code'] === 'response_duplicate') {
              $processingRule = $this->getRootForm()->getProcessingRule($this->getIdentifier());
              $processingRule->getProcessingMessages()->addError(new Error($response['error']['error_code'], 1185587569));
            } elseif($response['error']['error_code'] === 'bad_request') {
              $processingRule = $this->getRootForm()->getProcessingRule($this->getIdentifier());
              $processingRule->getProcessingMessages()->addError(new Error($response['error']['error_code'], 1380742851));
            } else{
              $processingRule = $this->getRootForm()->getProcessingRule($this->getIdentifier());
              $processingRule->getProcessingMessages()->addError(new Error($response['error']['error_code'], 1380742851));
            }
        }
    }

    /**
     * Verify the generated solution with Friendly Captcha API.
     *
     * @param string $url Friendly Captcha verify url
     * @param string $response string with value of friendlyCaptcha Widget
     * @param string $apiKey a string with the api key
     *
     * @return bool|string
     */

    public function verifyCaptchaSolutionV2($url, $response, $apiKey)
    {

        $data = ['response' => $response];
        $headers = [
            'Content-Type' => 'application/json',
            'Accept' => 'application/json',
            'X-API-Key' => $apiKey,
        ];


        if($this ->settings['composer'] === 'php') {
            $verify = CaBundle::getBundledCaBundlePath();
        } elseif ($this ->settings['cert'] === 'false') {
            $verify = false;
        } else {
            $verify = true;
        }

        $client = new Client();

        try {
            $apiResponse = $client->post($url, [
                'headers' => $headers,
                'json' => $data,
                'timeout' => 5,
                'verify' => $verify,
            ]);

            $body = $apiResponse->getBody()->getContents();

            return $body;

        } catch (RequestException $e) {
            if ($e->hasResponse()) {
                $errorBody = $e->getResponse()->getBody()->getContents();
                return $errorBody;
            } else {
                return null;
            }
        }
    }
}
