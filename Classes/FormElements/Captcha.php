<?php

namespace Ahorn\FriendlyCaptcha\FormElements;

use Neos\Flow\Annotations as Flow;
use Neos\Error\Messages\Error;
use Neos\Form\Core\Model\AbstractFormElement;
use Neos\Form\Core\Runtime\FormRuntime;
use GuzzleHttp\Client;
use Psr\Log\LoggerInterface;

class Captcha extends AbstractFormElement
{


    /**
     * @Flow\Inject
     * @var LoggerInterface
     */
    protected $logger;

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

        $this->logger->info('Sven 111 Verify Value: ' .$elementValue);

        if (empty($elementValue)) {
          $processingRule = $this->getRootForm()->getProcessingRule($this->getIdentifier());
          $processingRule->getProcessingMessages()->addError(new Error('You forgot to add the solution parameter.', 1515642243));
          return;
        }


        $verify = $this->verifyCaptchaSolutionV2('https://'.$apiEndpoint.'.frcapi.com/api/v2/captcha/siteverify', $elementValue, $apiKey);
        $response = $verify ? json_decode($verify, true) : [];

        $this->logger->info('Sven 111 response Value: ' . json_encode($response));

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
     * @param string $options Query string with options like secret key
     * @param string $apiKey a string with the api key
     *
     * @return bool|string
     */

    public function verifyCaptchaSolutionV2($url, $response, $apiKey)
    {
        $data = ['response' => $response];
        $jsonData = json_encode($data);
        $headers = [
            'Content-Type' => 'application/json',
            'Accept' => 'application/json',
            'X-API-Key' => $apiKey,
        ];
        $jsonHeader = json_encode($headers);
        $this->logger->info('Sven 111 Verify Value: ' .$jsonData );
        $this->logger->info('Sven 111 Key: ' .$apiKey);
        $this->logger->info('Sven 111 Header: ' .$jsonHeader);
        $client = new Client();
        try {
            $apiResponse = $client->post($url, [
                'headers' => $headers,
                'json' => $data,
                'timeout' => 5,
                'verify' => false, // TODO hier was überlegen
            ]);

            $body = $apiResponse->getBody()->getContents();

            return $body;

        } catch (\Exception $e) {
            $this->logger->error('Fehler bei der Anfrage: ' . $e->getMessage());
            $this->logger->error('Fehlercode: ' . $e->getCode());
            $this->logger->error('Stack-Trace: ' . $e->getTraceAsString());
            return null;
        }



        // $ch = curl_init();
        // $headers = [
        //     'Content-Type: application/json',
        //     'Accept: application/json',
        //     'X-API-Key: ' . $apiKey,
        // ];
        // $data = ['response' => $response];
        // $jsonData = json_encode($data);
        // curl_setopt($ch, CURLOPT_TIMEOUT, 5);
        // curl_setopt($ch, CURLOPT_URL, $url);
        // curl_setopt($ch, CURLOPT_POST, true);
        // curl_setopt($ch, CURLOPT_POSTFIELDS,  $jsonData);
        // curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        // curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
        // $curlResponse = curl_exec($ch);

        // $this->logger->info('frienldycaptcha-url ' . $url);
        // $this->logger->info('frienldycaptcha-options ' . $jsonData);
        // $this->logger->info('frienldycaptcha-apikey ' . $apiKey);
        // $this->logger->info('frienldycaptcha-response ' . $curlResponse);
        // curl_close($ch);
        // return $curlResponse;
    }
}
