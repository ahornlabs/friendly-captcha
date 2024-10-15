<?php

namespace Ahorn\FriendlyCaptcha\FormElements;

use Neos\Flow\Annotations as Flow;
use Neos\Error\Messages\Error;
use Neos\Form\Core\Model\AbstractFormElement;
use Neos\Form\Core\Runtime\FormRuntime;

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
        if ($this->settings['secretKey']) {
            $secretKey = $properties['secretKey'] ?: $this->settings['secretKey'];
        } else {
            $secretKey = $properties['secretKey'] ?: null;
        }

        if (empty($secretKey)) {
            $processingRule = $this->getRootForm()->getProcessingRule($this->getIdentifier());
            $processingRule->getProcessingMessages()->addError(new Error('Error. Please try again later.', 17942348245));
            return;
        }
        $params = array('secret' => $secretKey, 'solution' => $elementValue);
        $query = http_build_query($params, '', '&');

        $result = ['verified' => false, 'error' => ''];

        if (empty($params['solution'])) {
            $processingRule = $this->getRootForm()->getProcessingRule($this->getIdentifier());
            $processingRule->getProcessingMessages()->addError(new Error('You forgot to add the solution parameter.', 1515642243));
        } else {
                $verify = $this->verifyCaptchaSolution('https://api.friendlycaptcha.com/api/v1/siteverify', $query);
                $response = $verify ? json_decode($verify, true) : [];

            if (!$response) {
                $processingRule = $this->getRootForm()->getProcessingRule($this->getIdentifier());
                $processingRule->getProcessingMessages()->addError(new Error('Validation server is not responding.', 1735489214));
            }

            if ($response['success']) {
                $result['verified'] = true;
            } else {
                $result['error'] = is_array($response['errors']) ?
                    reset($response['errors']) :
                    $response['errors'];
            }
        }

        if ($result['verified'] === false) {
            if ($result['error'] === 'secret_invalid') {
                $processingRule = $this->getRootForm()->getProcessingRule($this->getIdentifier());
                $processingRule->getProcessingMessages()->addError(new Error($result['error'], 1732156724));
            } elseif ($result['error'] === 'solution_invalid') {
                $processingRule = $this->getRootForm()->getProcessingRule($this->getIdentifier());
                $processingRule->getProcessingMessages()->addError(new Error($result['error'], 1380742852));
            } elseif ($result['error'] === 'solution_timeout_or_duplicate') {
                $processingRule = $this->getRootForm()->getProcessingRule($this->getIdentifier());
                $processingRule->getProcessingMessages()->addError(new Error($result['error'], 1380742853));
            } else {
                $processingRule = $this->getRootForm()->getProcessingRule($this->getIdentifier());
                $processingRule->getProcessingMessages()->addError(new Error((string)$result['error'], 1380742851));
            }
        }
    }

    /**
     * @deprecated Use the (corrctly named) verifyCaptchaSolution(…) method
     * @see verifyCaptchaSolution
     */

    public function verifyCaptchaSoltion($url, $options)
    {
        return $this->verifyCaptchaSolution($url, $options);
    }

    /**
     * Verify the generated solution with Friendly Captcha API.
     *
     * @param string $url Friendly Captcha verify url
     * @param string $options Query string with options like secret key
     *
     * @return bool|string
     */

    public function verifyCaptchaSolution($url, $options)
    {
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_TIMEOUT, 1);
        curl_setopt($ch, CURLOPT_URL, $url);
        curl_setopt($ch, CURLOPT_POSTFIELDS, $options);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        return curl_exec($ch);
    }
}
