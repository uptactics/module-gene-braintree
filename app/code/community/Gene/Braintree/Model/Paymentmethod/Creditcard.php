<?php

/**
 * Class Gene_Braintree_Model_Paymentmethod_Creditcard
 *
 * @author Dave Macaulay <braintreesupport@gene.co.uk>
 */
class Gene_Braintree_Model_Paymentmethod_Creditcard extends Gene_Braintree_Model_Paymentmethod_Abstract {

  /**
   * Setup block types
   *
   * @var string
   */
  protected $_formBlockType = 'gene_braintree/creditcard';

  protected $_infoBlockType = 'gene_braintree/creditcard_info';

  /**
   * Set the code
   *
   * @var string
   */
  protected $_code = 'gene_braintree_creditcard';

  /**
   * Payment Method features
   *
   * @var bool
   */
  protected $_isGateway = FALSE;

  protected $_canOrder = FALSE;

  protected $_canAuthorize = TRUE;

  protected $_canCapture = TRUE;

  protected $_canCapturePartial = TRUE;

  protected $_canRefund = TRUE;

  protected $_canRefundInvoicePartial = TRUE;

  protected $_canVoid = TRUE;

  protected $_canUseInternal = TRUE;

  protected $_canUseCheckout = TRUE;

  protected $_canUseForMultishipping = TRUE;

  protected $_isInitializeNeeded = FALSE;

  protected $_canFetchTransactionInfo = FALSE;

  protected $_canReviewPayment = TRUE;

  protected $_canCreateBillingAgreement = FALSE;

  protected $_canManageRecurringProfiles = FALSE;

  /**
   * Are we submitting the payment after the initial payment validate?
   *
   * @var bool
   */
  protected $_submitAfterPayment = FALSE;

  /**
   * Place Braintree specific data into the additional information of the
   * payment instance object
   *
   * @param mixed $data
   *
   * @return  Mage_Payment_Model_Info
   */
  public function assignData($data) {
    if (!($data instanceof Varien_Object)) {
      $data = new Varien_Object($data);
    }
    $info = $this->getInfoInstance();
    $info->setAdditionalInformation('card_payment_method_token',
      $data->getData('card_payment_method_token'))
      ->setAdditionalInformation('payment_method_nonce',
        $data->getData('payment_method_nonce'))
      ->setAdditionalInformation('save_card', $data->getData('save_card'))
      ->setAdditionalInformation('device_data', $data->getData('device_data'));

    if ($submitAfterPayment = $data->getData('submit_after_payment')) {
      $this->_submitAfterPayment = $submitAfterPayment;
    }

    return $this;
  }


  /**
   * Determine whether or not the vault is enabled, can be modified by numerous
   * events
   *
   * @return bool
   */
  public function isVaultEnabled() {
    $object = new Varien_Object();
    $object->setResponse($this->_getConfig('use_vault'));

    // Specific event for this method
    Mage::dispatchEvent('gene_braintree_creditcard_is_vault_enabled',
      ['object' => $object]);

    // General event if we want to enforce saving of all payment methods
    Mage::dispatchEvent('gene_braintree_is_vault_enabled',
      ['object' => $object]);

    return $object->getResponse();
  }

  /**
   * If we're trying to charge a 3D secure card in the vault we need to build a
   * special nonce
   *
   * @param $paymentMethodToken
   *
   * @return mixed
   */
  public function getThreeDSecureVaultNonce($paymentMethodToken) {
    return $this->_getWrapper()->getThreeDSecureVaultNonce($paymentMethodToken);
  }

  /**
   * Is 3D secure enabled?
   *
   * @return bool
   */
  public function is3DEnabled() {
    // 3D secure can never be enabled for the admin
    if (Mage::app()->getStore()->isAdmin()) {
      return FALSE;
    }

    /* @var $quote Mage_Sales_Model_Quote */
    $quote = Mage::getSingleton('checkout/cart')->getQuote();

    // Is 3D secure currently enabled?
    $result = $this->_getConfig('threedsecure');

    // Do we have a requirement on the threshold
    if ($result && $this->_getConfig('threedsecure_threshold') > 0) {
      // Check to see if the base grand total is bigger then the threshold
      $result = $quote->collectTotals()->getBaseGrandTotal() >
        $this->_getConfig('threedsecure_threshold');
    }

    // Do we only want to enable 3Ds for specific countries?
    if ($result && $this->_getConfig('threedsecure_allowspecific') ==
      Gene_Braintree_Model_System_Config_Source_Payment_Threedsecurecountries::SPECIFIC_COUNTRIES
    ) {
      $countries = $this->_getConfig('threedsecure_specificcountry');
      if ($countries) {
        $countriesArray = explode(',', $countries);
        if (count($countriesArray) >= 1) {
          $result = in_array($quote->getBillingAddress()->getCountryId(),
            $countriesArray);
        }
      }
    }

    return ($result == 1 ? TRUE : FALSE);
  }

  /**
   * Skip advanced fraud on this order
   *
   * @return bool
   */
  protected function _skipAdvancedFraudChecking() {
    if (Mage::app()
        ->getStore()
        ->isAdmin() && $this->_getConfig('skip_advanced_fraud_checking')) {
      return TRUE;
    }

    return FALSE;
  }

  /**
   * Should we save this method in the database?
   *
   * @param \Varien_Object $payment
   * @param                $skipMultishipping
   *
   * @return mixed
   */
  public function shouldSaveMethod($payment, $skipMultishipping = FALSE) {
    if ($skipMultishipping === FALSE) {
      // We must always save the method for multi shipping requests
      if ($payment->getMultiShipping() && !$this->_getOriginalToken()) {
        return TRUE;
      }
      elseif ($this->_getOriginalToken()) {
        // If we have an original token, there is no need to save the same payment method again
        return FALSE;
      }
    }

    // Retrieve whether or not we should save the card from the info instance
    $saveCard = $this->getInfoInstance()->getAdditionalInformation('save_card');

    $object = new Varien_Object();
    $object->setResponse(($this->isVaultEnabled() && $saveCard == 1));

    // Specific event for this method
    Mage::dispatchEvent('gene_braintree_creditcard_should_save_method', [
      'object' => $object,
      'payment' => $payment,
    ]);

    // General event if we want to enforce saving of all payment methods
    Mage::dispatchEvent('gene_braintree_save_method',
      ['object' => $object, 'payment' => $payment]);

    return $object->getResponse();
  }

  /**
   * Return the payment method token from the info instance
   *
   * @return null|string
   */
  public function getPaymentMethodToken() {
    $cToken = $this->getInfoInstance()
      ->getAdditionalInformation('card_payment_method_token');
    if (!empty($cToken)) {
      return $cToken;
    }

    return $this->getInfoInstance()->getAdditionalInformation('token');
  }

  /**
   * Return the payment method nonce from the info instance
   *
   * @return null|string
   */
  public function getPaymentMethodNonce() {
    return $this->getInfoInstance()
      ->getAdditionalInformation('payment_method_nonce');
  }

  /**
   * Validate payment method information object
   *
   * @return $this
   */
  public function validate() {
    // Run the built in Magento validation
    parent::validate();

    if ($this->_getConfig('enable_ip_count')) {
      $remoteIp = Mage::helper('core/http')->getRemoteAddr(FALSE);
      $cacheId = 'gene_braintree_failed_count';
      if (($failedData = Mage::app()->getCache()->load($cacheId))) {
        $failedData = unserialize($failedData);
        if (isset($failedData[$remoteIp]) && is_array($failedData[$remoteIp]) && $failedData[$remoteIp]['count'] >= $this->_getConfig('ip_count_threshold')) {
          $dif = time() - $failedData[$remoteIp]['ts'];
          if ($dif > $this->_getConfig('ip_count_block_period')) {
            unset($failedData[$remoteIp]['alerted']);
            $mail = Mage::getModel('core/email');
            $mail->setToEmail(Mage::getStoreConfig('payment/gene_braintree_creditcard/ip_count_email_to'));
            $mail->setBody('IP UNBanned: ' . $remoteIp . '<br/>Count when banned was: ' . $failedData[$remoteIp]['count'] . '<br/>Time: ' . date('Y-m-d H:i:s'));
            $mail->setSubject('IP UNBanned: ' . $remoteIp);
            $mail->setFromEmail(Mage::getStoreConfig('contacts/email/recipient_email'));
            $mail->setType('html');
            try {
              $mail->send();
            } catch (Exception $ex) {
              mage::log('IP UNBanned: ' . $remoteIp . ' Count when banned was : ' . $failedData[$remoteIp]['count'] . ' Time: ' . date('Y-m-d H:i:s'));
            }
            $failedData[$remoteIp]['count'] = 0;
            $failedData[$remoteIp]['ts'] = time();
            Mage::app()
              ->getCache()
              ->save(serialize($failedData), $cacheId, ['gene_braintree']);
          }
          else {
            if (!isset($failedData[$remoteIp]['alerted'])) {
              $mail = Mage::getModel('core/email');
              $mail->setToEmail(Mage::getStoreConfig('payment/gene_braintree_creditcard/ip_count_email_to'));
              $mail->setBody('IP Banned: ' . $remoteIp . '<br/>Count: ' . $failedData[$remoteIp]['count'] . '<br/>Time: ' . date('Y-m-d H:i:s'));
              $mail->setSubject('IP Banned: ' . $remoteIp);
              $mail->setFromEmail(Mage::getStoreConfig('contacts/email/recipient_email'));
              $mail->setType('html');
              try {
                $mail->send();
              } catch (Exception $ex) {
                Mage::getSingleton('core/session')
                  ->addError('Unable to send braintree block email.');
              }
            }
            Mage::throwException(
              $this->_getHelper()
                ->__('Your card payment has failed too many times, please try again later.')
            );
          }
        }

      }
    }

    // Validation doesn't need to occur now, as the payment has not yet been tokenized
    if ($this->_submitAfterPayment) {
      return $this;
    }

    // Confirm that we have a nonce from Braintree
    if (!$this->getPaymentMethodToken() ||
      ($this->getPaymentMethodToken() && $this->getPaymentMethodToken() == 'threedsecure')
    ) {
      if (!$this->getPaymentMethodNonce()) {
        Mage::helper('gene_braintree')
          ->log('Card payment has failed, missing token/nonce');
        Mage::helper('gene_braintree')->log($_SERVER['HTTP_USER_AGENT']);

        Mage::throwException(
          $this->_getHelper()
            ->__('Your card payment has failed, please try again.')
        );
      }
    }
    elseif (!$this->getPaymentMethodToken()) {
      Mage::helper('gene_braintree')->log('No saved card token present');
      Mage::helper('gene_braintree')->log($_SERVER['HTTP_USER_AGENT']);

      Mage::throwException(
        $this->_getHelper()
          ->__('Your card payment has failed, please try again.')
      );
    }

    return $this;
  }

  /**
   * Psuedo _authorize function so we can pass in extra data
   *
   * @param \Varien_Object $payment
   * @param                $amount
   * @param bool|false $shouldCapture
   * @param bool|false $token
   *
   * @return $this
   * @throws \Mage_Core_Exception
   */
  protected function _authorize(
    Varien_Object $payment,
    $amount,
    $shouldCapture = FALSE,
    $token = FALSE
  ) {
    // Init the environment
    $this->_getWrapper()->init($payment->getOrder()->getStoreId());

    // Retrieve the amount we should capture
    $amount = $this->_getWrapper()
      ->getCaptureAmount($payment->getOrder(), $amount);

    // Attempt to create the sale
    try {
      // Don't send device data if using the admin
      if (Mage::app()->getStore()->isAdmin()) {
        $deviceData = NULL;
      }
      else {
        $deviceData = $this->getInfoInstance()
          ->getAdditionalInformation('device_data');
      }

      // Build up the sale array
      $saleArray = $this->_getWrapper()->buildSale(
        $amount,
        $this->_buildPaymentRequest($token),
        $payment->getOrder(),
        $shouldCapture,
        $deviceData,
        $this->shouldSaveMethod($payment),
        $this->_is3DEnabled()
      );

      // If in the admin and we want to skip advanced fraud checks.
      // @see https://developers.braintreepayments.com/reference/request/transaction/sale/php#options.skip_advanced_fraud_checking
      if ($this->_skipAdvancedFraudChecking()) {
        $saleArray['options']['skipAdvancedFraudChecking'] = TRUE;
      }

      // Attempt to create the sale
      $result = $this->_getWrapper()->makeSale(
        $this->_dispatchSaleArrayEvent('gene_braintree_creditcard_sale_array',
          $saleArray, $payment)
      );

    } catch (Exception $e) {
      // If we're in developer mode return the message error
      if (Mage::getIsDeveloperMode()) {
        return $this->_processFailedResult($e->getMessage());
      }

      // Handle an exception being thrown
      Mage::dispatchEvent('gene_braintree_creditcard_failed_exception', [
        'payment' => $payment,
        'exception' => $e,
      ]);

      return $this->_processFailedResult(
        $this->_getHelper()->__(
          'There was an issue whilst trying to process your card payment, please try again or another' .
          ' method.'
        ),
        $e
      );
    }

    return $this->handleResult($result, $payment, $amount, $saleArray);
  }


  /**
   * Capture the payment on the checkout page
   *
   * @param Varien_Object $payment
   * @param float $amount
   *
   * @return Mage_Payment_Model_Abstract
   */
  protected function _captureAuthorized(Varien_Object $payment, $amount) {
    // Has the payment already been authorized?
    if ($payment->getCcTransId()) {
      // Convert the capture amount to the correct currency
      $captureAmount = $this->_getWrapper()
        ->getCaptureAmount($payment->getOrder(), $amount);

      // Check to see if the transaction has already been captured
      $lastTransactionId = $payment->getLastTransId();
      if ($lastTransactionId) {
        try {
          $this->_getWrapper()->init($payment->getOrder()->getStoreId());
          $transaction = Braintree\Transaction::find($lastTransactionId);

          // Has the transaction already been settled? or submitted for the settlement?
          // Also treat settling transaction as being process. Case #828048
          if (isset($transaction->id) &&
            (
              $transaction->status == Braintree\Transaction::SUBMITTED_FOR_SETTLEMENT ||
              $transaction->status == Braintree\Transaction::SETTLED ||
              $transaction->status == Braintree\Transaction::SETTLING
            )
          ) {
            // Do the capture amounts match?
            if ($captureAmount == $transaction->amount) {
              // We can just approve the invoice
              $this->_updateKountStatus($payment, 'A');
              $payment->setStatus(self::STATUS_APPROVED);

              return $this;
            }
          }
        } catch (Exception $e) {
          // Unable to load transaction, so process as below
        }
      }

      // Has the authorization already been settled? Partial invoicing
      if ($this->authorizationUsed($payment)) {
        // Set the token as false
        $token = FALSE;

        // Was the original payment created with a token?
        if ($additionalInfoToken = $payment->getAdditionalInformation('token')) {
          try {
            // Init the environment
            $this->_getWrapper()->init($payment->getOrder()->getStoreId());

            // Attempt to find the token
            Braintree\PaymentMethod::find($additionalInfoToken);

            // Set the token if a success
            $token = $additionalInfoToken;

          } catch (Exception $e) {
            $token = FALSE;
          }

        }

        // If we managed to find a token use that for the capture
        if ($token) {
          // Stop processing the rest of the method
          // We pass $amount instead of $captureAmount as the authorize function contains the conversion
          $this->_authorize($payment, $amount, TRUE, $token);
          return $this;

        }
        else {
          // Attempt to clone the transaction
          $result = $this->_getWrapper()->init(
            $payment->getOrder()->getStoreId()
          )->cloneTransaction($lastTransactionId, $captureAmount);
        }

      }
      else {
        // Init the environment
        $result = $this->_getWrapper()->init(
          $payment->getOrder()->getStoreId()
        )->submitForSettlement($payment->getCcTransId(), $captureAmount);

        // Log the result
        Gene_Braintree_Model_Debug::log(['capture:submitForSettlement' => $result]);
      }

      if ($result->success) {
        $this->_updateKountStatus($payment, 'A');
        $this->_processSuccessResult($payment, $result, $amount);
      }
      elseif ($result->errors->deepSize() > 0) {
        // Clean up
        Gene_Braintree_Model_Wrapper_Braintree::cleanUp();

        Mage::throwException($this->_getWrapper()
          ->parseErrors($result->errors->deepAll()));
      }
      else {
        // Clean up
        Gene_Braintree_Model_Wrapper_Braintree::cleanUp();

        Mage::throwException(
          $result->transaction->processorSettlementResponseCode . ':
                    ' . $result->transaction->processorSettlementResponseText
        );
      }

    }
    else {
      // Otherwise we need to do an auth & capture at once
      $this->_authorize($payment, $amount, TRUE);
    }

    return $this;
  }

  /**
   * Handle the result of the sale
   *
   * @param $result
   * @param $payment
   * @param $amount
   * @param $saleArray
   *
   * @return $this
   */
  protected function handleResult($result, $payment, $amount, $saleArray) {
    // Log the initial sale array, no protected data is included
    Gene_Braintree_Model_Debug::log(['_authorize:result' => $result]);

    // If the transaction was 3Ds but doesn't contain a 3Ds response
    if ($this->is3DEnabled()
      && isset($saleArray['options']['threeDSecure']['required'])
      && $saleArray['options']['threeDSecure']['required'] == TRUE
    ) {
      // Check to see if the liability was shifted
      if (!isset($result->transaction->threeDSecureInfo)
        || empty($result->transaction->threeDSecureInfo)
        || !$result->transaction->threeDSecureInfo->liabilityShifted
      ) {
        switch ($this->_getConfig('threedsecure_failed_liability')) {
          case Gene_Braintree_Model_System_Config_Source_Payment_Liabilityaction::BLOCK:
            // Don't fail american express cards
            if ($result->transaction->creditCard['cardType'] != "American Express") {
              return $this->processFailedThreeDResult($result);
            }
            break;
          case Gene_Braintree_Model_System_Config_Source_Payment_Liabilityaction::FRAUD:
            $payment->setIsTransactionPending(TRUE);
            $payment->setIsFraudDetected(TRUE);
            break;
        }
      }
    }

    // If the sale has failed
    if ($result->success != TRUE) {
      // Dispatch an event for when a payment fails
      Mage::dispatchEvent('gene_braintree_creditcard_failed',
        ['payment' => $payment, 'result' => $result]);
      if ($this->_getConfig('enable_ip_count')) {
        // count failures by IP
        $remoteIp = $payment->getOrder()->getRemoteIp();
        $cacheId = 'gene_braintree_failed_count';
        if (($failedData = Mage::app()->getCache()->load($cacheId))) {
          $failedData = unserialize($failedData);
          if (isset($failedData[$remoteIp]) && is_array($failedData[$remoteIp]) && isset($failedData[$remoteIp]['ts'])) {
            $failedData[$remoteIp]['count'] = $failedData[$remoteIp]['count'] + 1;
            $failedData[$remoteIp]['ts'] = time();
            Mage::app()
              ->getCache()
              ->save(serialize($failedData), $cacheId, ['gene_braintree']);

          }
        }
        else {
          $failedData = [
            $remoteIp => [
              'count' => 1,
              'ts' => time(),
            ],
          ];
          //then serialize and save it
          Mage::app()
            ->getCache()
            ->save(serialize($failedData), $cacheId, ['gene_braintree']);
        }

      }
      // Return a different message for declined cards
      if (isset($result->transaction->status)) {
        // Return a custom response for processor declined messages
        if ($result->transaction->status == Braintree\Transaction::PROCESSOR_DECLINED) {

          return $this->_processFailedResult(
            $this->_getHelper()->__(
              'Your transaction has been declined, please try another payment method or contacting ' .
              'your issuing bank.'
            ),
            FALSE,
            $result
          );
        }
        elseif ($result->transaction->status == Braintree\Transaction::GATEWAY_REJECTED
          && isset($result->transaction->gatewayRejectionReason)
          && $result->transaction->gatewayRejectionReason == Braintree\Transaction::THREE_D_SECURE
        ) {
          // An event for when 3D secure fails
          Mage::dispatchEvent('gene_braintree_creditcard_failed_threed', [
            'payment' => $payment,
            'result' => $result,
          ]);

          return $this->_processFailedResult(
            $this->_getHelper()->__(
              'Your card has failed 3D secure validation, please try again or consider using an ' .
              'alternate payment method.'
            ),
            FALSE,
            $result
          );
        }
      }

      return $this->_processFailedResult(
        $this->_getHelper()->__(
          '%s Please try again or attempt refreshing the page.',
          $this->_getHelper()->__(
            $this->_getWrapper()->parseMessage($result->message)
          )
        ),
        $result
      );
    }

    // If no errors are thrown we're safe to process the transaction as a success
    $this->_processSuccessResult($payment, $result, $amount);

    return $this;
  }

  /**
   * The transaction has failed due to 3D secure
   *
   * @param $result
   *
   * @return $this
   */
  protected function processFailedThreeDResult($result) {
    return $this->_processFailedResult(
      $this->_getHelper()->__(
        'This transaction must be passed through 3D secure, please try again or consider using an ' .
        'alternate payment method.'
      ),
      FALSE,
      $result
    );
  }

  /**
   * Build up the payment request
   *
   * @param $token
   *
   * @return array
   */
  protected function _buildPaymentRequest($token) {
    $paymentArray = [];

    // If we have an original token use that for the subsequent requests
    if ($originalToken = $this->_getOriginalToken()) {
      $paymentArray['paymentMethodToken'] = $originalToken;

      return $paymentArray;
    }

    // Check to see whether we're using a payment method token?
    if ($this->getPaymentMethodToken() &&
      !in_array($this->getPaymentMethodToken(), ['other', 'threedsecure'])
    ) {
      // Build our payment array
      $paymentArray['paymentMethodToken'] = $this->getPaymentMethodToken();
      unset($paymentArray['cvv']);
    }
    else {
      // Build our payment array with a nonce
      $paymentArray['paymentMethodNonce'] = $this->getPaymentMethodNonce();
    }

    // If the user is using a stored card with 3D secure, enable it in the request and remove CVV
    if ($this->getPaymentMethodToken() && $this->getPaymentMethodToken() == 'threedsecure') {
      // If we're using 3D secure token card don't send CVV
      unset($paymentArray['cvv']);
    }

    // If a token is present in the request use that
    if ($token) {
      // Remove this unneeded data
      unset($paymentArray['paymentMethodNonce'], $paymentArray['cvv']);

      // Send the token as the payment array
      $paymentArray['paymentMethodToken'] = $token;
    }

    return $paymentArray;
  }

  /**
   * Is 3D secure enabled based on the current data?
   *
   * @return bool
   */
  protected function _is3DEnabled() {
    // If we're creating the transaction from an original token we cannot use 3Ds currently
    if ($this->_getOriginalToken()) {
      return FALSE;
    }

    if ($this->getPaymentMethodToken() && $this->getPaymentMethodToken() == 'threedsecure') {
      return TRUE;
    }
    elseif ($this->getPaymentMethodToken() && $this->getPaymentMethodToken() != 'other') {
      return FALSE;
    }

    return $this->is3DEnabled();
  }

  /**
   * Authorize the requested amount
   *
   * @param \Varien_Object $payment
   * @param float $amount
   *
   * @return \Gene_Braintree_Model_Paymentmethod_Creditcard
   */
  public function authorize(Varien_Object $payment, $amount) {
    return $this->_authorize($payment, $amount, FALSE);
  }

  /**
   * Process capturing of a payment
   *
   * @param \Varien_Object $payment
   * @param float $amount
   *
   * @return \Mage_Payment_Model_Abstract
   */
  public function capture(Varien_Object $payment, $amount) {
    return $this->_captureAuthorized($payment, $amount);
  }

  /**
   * Processes successful authorize/clone result
   *
   * @param Varien_Object $payment
   * @param Braintree\Result\Successful $result
   * @param float $amount
   *
   * @return Varien_Object
   */
  protected function _processSuccessResult(
    Varien_Object $payment,
    $result,
    $amount
  ) {
    // Pass an event if the payment was a success
    Mage::dispatchEvent('gene_braintree_creditcard_success', [
      'payment' => $payment,
      'result' => $result,
      'amount' => $amount,
    ]);

    // Set some basic information about the payment
    $payment->setStatus(self::STATUS_APPROVED)
      ->setCcTransId($result->transaction->id)
      ->setLastTransId($result->transaction->id)
      ->setTransactionId($result->transaction->id)
      ->setIsTransactionClosed(0)
      ->setAmount($amount)
      ->setShouldCloseParentTransaction(FALSE);

    // Set information about the card
    $payment->setCcLast4($result->transaction->creditCardDetails->last4)
      ->setCcType($result->transaction->creditCardDetails->cardType)
      ->setCcExpMonth($result->transaction->creditCardDetails->expirationMonth)
      ->setCcExpYear($result->transaction->creditCardDetails->expirationYear);

    // Additional information to store
    $additionalInfo = [];

    // The fields within the transaction to log
    $storeFields = [
      'avsErrorResponseCode',
      'avsPostalCodeResponseCode',
      'avsStreetAddressResponseCode',
      'cvvResponseCode',
      'gatewayRejectionReason',
      'processorAuthorizationCode',
      'processorResponseCode',
      'processorResponseText',
      'threeDSecure',
      'kount_id',
      'kount_session_id',
    ];

    // Handle any fraud response from Braintree
    $this->handleFraud($result, $payment);

    // If 3D secure is enabled, presume it's passed
    if ($this->_is3DEnabled()
      && isset($result->transaction->threeDSecureInfo->liabilityShifted)
      && $result->transaction->threeDSecureInfo->liabilityShifted
    ) {
      $additionalInfo['threeDSecure'] = Mage::helper('gene_braintree')
        ->__('Liability Shifted');
    }
    elseif ($this->_is3DEnabled()) {
      $additionalInfo['threeDSecure'] = Mage::helper('gene_braintree')
        ->__('Liability Not Shifted');
    }

    // Iterate through and pull out any data we want
    foreach ($storeFields as $storeField) {
      if (isset($result->transaction->{$storeField}) && !empty($result->transaction->{$storeField})) {
        $additionalInfo[$storeField] = $result->transaction->{$storeField};
      }
      elseif ($value = $payment->getAdditionalInformation($storeField)) {
        $additionalInfo[$storeField] = $value;
      }
    }

    // Check it's not empty and store it
    if (!empty($additionalInfo)) {
      $payment->setAdditionalInformation($additionalInfo);
    }

    if (isset($result->transaction->creditCard['token']) && $result->transaction->creditCard['token']) {
      $payment->setAdditionalInformation('token',
        $result->transaction->creditCard['token']);

      // If the transaction is part of a multi shipping transaction store the token for the next order
      if ($payment->getMultiShipping() && !$this->_getOriginalToken()) {
        $this->_setOriginalToken($result->transaction->creditCard['token']);

        // If we shouldn't have this method saved, add it into the session to be removed once the request is
        // complete
        if (!$this->shouldSaveMethod($payment, TRUE)) {
          Mage::getSingleton('checkout/session')->setTemporaryPaymentToken(
            $result->transaction->creditCard['token']
          );
        }
      }
    }

    return $payment;
  }

}
