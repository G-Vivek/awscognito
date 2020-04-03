<?php
namespace Torinit\awscognito\cognito;

use Aws\CognitoIdentityProvider\CognitoIdentityProviderClient;
use Aws\CognitoIdentityProvider\Exception\CognitoIdentityProviderException;
use Illuminate\Support\Facades\Password;
use Illuminate\Support\Str;

class CognitoClient
{
    const NEW_PASSWORD_CHALLENGE = 'NEW_PASSWORD_REQUIRED';
    const FORCE_PASSWORD_STATUS  = 'FORCE_CHANGE_PASSWORD';
    const RESET_REQUIRED         = 'PasswordResetRequiredException';
    const USER_NOT_FOUND         = 'UserNotFoundException';
    const USERNAME_EXISTS        = 'UsernameExistsException';
    const INVALID_PASSWORD       = 'InvalidPasswordException';
    const CODE_MISMATCH          = 'CodeMismatchException';
    const EXPIRED_CODE           = 'ExpiredCodeException';
    const NOT_CONFIRMED          = 'UserNotConfirmedException';


    /**
     * @var CognitoIdentityProviderClient
     */
    protected $client;

    /**
     * @var string
     */
    protected $clientId;

    /**
     * @var string
     */
    protected $clientSecret;

    /**
     * @var string
     */
    protected $poolId;

    /**
     * CognitoClient constructor.
     * @param CognitoIdentityProviderClient $client
     * @param string $clientId
     * @param string $clientSecret
     * @param string $poolId
     */
    public function __construct(
        CognitoIdentityProviderClient $client,
        $clientId,
        $clientSecret,
        $poolId
    ) {

        $this->client       = $client;
        $this->clientId     = $clientId;
        $this->clientSecret = $clientSecret;
        $this->poolId       = $poolId;
    }


    /**
     * Checks if credentials of a user are valid
     *
     * @see http://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_AdminInitiateAuth.html
     * @param string $email
     * @param string $password
     * @return \Aws\Result|bool
     */
    public function authenticate($email, $password)
    {
        try {
            $response = $this->client->adminInitiateAuth([
                'AuthFlow'       => 'ADMIN_NO_SRP_AUTH',
                'AuthParameters' => [
                    'USERNAME'     => $email,
                    'PASSWORD'     => $password,
                    'SECRET_HASH'  => $this->cognitoSecretHash($email)
                ],
                'ClientId'   => $this->clientId,
                'UserPoolId' => $this->poolId
            ]);
        } catch (CognitoIdentityProviderException $exception) {
            if($exception->getAwsErrorCode() === self::NOT_CONFIRMED){
                return 420;
            }
            // if (
            //     $exception->getAwsErrorCode() === self::RESET_REQUIRED ||
            //     $exception->getAwsErrorCode() === self::USER_NOT_FOUND
            // ) {
            //     return false;
            // }

            // throw $exception;
            return $exception->getAwsErrorMessage();
        }

        return $response->toArray();
    }

    /**
     * Registers a user in the given user pool
     *
     * @param $email
     * @param $password
     * @param array $attributes
     * @return bool
     */
    public function register($email, $password, array $attributes = [])
    {
        $attributes['email'] = $email;

        try {
            $response = $this->client->signUp([
                'ClientId' => $this->clientId,
                'Password' => $password,
                'SecretHash' => $this->cognitoSecretHash($email),
                'UserAttributes' => $this->formatAttributes($attributes),
                'Username' => $email
            ]);
        } catch (CognitoIdentityProviderException $e) {
            // if ($e->getAwsErrorCode() === self::USERNAME_EXISTS) {
            //     return false;
            // }
            return $e->getAwsErrorMessage();
        }
        $this->setUserAttributes($email, ['email_verified' => 'true']);
        return 1;
    }


    public function adminCreate($email, $password, array $attributes = [])
    {
        $attributes['email'] = $email;
        try {
            $response = $this->client->signUp([
                'ClientId' => $this->clientId,
                'Password' => $password,
                'SecretHash' => $this->cognitoSecretHash($email),
                'UserAttributes' => $this->formatAttributes($attributes),
                'Username' => $email
            ]);
        } catch (CognitoIdentityProviderException $e) {

            // if ($e->getAwsErrorCode() === self::USERNAME_EXISTS) {
            //     return false;
            // }
            return $e->getAwsErrorMessage();
        }
        $this->setUserAttributes($email, ['email_verified' => 'true', 'phone_number_verified' => 'true']);
        return 1;
    }

    public function changePassword($accessToken, $oldPassword, $newPassword){
        try {
            $result = $this->client->changePassword([
                'AccessToken' => $accessToken,
                'PreviousPassword' => $oldPassword,
                'ProposedPassword' => $newPassword,
            ]);
        } catch (CognitoIdentityProviderException $e) {
            return $e->getAwsErrorMessage();
        }
        return 1;
    }

    public function adminUserConfirm($userName)
    {
        try {
            $response = $this->client->adminConfirmSignUp([
                'UserPoolId' => $this->poolId,
                'Username' => $userName
            ]);
        } catch (CognitoIdentityProviderException $e) {
            return $e->getAwsErrorMessage();
        }
        return 1;
    }

    /**
     * Registers a user in the given user pool
     *
     * @param $email
     * @param $password
     * @param array $attributes
     * @return bool
     */
    public function create($email, $password, array $attributes = [])
    {

        
        $attributes['email'] = $email;
        try {
            $response = $this->client->AdminCreateUser([
                'DesiredDeliveryMediums' => ["SMS", "EMAIL"],
                'UserPoolId' => $this->poolId,
                'Password' => $password,
                'SecretHash' => $this->cognitoSecretHash($email),
                'UserAttributes' => $this->formatAttributes($attributes),
                'Username' => $email
            ]);
        } catch (CognitoIdentityProviderException $e) {
            return $e->getAwsErrorMessage();
        }
        $this->setUserAttributes($email, ['email_verified' => 'true', 'phone_number_verified' => 'true']);
        return 1;
    }

    /**
     * Confirm Registered a user in the given user pool
     *
     * @param $email
     * @param $code
     * @return bool
     */
    public function confirmRegister($email, $code)
    {
        try {
            $response = $this->client->confirmSignUp([
                'ClientId' => $this->clientId,
                'Username' => $email,
                'SecretHash' => $this->cognitoSecretHash($email),
                'ConfirmationCode' => $code,
            ]);
        } catch (CognitoIdentityProviderException $e) {
            // if ($e->getAwsErrorCode() === self::CODE_MISMATCH) {
            //     return false;
            // }
            return $e->getAwsErrorMessage();
        }
        return 1;
    }

    /**
     * Confirm new mobile
     *
     * @param $email
     * @param $code
     * @return bool
     */
    public function confirmMobile($token, $code)
    {
        try {
            $response = $this->client->VerifyUserAttribute([
                "AccessToken" => $token,
                "AttributeName" => "phone_number",
                "Code" => $code
            ]);
        } catch (CognitoIdentityProviderException $e) {
            return $e->getAwsErrorMessage();
        }
        return 1;
    }

    /**
     * Send a password reset code to a user.
     * @see http://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_ForgotPassword.html
     *
     * @param  string $username
     * @return string
     */
    public function sendResetLink($username)
    {
        try {
            $result = $this->client->forgotPassword([
                'ClientId' => $this->clientId,
                'SecretHash' => $this->cognitoSecretHash($username),
                'Username' => $username,
            ]);
        } catch (CognitoIdentityProviderException $e) {
            // if ($e->getAwsErrorCode() === self::USER_NOT_FOUND) {
            //     return Password::INVALID_USER;
            // }
            return $e->getAwsErrorMessage();
        }

        return 1;
    }

    /**
     * Confirm forgot user's password in the given user pool
     * @param $data
     * @return bool
     */
    public function confirmPassword($data)
    {
        try {
            $response = $this->client->confirmForgotPassword([
                'ClientId' => $this->clientId,
                'Username' => $data['email'],
                'SecretHash' => $this->cognitoSecretHash($data['email']),
                'ConfirmationCode' => $data['verification_code'],
                'Password' => $data['password'],
            ]);
        } catch (CognitoIdentityProviderException $e) {
            // if ($e->getAwsErrorCode() === self::CODE_MISMATCH) {
            //     return false;
            // }
            return $e->getAwsErrorMessage();
        }
        return 1;
    }

    # HELPER FUNCTIONS

    /**
     * Set a users attributes.
     * http://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_AdminUpdateUserAttributes.html
     *
     * @param string $username
     * @param array  $attributes
     * @return bool
     */
    public function setUserAttributes($username, array $attributes)
    {
        $this->client->AdminUpdateUserAttributes([
            'Username' => $username,
            'UserPoolId' => $this->poolId,
            'UserAttributes' => $this->formatAttributes($attributes),
        ]);

        return true;
    }


    /**
     * Creates the Cognito secret hash
     * @param string $username
     * @return string
     */
    protected function cognitoSecretHash($username)
    {
        return $this->hash($username . $this->clientId);
    }

    /**
     * Creates a HMAC from a string
     *
     * @param string $message
     * @return string
     */
    protected function hash($message)
    {
        $hash = hash_hmac(
            'sha256',
            $message,
            $this->clientSecret,
            true
        );

        return base64_encode($hash);
    }

    /**
     * Get user details.
     * http://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_GetUser.html
     *
     * @param  string $username
     * @return mixed
     */
    public function getUser($username)
    {
        try {
            $user = $this->client->AdminGetUser([
                'Username' => $username,
                'UserPoolId' => $this->poolId,
            ]);
        } catch (CognitoIdentityProviderException $e) {
            return false;
        }

        return $user;
    }

    /**
     * Format attributes in Name/Value array
     *
     * @param  array $attributes
     * @return array
     */
    protected function formatAttributes(array $attributes)
    {
        $userAttributes = [];

        foreach ($attributes as $key => $value) {
            $userAttributes[] = [
                'Name' => $key,
                'Value' => $value,
            ];
        }

        return $userAttributes;
    }

    /**
     * Resend Confirmation Code.
     * https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_ResendConfirmationCode.html
     *
     * @param  string $username
     * @return mixed
     */
    public function resendConfirmationCode($email)
    {
        try {
            $user = $this->client->ResendConfirmationCode([
                "ClientId" => $this->clientId,
                "SecretHash" => $this->cognitoSecretHash($email),
                "Username" => $email
            ]);
            return $user;
        } catch (CognitoIdentityProviderException $e) {
            return $e->getAwsErrorMessage();
        }

        return 1;
    }

    /**
     * Get new access token.
     *
     * @param  string $username
     * @return mixed
     */
    public function getToken($refreshToken)
    {
        try {
            $result = $this->client->AdminInitiateAuth([
                "ClientId" => $this->clientId,
                "UserPoolId" => $this->poolId,
                "AuthFlow" => "REFRESH_TOKEN_AUTH",
                "AuthParameters" => ['REFRESH_TOKEN' => $refreshToken, 'SECRET_HASH' => $this->clientSecret],
            ]);
            return $result->toArray();
        } catch (CognitoIdentityProviderException $e) {
            return $e->getAwsErrorMessage();
        }
    }

    /**
     * Set Password
     *
     * @param $email
     * @param $code
     * @return bool
     */
    public function setPassword($password, $username)
    {
        try {
            $response = $this->client->AdminSetUserPassword([
                "Password" => $password,
                "Permanent" => true,
                "Username" => $username,
                "UserPoolId" => $this->poolId,
            ]);
        } catch (CognitoIdentityProviderException $e) {
            return $e->getAwsErrorMessage();
        }
        return 1;
    }

    /**
     * Set new password for users which are created from admin
     *
     * @param $email
     * @param $password
     * @param array $attributes
     * @return bool
     */
    public function authChallenge($username, $password, $session)
    {
        try {
            $response = $this->client->AdminRespondToAuthChallenge([
                'AuthFlow' => 'ADMIN_NO_SRP_AUTH',
                'ChallengeName' => 'NEW_PASSWORD_REQUIRED',
                'ChallengeResponses' => [
                    'USERNAME' => $username,
                    'NEW_PASSWORD' => $password,
                    'SECRET_HASH'  => $this->cognitoSecretHash($username)
                ],
                'AuthParameters' => [
                    'USERNAME' => $username, // REQUIRED
                    'PASSWORD' => $password,
                    'SECRET_HASH'  => $this->cognitoSecretHash($username)
                ],
                'ClientId' => $this->clientId,
                'UserPoolId' => $this->poolId,
                'Session' => $session,
            ]);
        } catch (CognitoIdentityProviderException $e) {
            return $e->getAwsErrorMessage();
        }
        return $response->toArray();
    }

    /**
     * Get Attribute Verification Code.
     * https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_GetUserAttributeVerificationCode.html
     *
     * @param  string $username
     * @return mixed
     */
    public function getAttributeVerificationCode($token)
    {
        try {
            $user = $this->client->GetUserAttributeVerificationCode([
                "AccessToken" => $token,
                "AttributeName" => "phone_number",
            ]);
        } catch (CognitoIdentityProviderException $e) {
            return $e->getAwsErrorMessage();
        }
        return 1;
    }

    /**
     * Delete user from AWS Cognito
     * https://docs.aws.amazon.com/aws-sdk-php/v3/api/api-cognito-idp-2016-04-18.html#admindeleteuser
     *
     * @param  string $Username
     * @param  string $UserPoolId
     * @return mixed
     */
    
    public function deleteUser($username)
    {
        try{
            $user = $this->client->adminDeleteUser([
                'UserPoolId' => $this->poolId, // REQUIRED
                'Username' => $username,
            ]);
        } catch (CognitoIdentityProviderException $e) {
            return $e->getAwsErrorMessage();
        }
        return true;
    }
}
