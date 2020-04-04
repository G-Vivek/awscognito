<?php
namespace Torinit\awscognito\Traits;
use torinit\awscognito\cognito\CognitoClient;
use App\User;
use Validator;
use DB;
trait congnitoUser
{
    public function sendResponse($status, $message, $data = [], $code = 200)
    {
        $response = [
            'status_code' => $code,
            'status'  => $status,
            'message' => $message,
            'data'    => $data
        ];
        return json_encode($response);
    }


    public function signup(array $data)
    {
        try {            
            $rules = array(
                'name'=> "required",
                "email" => "required|unique:users,email",
                "password" => "required",
                "country_code" => "required",
                "mobile" => "required",
            );

            $validator = Validator::make($data, $rules);
            if ($validator->fails()) {
                return $this->sendResponse(false, $validator->getMessageBag()->first(), array(), 400);
            }
            DB::beginTransaction();
            $user = User::create($data);   
            if ($user) {
                $attributes = ["name" => $data['name'], "email" => $data['email'], "phone_number" => $data['country_code'] . $data['mobile'], "picture" => ""];
                $result = app()->make(CognitoClient::class)->register($data['email'],$data['password'], $attributes);
                if ($result == 1) {
                    $params = app()->make(CognitoClient::class)->getUser($data['email']);
                    $user->update(['username' => $params->get('Username')]);
                }else{
                    return $this->sendResponse(false, 'Something went wrong, Try again.', $result, 400);
                }
                DB::commit();
                return $this->sendResponse(true, 'User created successfully', $result, 200);
            }

        } catch (Exception $e) {
            
            DB::rollBack();
            return $this->sendResponse(false, $e->getMessage(), array(), 400);
        }
    }

    public function verifyEmail(array $data)
    {
        
        $rules = array(
                "email" => "required",
                "verification_code" => "required",
            );

        $validator = Validator::make($data, $rules);
        if ($validator->fails()) {
            return $this->sendResponse(false, $validator->getMessageBag()->first(), array(), 400);
        }

        $response = app()->make(CognitoClient::class)->confirmRegister($data['email'], $data['verification_code']);
        if($response === 1){
            User::where('email', $data['email'])->update(['status' => 1]);
            return $this->sendResponse(true, 'User email verified successfully', [], 200); 
        }else{
            return $this->sendResponse(false, 'error', $response, 400);
        }

        return false;
    }

    public function verifyMobile(array $data)
    {
        return app()->make(CognitoClient::class)->confirmMobile($data['access_token'], $data['verification_code']);
    }


    public function UserLogin(array $data)
    {
        $user = User::where('email', $data['email'])->first();
        $result = app()->make(CognitoClient::class)->authenticate($data['email'], $data['password']);
        if (is_array($result)) {
            return $this->sendResponse(true, 'User logged in successfully.', $result, 200);   
        }else{
            return $this->sendResponse(false, 'Error', $result, 400);
        }
    }

    public function changePassword($accessToken, $oldPassword, $newPassword)
    {
        $result = app()->make(CognitoClient::class)->changePassword($accessToken, $oldPassword, $newPassword);
        if ($result == 1) {
            return $this->sendResponse(true, 'Password changed successfully.', $result, 200);
        }
        return $this->sendResponse(true, 'Something went wrong, Try again.', $result, 200);
    }

    public function resendConfirmationCode($email)
    {

        $result = app()->make(CognitoClient::class)->resendConfirmationCode($email);
        if (isset($result)) {
            return $this->sendResponse(true, 'Verification code sent successfully.', [], 200);
        }else{
            return $this->sendResponse(false, 'error', $result, 400);
        }
    }

    public function sendResetLink($email)
    {

        $result =  app()->make(CognitoClient::class)->sendResetLink($email);
        if($result) {
            return $this->sendResponse(true, 'Verification code sent successfully.', $result, 200);
        }else{
            return $this->sendResponse(true, 'error', $result, 200);
        }

    }

    public function userConfirmPassword (array $data){
        $user = User::where('email', $data['email'])->first();
        $result = app()->make(CognitoClient::class)->setPassword($data['password'],$user->username);
        if ($result == 1) {
            $user->update(['password' => $data['password']]);
        }
        return $result;
    }  

}