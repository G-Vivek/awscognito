<?php
return [

    "region" => env("AWS_REGION_TOP"),
    "version" => "latest",
    "aws_cognito_key" => env("AWS_COGNITO_KEY"),
    "aws_cognito_secret" => env("AWS_COGNITO_SECRET"),
    "aws_cognito_region" => env("AWS_COGNITO_REGION"), 
    "aws_cognito_client_id" => env("AWS_COGNITO_CLIENT_ID"),
    "aws_cognito_client_secret" => env("AWS_COGNITO_CLIENT_SECRET"), 
    "aws_cognito_user_pool_id" => env("AWS_COGNITO_USER_POOL_ID"), 
    "credentials" => [
        'key' => env("AWS_COGNITO_KEY"), 
        'secret' => env("AWS_COGNITO_SECRET") 
    ],
];
